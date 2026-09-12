//! 清单读写与合并模块：Manifest 加载、初始化、保存、条目合并与通用解析工具。
//!
//! # 模块职责
//! 提供发布链路共用的清单 IO 与合并能力：
//! - [`load_or_init_manifest`] / [`save_manifest_file`]：单包路径的清单读写；
//! - [`update_manifest_entries`]：把单个平台条目安全合并进清单（含 SemVer 降级保护）；
//! - [`build_package_info`]：从参数对象构造 [`PackageInfo`]，收敛重复组装逻辑；
//! - [`parse_install_mode`] / [`resolve_relative_to`] / [`parse_optional_semver`]：通用解析工具。
//!
//! # 设计原理
//! - **实现初衷**：清单合并是发布安全的核心——低版本不得覆盖高版本元数据，
//!   多平台条目必须互不干扰地追加，全局签名在内容变更后必须失效。
//!   把这些规则收敛到本模块，单包与批量两条路径共享同一套合并语义。
//! - **核心优势**：
//!   - 合并逻辑按「主通道 / 发布通道」分支调用同一份 [`merge_entry_metadata`]，
//!     杜绝两处独立实现导致的规则漂移；
//!   - [`build_package_info`] 作为 `PackageInfo` 的唯一构造入口，
//!     固定默认值（镜像列表、载荷哈希等）只声明一次。
//! - **代价与局限**：合并规则变更时需同时评估主通道与发布通道两条分支的影响。
//!
//! # 兄弟导航
//! - [`super::types`]：本模块操作的核心数据类型；
//! - [`super::single`] / [`super::batch`]：调用本模块完成实际的清单读写。

use super::types::{ManifestReleaseEntry, ManifestUpdateContext, PackageInfoParams};
use anyhow::{Context, Result};
use semver::Version;
use shipup::{ChannelInfo, InstallMode, Manifest, PackageInfo};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// 从参数对象构造完整的 [`PackageInfo`]。
///
/// # 设计原理
/// 单包与批量两条路径原先各自内联构造 `PackageInfo`，字段完全一致却分散在两处。
/// 收敛为本函数后，镜像列表、多签名列表、载荷哈希等固定默认值只声明一次，
/// 新增字段时不会出现「一处更新、另一处遗漏」的静默数据缺失。
pub(super) fn build_package_info(params: PackageInfoParams) -> PackageInfo {
    PackageInfo {
        url: params.url,
        mirrors: vec![],
        signature: params.signature,
        signatures: vec![],
        checksum: Some(params.checksum),
        package_type: params.package_type,
        install_mode: params.install_mode,
        install_args: params.install_args,
        executable_path: params.executable_path,
        require_elevation: params.require_elevation,
        wait_for_exit: params.wait_for_exit,
        payload_checksums: Default::default(),
        size: Some(params.package_size),
    }
}

/// 将包信息合并至指定通道或主通道的 Manifest 数据结构中。
///
/// # 设计原理
/// - **实现初衷**：支持跨平台 CI/CD 逐步合并发布包至同一清单，
///   并防范低版本误操作降级覆盖高版本主信息。
/// - **安全合并**：严格比对 SemVer 版本高低，仅在待合并版本大于或等于清单版本时更新元数据；
///   低版本包合并时仅追加目标平台包矩阵，保留清单中更高版本的元数据。
///
/// # Panics
/// 本函数不主动 panic；`resolve_expires_at` 的解析失败被 `.ok().flatten()` 安全消化
/// （过期时间解析失败时保留清单原值，不中断合并流程）。
pub(super) fn update_manifest_entries(
    manifest: &mut Manifest,
    target: &str,
    ctx: &ManifestUpdateContext,
    entry: ManifestReleaseEntry,
) {
    match ctx.channel {
        Some(ref channel_name) => {
            merge_into_channel(manifest, channel_name, target, ctx, entry);
        }
        None => {
            merge_into_main(manifest, target, ctx, entry);
        }
    }

    // 若发布参数中指定了过期时间或版本序号，同步更新清单根级别防重放元数据
    apply_root_metadata(manifest, ctx);

    // 清单内容变更后，原有的全局签名已失效，予以重置
    manifest.signature = None;
}

/// 版本化元数据的可变借用视图（参数对象模式）。
///
/// 把 [`ChannelInfo`] 与主清单 [`Manifest`] 中结构相同的「版本相关元数据」字段
/// 收敛为一个可变借用视图，使得版本合并规则只写一份。
struct VersionedMetaRefs<'a> {
    version: &'a mut Version,
    min_supported_version: &'a mut Option<Version>,
    force_update: &'a mut bool,
    pub_date: &'a mut Option<String>,
    notes: &'a mut Option<String>,
    rollout_percentage: &'a mut Option<u8>,
}

/// 将条目合并进指定发布通道。
fn merge_into_channel(
    manifest: &mut Manifest,
    channel_name: &str,
    target: &str,
    ctx: &ManifestUpdateContext,
    entry: ManifestReleaseEntry,
) {
    let ch_entry = manifest
        .channels
        .entry(channel_name.to_string())
        .or_insert_with(|| ChannelInfo {
            version: entry.version.clone(),
            min_supported_version: entry.min_supported_version.clone(),
            force_update: ctx.force_update,
            pub_date: Some(entry.pub_date.clone()),
            notes: ctx.notes.clone(),
            packages: BTreeMap::new(),
            rollout_percentage: ctx.rollout_percentage,
        });

    let location_label = format!("发布通道 '{channel_name}'");
    {
        let mut meta = VersionedMetaRefs {
            version: &mut ch_entry.version,
            min_supported_version: &mut ch_entry.min_supported_version,
            force_update: &mut ch_entry.force_update,
            pub_date: &mut ch_entry.pub_date,
            notes: &mut ch_entry.notes,
            rollout_percentage: &mut ch_entry.rollout_percentage,
        };
        merge_entry_metadata(&mut meta, &entry, ctx, &location_label);
    }
    ch_entry
        .packages
        .insert(target.to_string(), entry.package_info);
}

/// 将条目合并进主通道（默认通道）。
fn merge_into_main(
    manifest: &mut Manifest,
    target: &str,
    ctx: &ManifestUpdateContext,
    entry: ManifestReleaseEntry,
) {
    {
        let mut meta = VersionedMetaRefs {
            version: &mut manifest.version,
            min_supported_version: &mut manifest.min_supported_version,
            force_update: &mut manifest.force_update,
            pub_date: &mut manifest.pub_date,
            notes: &mut manifest.notes,
            rollout_percentage: &mut manifest.rollout_percentage,
        };
        merge_entry_metadata(&mut meta, &entry, ctx, "主通道");
    }
    manifest
        .packages
        .insert(target.to_string(), entry.package_info);
}

/// 执行 SemVer 版本比较并按规则合并元数据字段。
///
/// - 版本更高：整体覆盖版本、发布日期与可选元数据；
/// - 版本相同：仅补齐缺失字段，已有的高优先级值保留；
/// - 版本更低：记录警告日志，保留清单中更高版本的元数据。
fn merge_entry_metadata(
    meta: &mut VersionedMetaRefs<'_>,
    entry: &ManifestReleaseEntry,
    ctx: &ManifestUpdateContext,
    location_label: &str,
) {
    if entry.version > *meta.version {
        *meta.version = entry.version.clone();
        *meta.pub_date = Some(entry.pub_date.clone());
        if entry.min_supported_version.is_some() {
            *meta.min_supported_version = entry.min_supported_version.clone();
        }
        apply_optional_overrides(meta, ctx);
    } else if entry.version == *meta.version {
        if meta.pub_date.is_none() {
            *meta.pub_date = Some(entry.pub_date.clone());
        }
        if entry.min_supported_version.is_some() {
            *meta.min_supported_version = entry.min_supported_version.clone();
        }
        apply_optional_overrides(meta, ctx);
    } else {
        log::warn!(
            "{location_label} 待合并版本 {} 低于当前版本 {}，保留现有高版本元数据",
            entry.version,
            *meta.version
        );
    }
}

/// 将上下文中显式声明的可选覆盖字段应用到版本化元数据上。
fn apply_optional_overrides(meta: &mut VersionedMetaRefs<'_>, ctx: &ManifestUpdateContext) {
    if ctx.force_update {
        *meta.force_update = true;
    }
    if let Some(ref n) = ctx.notes {
        *meta.notes = Some(n.clone());
    }
    if ctx.rollout_percentage.is_some() {
        *meta.rollout_percentage = ctx.rollout_percentage;
    }
}

/// 应用清单根级别的防重放元数据（过期时间与版本序号）。
///
/// 过期时间解析失败时安全消化（保留原值），不中断合并流程。
fn apply_root_metadata(manifest: &mut Manifest, ctx: &ManifestUpdateContext) {
    let resolved_expires_at = ctx.resolve_expires().ok().flatten();
    if resolved_expires_at.is_some() {
        manifest.expires_at = resolved_expires_at;
    }
    if ctx.version_seq.is_some() {
        manifest.version_seq = ctx.version_seq;
    }
}

/// 读取现有 Manifest 文件或初始化默认空 Manifest。
///
/// # Errors
/// 已有清单文件读取或反序列化失败、过期时间解析失败时返回带路径上下文的中文错误。
pub(super) fn load_or_init_manifest(
    manifest_path: &Path,
    ctx: &ManifestUpdateContext,
    entry: &ManifestReleaseEntry,
) -> Result<Manifest> {
    let resolved_expires_at = ctx.resolve_expires()?;
    if manifest_path.exists() {
        let content = fs::read_to_string(manifest_path)
            .with_context(|| format!("读取已有 Manifest 文件失败: {}", manifest_path.display()))?;
        let mut m = serde_json::from_str::<Manifest>(&content)
            .with_context(|| format!("反序列化 Manifest JSON 失败: {}", manifest_path.display()))?;
        if resolved_expires_at.is_some() {
            m.expires_at = resolved_expires_at;
        }
        if ctx.version_seq.is_some() {
            m.version_seq = ctx.version_seq;
        }
        Ok(m)
    } else {
        Ok(Manifest {
            version: entry.version.clone(),
            min_supported_version: entry.min_supported_version.clone(),
            force_update: ctx.force_update,
            pub_date: Some(entry.pub_date.clone()),
            notes: ctx.notes.clone(),
            packages: BTreeMap::new(),
            channels: BTreeMap::new(),
            signature: None,
            signatures: vec![],
            rollout_percentage: ctx.rollout_percentage,
            expires_at: resolved_expires_at,
            version_seq: ctx.version_seq,
        })
    }
}

/// 将格式化后的 Manifest JSON 写入磁盘目标路径。
///
/// # Errors
/// 序列化失败、父目录创建失败或文件写入失败时返回带路径上下文的中文错误。
pub(super) fn save_manifest_file(manifest_path: &Path, manifest: &Manifest) -> Result<()> {
    let json_output =
        serde_json::to_string_pretty(manifest).context("序列化 Manifest 为格式化 JSON 失败")?;
    if let Some(parent) = manifest_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建 Manifest 输出父目录失败: {}", parent.display()))?;
    }
    fs::write(manifest_path, json_output)
        .with_context(|| format!("写入 Manifest 文件失败: {}", manifest_path.display()))?;
    Ok(())
}

/// 解析安装器交互模式字符串为强类型枚举。
///
/// # Errors
/// 模式字符串不在 `passive` / `quiet` / `basicUi` 可选范围内时返回带提示的中文错误。
pub(super) fn parse_install_mode(
    mode: Option<&str>,
    target_hint: Option<&str>,
) -> Result<Option<InstallMode>> {
    let Some(mode) = mode else {
        return Ok(None);
    };
    match mode.to_ascii_lowercase().as_str() {
        "passive" => Ok(Some(InstallMode::Passive)),
        "quiet" => Ok(Some(InstallMode::Quiet)),
        "basicui" | "basic-ui" => Ok(Some(InstallMode::BasicUi)),
        other => {
            if let Some(t) = target_hint {
                anyhow::bail!(
                    "平台 '{}' 不支持的安装模式: {}，可选值为 passive / quiet / basicUi",
                    t,
                    other
                );
            }
            anyhow::bail!(
                "不支持的安装模式: {}，可选值为 passive / quiet / basicUi",
                other
            )
        }
    }
}

/// 以基准目录展开相对路径，绝对路径原样返回。
///
/// 批量发布配置中的路径均以配置文件所在目录为基准，避免受到进程当前工作目录影响。
pub(super) fn resolve_relative_to(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_relative() {
        base_dir.join(path)
    } else {
        path.to_path_buf()
    }
}

/// 解析可选的 SemVer 版本号字符串。
///
/// # Errors
/// 版本号格式非法时返回带字段标签与原始值的中文错误。
pub(super) fn parse_optional_semver(
    value: Option<&str>,
    field_label: &str,
) -> Result<Option<Version>> {
    value
        .map(|v| Version::parse(v).with_context(|| format!("解析{field_label} '{v}' 失败")))
        .transpose()
}
