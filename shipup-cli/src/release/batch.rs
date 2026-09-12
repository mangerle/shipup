//! 批量发布子模块：基于 TOML 配置文件的跨平台批量发布合并。
//!
//! # 模块职责
//! 读取 `shipup.toml` 批量发布配置，为每个平台条目计算包体哈希与签名，
//! 并把所有平台的元数据增量合并进同一份 Manifest 清单。
//!
//! # 设计原理
//! - **实现初衷**：多平台发布通常由不同流水线分头执行，需要在同一份清单上增量合并，
//!   同时保证任一平台失败时不产生「部分写入」的半成品清单。
//! - **核心优势**：批次级参数只解析一次；每个平台的处理被收敛到 [`merge_single_package`]；
//!   所有平台全部成功后才统一落盘，中途失败不会污染既有清单。
//! - **代价与局限**：批量模式按顺序处理配置中的平台条目，
//!   超大发布矩阵下耗时线性增长。
//!
//! # 兄弟导航
//! - [`super::single`]：单包命令行发布路径；
//! - [`super::manifest_io`]：清单读写与条目合并的底层实现；
//! - [`super::types`]：清单条目与合并上下文类型。

use super::manifest_io::{
    build_package_info, parse_install_mode, parse_optional_semver, resolve_relative_to,
    save_manifest_file, update_manifest_entries,
};
use super::types::{ManifestReleaseEntry, ManifestUpdateContext, PackageInfoParams};
use crate::util::{compute_payload_integrity, current_utc_rfc3339, resolve_expires_at};
use anyhow::{Context, Result};
use semver::Version;
use shipup::{Manifest, PackageType};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// 批量发布配置文件结构。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct BatchReleaseConfig {
    version: String,
    notes: Option<String>,
    pub_date: Option<String>,
    min_supported_version: Option<String>,
    #[serde(default)]
    force_update: bool,
    channel: Option<String>,
    rollout_percentage: Option<u8>,
    manifest: Option<PathBuf>,
    key: Option<PathBuf>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    expires_in: Option<String>,
    #[serde(default)]
    version_seq: Option<u64>,
    packages: Vec<BatchPackageConfig>,
}

/// 批量发布单个平台配置。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct BatchPackageConfig {
    target: String,
    package: PathBuf,
    package_type: String,
    url: String,
    executable_path: Option<String>,
    install_mode: Option<String>,
    #[serde(default)]
    install_args: Vec<String>,
    #[serde(default)]
    require_elevation: bool,
    #[serde(default)]
    wait_for_exit: bool,
    key: Option<PathBuf>,
}

impl From<&BatchReleaseConfig> for ManifestUpdateContext {
    /// 从批量发布配置中提取合并所需的批次级元数据。
    ///
    /// # 设计原理
    /// 替代原先「回造完整 `ReleaseArgs`」的冗余做法，
    /// 批量路径只需填充合并逻辑真正读取的 7 个字段。
    fn from(batch: &BatchReleaseConfig) -> Self {
        Self {
            channel: batch.channel.clone(),
            force_update: batch.force_update,
            notes: batch.notes.clone(),
            rollout_percentage: batch.rollout_percentage,
            expires_at: batch.expires_at.clone(),
            expires_in: batch.expires_in.clone(),
            version_seq: batch.version_seq,
        }
    }
}

/// 批量发布过程中各平台条目共享的上下文（参数对象模式）。
///
/// # 设计原理
/// - **实现初衷**：批量发布需要为每个平台条目重复使用同一批「批次级」参数
///   （配置目录、版本、发布日期与批次配置本身）。
///   若把这些参数逐个平铺到处理函数上，参数量会迅速突破可读上限。
/// - **核心优势**：把批次级参数收敛为一个借用视图，单平台处理函数只需接收
///   「目标清单」「当前条目」与「批次上下文」三项，职责边界一目了然。
/// - **代价与局限**：新增批次级参数时需同步扩展本结构体与唯一的构造处。
struct BatchReleaseContext<'a> {
    /// 批量配置文件所在目录，作为所有相对路径的解析基准
    config_dir: &'a Path,
    /// 本批次统一的目标版本号
    version: &'a Version,
    /// 本批次统一的最低支持版本号
    min_supported_version: Option<&'a Version>,
    /// 本批次统一的发布日期（RFC 3339）
    pub_date: &'a str,
    /// 原始批次配置，用于读取各条目的兜底字段
    batch: &'a BatchReleaseConfig,
}

/// 执行基于 TOML 配置文件的跨平台批量发布合并。
///
/// # Errors
/// 配置文件读取或 TOML 解析失败、版本号非法、任一平台包体缺失、
/// 哈希计算或元数据读取失败时返回错误。
pub(super) fn handle_batch_release(config_path: &Path, default_manifest_path: &Path) -> Result<()> {
    let batch_config = load_batch_release_config(config_path)?;
    let config_dir = config_path.parent().unwrap_or(Path::new("."));

    let version = Version::parse(&batch_config.version).with_context(|| {
        format!(
            "解析配置文件中的目标版本号 '{}' 失败，请确保符合 SemVer 规范",
            batch_config.version
        )
    })?;
    let min_supported_version = parse_optional_semver(
        batch_config.min_supported_version.as_deref(),
        "最低支持版本号",
    )?;
    let pub_date = batch_config
        .pub_date
        .clone()
        .unwrap_or_else(current_utc_rfc3339);

    let manifest_path =
        resolve_batch_manifest_path(&batch_config, config_dir, default_manifest_path);
    let resolved_expires_at = resolve_expires_at(
        batch_config.expires_at.as_deref(),
        batch_config.expires_in.as_deref(),
    )?;

    let ctx = BatchReleaseContext {
        config_dir,
        version: &version,
        min_supported_version: min_supported_version.as_ref(),
        pub_date: &pub_date,
        batch: &batch_config,
    };

    let mut manifest = load_or_init_batch_manifest(&manifest_path, &ctx, resolved_expires_at)?;

    let mut success_count = 0usize;
    for pkg in &batch_config.packages {
        merge_single_package(&mut manifest, pkg, &ctx)?;
        success_count = success_count.saturating_add(1);
        log::info!("  已完成平台 '{}' 的包签名与清单合并", pkg.target);
    }

    save_manifest_file(&manifest_path, &manifest)?;
    log::info!(
        "批量发布成功！已合并 {} 个平台的包元数据并写入 Manifest：{}",
        success_count,
        manifest_path.display()
    );
    Ok(())
}

/// 读取并反序列化批量发布 TOML 配置。
///
/// # Errors
/// 文件读取失败或 TOML 语法与字段不匹配时，返回带文件路径上下文的中文错误。
fn load_batch_release_config(config_path: &Path) -> Result<BatchReleaseConfig> {
    let toml_content = fs::read_to_string(config_path)
        .with_context(|| format!("读取批量发布配置文件失败: {}", config_path.display()))?;
    toml::from_str(&toml_content)
        .with_context(|| format!("解析批量发布配置 TOML 失败: {}", config_path.display()))
}

/// 解析批量发布最终写入的 Manifest 路径。
///
/// 配置中的相对路径以配置文件所在目录为基准展开；未配置时回退到命令行给定的默认路径。
fn resolve_batch_manifest_path(
    batch_config: &BatchReleaseConfig,
    config_dir: &Path,
    default_manifest_path: &Path,
) -> PathBuf {
    batch_config
        .manifest
        .as_ref()
        .map(|p| resolve_relative_to(config_dir, p))
        .unwrap_or_else(|| default_manifest_path.to_path_buf())
}

/// 载入已有 Manifest 并覆盖批次级字段；文件不存在时按批次配置新建一份。
///
/// # 设计原理
/// - **实现初衷**：批量发布需要支持「多次追加不同平台」的增量工作流，
///   因此必须保留清单中已有的其他平台条目，只更新本批次声明的批次级字段。
/// - **核心优势**：仅在配置显式提供时才覆盖 `expires_at` 与 `version_seq`，
///   避免未填写字段被静默清空而削弱清单的防重放能力。
///
/// # Errors
/// 读取或反序列化已有清单失败时，返回带文件路径上下文的中文错误。
fn load_or_init_batch_manifest(
    manifest_path: &Path,
    ctx: &BatchReleaseContext<'_>,
    resolved_expires_at: Option<String>,
) -> Result<Manifest> {
    if !manifest_path.exists() {
        return Ok(Manifest {
            version: ctx.version.clone(),
            min_supported_version: ctx.min_supported_version.cloned(),
            force_update: ctx.batch.force_update,
            pub_date: Some(ctx.pub_date.to_string()),
            notes: ctx.batch.notes.clone(),
            packages: BTreeMap::new(),
            channels: BTreeMap::new(),
            signature: None,
            signatures: vec![],
            rollout_percentage: ctx.batch.rollout_percentage,
            expires_at: resolved_expires_at,
            version_seq: ctx.batch.version_seq,
        });
    }

    let content = fs::read_to_string(manifest_path)
        .with_context(|| format!("读取已有 Manifest 文件失败: {}", manifest_path.display()))?;
    let mut manifest = serde_json::from_str::<Manifest>(&content)
        .with_context(|| format!("反序列化 Manifest JSON 失败: {}", manifest_path.display()))?;

    if resolved_expires_at.is_some() {
        manifest.expires_at = resolved_expires_at;
    }
    if ctx.batch.version_seq.is_some() {
        manifest.version_seq = ctx.batch.version_seq;
    }
    Ok(manifest)
}

/// 计算单个平台包体的完整信息并合并进清单。
///
/// 若条目自身未指定密钥，则回退使用批次级 `key`；两者均未提供时生成无签名条目。
///
/// # Errors
/// - 包体文件不存在：直接终止批量发布并指明缺失平台；
/// - 包类型或安装模式字符串非法：返回带可选值提示的中文错误；
/// - 哈希计算或元数据读取失败：返回带文件路径上下文的中文错误。
fn merge_single_package(
    manifest: &mut Manifest,
    pkg: &BatchPackageConfig,
    ctx: &BatchReleaseContext<'_>,
) -> Result<()> {
    let pkg_path = resolve_relative_to(ctx.config_dir, &pkg.package);
    if !pkg_path.exists() {
        anyhow::bail!(
            "平台 '{}' 对应的发布包文件不存在: {}",
            pkg.target,
            pkg_path.display()
        );
    }

    let parsed_pkg_type = PackageType::from_str(&pkg.package_type).with_context(|| {
        format!(
            "平台 '{}' 的包类型 '{}' 解析失败，可选: binary, archive, installer",
            pkg.target, pkg.package_type
        )
    })?;

    let key_path = resolve_batch_package_key(pkg, ctx);
    let (checksum, signature) = compute_payload_integrity(&pkg_path, key_path.as_deref())?;
    let parsed_install_mode = parse_install_mode(pkg.install_mode.as_deref(), Some(&pkg.target))?;
    let package_size = fs::metadata(&pkg_path)
        .with_context(|| format!("获取发布包元数据失败: {}", pkg_path.display()))?
        .len();

    let entry = ManifestReleaseEntry {
        version: ctx.version.clone(),
        min_supported_version: ctx.min_supported_version.cloned(),
        pub_date: ctx.pub_date.to_string(),
        package_info: build_package_info(PackageInfoParams {
            url: pkg.url.clone(),
            signature,
            checksum,
            package_type: parsed_pkg_type,
            install_mode: parsed_install_mode,
            install_args: pkg.install_args.clone(),
            executable_path: pkg.executable_path.clone(),
            require_elevation: pkg.require_elevation,
            wait_for_exit: pkg.wait_for_exit,
            package_size,
        }),
    };

    let update_ctx = ManifestUpdateContext::from(ctx.batch);
    update_manifest_entries(manifest, &pkg.target, &update_ctx, entry);
    Ok(())
}

/// 解析批量发布中单个平台条目应使用的签名密钥路径。
///
/// 条目自身未指定密钥时，回退使用批次级 `key`；两者均未提供时返回 `None`（不签名）。
fn resolve_batch_package_key(
    pkg: &BatchPackageConfig,
    ctx: &BatchReleaseContext<'_>,
) -> Option<PathBuf> {
    pkg.key
        .as_ref()
        .map(|p| resolve_relative_to(ctx.config_dir, p))
        .or_else(|| {
            ctx.batch
                .key
                .as_ref()
                .map(|p| resolve_relative_to(ctx.config_dir, p))
        })
}
