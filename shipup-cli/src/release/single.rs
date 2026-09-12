//! 单包发布子模块：`release` 命令在未指定 `--config` 时的单平台发布路径。
//!
//! # 模块职责
//! 解析命令行必填参数，计算包体哈希与签名，构造 [`ManifestReleaseEntry`]，
//! 并通过清单 IO 模块完成读取-合并-写回的完整闭环。
//! 当指定了 `--config` 时，本模块将分派到 [`super::batch`] 的批量发布路径。
//!
//! # 设计原理
//! - **实现初衷**：单包发布是 CI/CD 流水线中最常用的形态——
//!   每个平台 Job 独立调用一次 `release`，逐步把各自产物合并进同一份清单。
//! - **核心优势**：必填参数校验收敛到 [`SingleReleaseParams`] 参数对象，
//!   包信息构造复用 [`build_package_info`]，与批量路径共享同一套合并语义。
//! - **代价与局限**：单包模式不支持一次声明多个平台，多平台需多次调用或改用批量模式。
//!
//! # 兄弟导航
//! - [`super::batch`]：基于 TOML 配置的多平台批量发布；
//! - [`super::manifest_io`]：清单读写与条目合并的底层实现。

use super::batch::handle_batch_release;
use super::manifest_io::{
    build_package_info, load_or_init_manifest, parse_install_mode, parse_optional_semver,
    save_manifest_file, update_manifest_entries,
};
use super::types::{ManifestReleaseEntry, ManifestUpdateContext, PackageInfoParams};
use crate::cli::ReleaseArgs;
use crate::util::{compute_payload_integrity, current_utc_rfc3339};
use anyhow::{Context, Result, anyhow};
use semver::Version;
use shipup::PackageType;
use std::fs;
use std::path::Path;
use std::str::FromStr;

/// 单包发布所需的必填参数集合（参数对象模式）。
///
/// 从 [`ReleaseArgs`] 中提取五个必填字段，避免在后续逻辑中反复 `.as_deref()` / `.as_ref()`。
struct SingleReleaseParams<'a> {
    version: &'a str,
    target: &'a str,
    package_path: &'a Path,
    package_type: &'a str,
    url: &'a str,
}

/// 执行发布包签名与 Manifest 清单合并。
///
/// # 设计原理
/// - **实现初衷**：支持流水线持续集成（CI/CD）中跨 Windows、macOS、Linux
///   多 Job 逐步合并发布成果物至单份 Manifest 中。
/// - **核心优势**：若目标清单文件已存在，将自动保留已有平台的发布包配置，
///   实现平台矩阵安全增量追加。
///
/// # Errors
/// 必填参数缺失、版本号或包类型解析失败、包体文件读取失败、清单读写失败时返回中文错误。
pub(crate) fn handle_release(args: &ReleaseArgs) -> Result<()> {
    if let Some(ref config_path) = args.config {
        return handle_batch_release(config_path, &args.manifest);
    }
    release_single_package(args)
}

/// 单包发布的完整执行流程。
fn release_single_package(args: &ReleaseArgs) -> Result<()> {
    let params = extract_single_release_params(args)?;
    let version = Version::parse(params.version).with_context(|| {
        format!(
            "解析目标版本号 '{}' 失败，请确保符合 SemVer 规范",
            params.version
        )
    })?;
    let parsed_pkg_type = PackageType::from_str(params.package_type).with_context(|| {
        format!(
            "解析更新包类型 '{}' 失败，可选: binary, archive, installer",
            params.package_type
        )
    })?;
    let min_supported_version =
        parse_optional_semver(args.min_supported_version.as_deref(), "最低支持版本号")?;

    let entry = build_single_release_entry(
        args,
        &params,
        version,
        min_supported_version,
        parsed_pkg_type,
    )?;
    let update_ctx = ManifestUpdateContext::from(args);

    let mut manifest = load_or_init_manifest(&args.manifest, &update_ctx, &entry)?;
    update_manifest_entries(&mut manifest, params.target, &update_ctx, entry);

    save_manifest_file(&args.manifest, &manifest)?;
    log::info!(
        "发布信息已成功合并并写入 Manifest：{}",
        args.manifest.display()
    );
    Ok(())
}

/// 从命令行参数中提取单包发布的五个必填字段。
///
/// # Errors
/// 任一必填参数未提供时返回指明参数名的中文错误。
fn extract_single_release_params(args: &ReleaseArgs) -> Result<SingleReleaseParams<'_>> {
    let version = args
        .version
        .as_deref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --version 参数"))?;
    let target = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --target 参数"))?;
    let package_path = args
        .package
        .as_ref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --package 参数"))?;
    let package_type = args
        .package_type
        .as_deref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --package-type 参数"))?;
    let url = args
        .url
        .as_deref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --url 参数"))?;

    Ok(SingleReleaseParams {
        version,
        target,
        package_path,
        package_type,
        url,
    })
}

/// 构造单包发布的清单条目（含哈希计算、签名与包信息组装）。
///
/// # Errors
/// 包体文件读取失败、密钥文件无效或元数据获取失败时返回带路径上下文的中文错误。
fn build_single_release_entry(
    args: &ReleaseArgs,
    params: &SingleReleaseParams<'_>,
    version: Version,
    min_supported_version: Option<Version>,
    parsed_pkg_type: PackageType,
) -> Result<ManifestReleaseEntry> {
    let (checksum, signature) =
        compute_payload_integrity(params.package_path, args.key.as_deref())?;
    let parsed_install_mode = parse_install_mode(args.install_mode.as_deref(), None)?;
    let package_size = fs::metadata(params.package_path)
        .with_context(|| format!("获取发布包元数据失败: {}", params.package_path.display()))?
        .len();
    let pub_date = args.pub_date.clone().unwrap_or_else(current_utc_rfc3339);

    Ok(ManifestReleaseEntry {
        version,
        min_supported_version,
        pub_date,
        package_info: build_package_info(PackageInfoParams {
            url: params.url.to_string(),
            signature,
            checksum,
            package_type: parsed_pkg_type,
            install_mode: parsed_install_mode,
            install_args: args.install_args.clone(),
            executable_path: args.executable_path.clone(),
            require_elevation: args.require_elevation,
            wait_for_exit: args.wait_for_exit,
            package_size,
        }),
    })
}
