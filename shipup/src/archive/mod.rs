//! 归档解压缩沙箱与 Zip Slip 路径逃逸防护模块。
//!
//! # 模块职责
//! 负责识别更新包归档格式（zip / tar.gz / tar.zst / tar.xz），在隔离沙箱目录内安全解压，
//! 对 Manifest 声明的关键载荷执行二次哈希校验，并最终把除主程序外的伴随资源（动态库、静态资源）
//! 同步到宿主应用目录。
//!
//! # 子模块划分
//! - [`budget`][]: 解压体积安全预算（防解压炸弹）
//! - [`detect`][]: 归档格式识别（魔数 + 扩展名）
//! - [`zip`][]: Zip 解压与 Zip Slip 防护（特性门控 `archive-zip`）
//! - [`tar`][]: tar.gz / tar.zst / tar.xz 解压（特性门控对应 `archive-tar*`）
//! - [`sync`][]: 解压后载荷哈希校验与资源同步
//!
//! # 设计原理
//! - **实现初衷**：解压不可信归档是整条更新链路中最易被攻击的环节，
//!   因此把「格式识别」「安全解压」「载荷校验」「资源同步」拆为四个可独立失败的阶段，
//!   任一阶段出错都能给出精确的领域错误，而不是笼统的「解压失败」。
//! - **核心优势**：
//!   - 每个解压条目在落盘前都经过路径规范化与沙箱根目录归属校验，杜绝 `../` 路径逃逸写穿宿主目录；
//!   - 解压累计体积受熔断上限约束，避免「解压炸弹」耗尽目标磁盘；
//!   - 先在沙箱内完成校验与资源同步规划，再触及宿主运行文件，保证宿主目录不会落入半途损坏的中间状态。
//! - **代价与局限**：沙箱解压需要额外一份「归档展开后」的磁盘空间；
//!   `zstd` / `xz` 两种小众格式需显式开启 `archive-tar-zst` / `archive-tar-xz` 特性才会参与编译。
//!
//! # 安全契约
//! 任何一条载荷校验失败都必须立即终止后续同步流程，严禁「先同步再校验」。

#[cfg(any(
    feature = "archive-zip",
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
mod budget;
mod detect;
mod sync;
mod tar;
mod zip;

#[cfg(test)]
mod tests;

use crate::error::{Result, UpdateError};
use std::fs;
use std::path::{Path, PathBuf};

pub use detect::{ArchiveFormat, detect_archive_format};
pub use sync::{sync_extracted_payload, verify_extracted_payload_checksums};

use tar::{extract_tar_gz, extract_tar_xz, extract_tar_zst};
use zip::extract_zip;

/// 解压更新归档包到安全沙箱目录，并提取指定的目标可执行文件或 Bundle
///
/// # 设计原理
/// - **实现初衷**：为分发包含依赖资产或 macOS `.app` 目录树的软件提供安全的临时解压隔离区，防止直接污染安装目录。
/// - **核心优势**：强制前置规范路径校验（Canonical Path），阻断 Zip Slip 路径逃逸，并对解压总膨胀体积实施熔断限制。
///   支持基于文件魔数自动嗅探 Zip、Tar.gz、Tar.zst 与 Tar.xz。
/// - **代价与局限**：解压需消耗额外的磁盘临时空间，解压完成后需由调用方负责清理沙箱目录。
///
/// # 参数
/// * `archive_path`: 归档文件路径（.zip / .tar.gz / .tar.zst / .tar.xz）
/// * `sandbox_dir`: 临时沙箱目标解压目录
/// * `executable_rel_path`: 归档包内目标主程序的相对路径
///
/// # Errors
/// - 当归档文件格式损坏时返回 [`UpdateError::ArchiveExtract`]。
/// - 当检测到 `../` 路径越界逃逸或非法软链接时抛出 [`UpdateError::ZipSlipViolation`]。
pub fn extract_archive(
    archive_path: &Path,
    sandbox_dir: &Path,
    executable_rel_path: Option<&str>,
) -> Result<PathBuf> {
    log::info!("正在初始化归档解压沙箱: {}", sandbox_dir.display());
    fs::create_dir_all(sandbox_dir)?;
    let canonical_sandbox = sandbox_dir.canonicalize()?;

    let format = detect_archive_format(archive_path);
    log::debug!("检测到归档文件格式: {:?}", format);

    match format {
        ArchiveFormat::Zip => extract_zip(archive_path, &canonical_sandbox)?,
        ArchiveFormat::TarGz => extract_tar_gz(archive_path, &canonical_sandbox)?,
        ArchiveFormat::TarZst => extract_tar_zst(archive_path, &canonical_sandbox)?,
        ArchiveFormat::TarXz => extract_tar_xz(archive_path, &canonical_sandbox)?,
        ArchiveFormat::Unknown => {
            // 未知格式时按 Zip -> TarGz -> TarZst -> TarXz 优先级顺序尝试解压
            if extract_zip(archive_path, &canonical_sandbox).is_err()
                && extract_tar_gz(archive_path, &canonical_sandbox).is_err()
                && extract_tar_zst(archive_path, &canonical_sandbox).is_err()
            {
                extract_tar_xz(archive_path, &canonical_sandbox)?;
            }
        }
    }

    if let Some(rel) = executable_rel_path {
        let target = canonical_sandbox.join(rel);
        if target.exists() {
            return Ok(target);
        }
        return Err(UpdateError::ArchiveExtract(format!(
            "归档包内未找到指定的执行文件: {}",
            rel
        )));
    }

    find_single_executable(&canonical_sandbox)
}

/// 在沙箱目录中扫描查找唯一的执行程序
fn find_single_executable(dir: &Path) -> Result<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                #[cfg(windows)]
                {
                    if let Some(ext) = path.extension()
                        && ext.eq_ignore_ascii_case("exe")
                    {
                        files.push(path);
                    }
                }
                #[cfg(not(windows))]
                {
                    files.push(path);
                }
            } else if path.is_dir() {
                #[cfg(target_os = "macos")]
                {
                    if let Some(ext) = path.extension()
                        && ext.eq_ignore_ascii_case("app")
                    {
                        return Ok(path);
                    }
                }
            }
        }
    }

    if files.len() == 1 {
        Ok(files.remove(0))
    } else {
        Err(UpdateError::ArchiveExtract(
            "归档解压后无法自动判定主程序文件，请在 Manifest 中明确指定 executable_path"
                .to_string(),
        ))
    }
}
