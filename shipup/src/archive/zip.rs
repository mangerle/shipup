//! Zip 归档解压与 Zip Slip 路径逃逸防护。
//!
//! # 模块职责
//! 在特性 `archive-zip` 开启时提供真实解压逻辑；未开启时返回明确的领域错误，
//! 使调用方能够区分「包损坏」与「编译配置未启用该格式支持」。

use crate::error::{Result, UpdateError};
#[cfg(feature = "archive-zip")]
use std::fs::{self, File};
use std::path::Path;

#[cfg(feature = "archive-zip")]
use super::budget::{ExtractionBudget, MAX_EXPANSION_RATIO, MAX_EXTRACTED_BYTES};
#[cfg(feature = "archive-zip")]
use std::io;
#[cfg(feature = "archive-zip")]
use std::io::Read;

#[cfg(feature = "archive-zip")]
pub(super) fn extract_zip(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let archive_len = file.metadata()?.len();
    let max_allowed_bytes = archive_len
        .saturating_mul(MAX_EXPANSION_RATIO)
        .min(MAX_EXTRACTED_BYTES);

    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| UpdateError::ArchiveExtract(format!("读取 zip 归档失败: {}", e)))?;

    let mut budget = ExtractionBudget::new(max_allowed_bytes);

    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| UpdateError::ArchiveExtract(format!("读取 zip 条目失败: {}", e)))?;

        let enclosed_name = match entry.enclosed_name() {
            Some(path) => path.to_owned(),
            None => {
                log::warn!("检测到非法 zip 条目路径逃逸: {}", entry.name());
                return Err(UpdateError::ZipSlipViolation(entry.name().to_string()));
            }
        };

        let dest_path = canonical_sandbox.join(&enclosed_name);
        if !dest_path.starts_with(canonical_sandbox) {
            log::warn!("检测到 Zip Slip 越界路径: {}", enclosed_name.display());
            return Err(UpdateError::ZipSlipViolation(
                enclosed_name.to_string_lossy().to_string(),
            ));
        }

        unpack_single_zip_entry(&mut entry, &dest_path, &mut budget)?;
    }

    Ok(())
}

#[cfg(feature = "archive-zip")]
fn unpack_single_zip_entry<R: Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    dest_path: &Path,
    budget: &mut ExtractionBudget,
) -> Result<()> {
    if entry.is_dir() {
        fs::create_dir_all(dest_path)?;
        return Ok(());
    }

    if let Some(parent) = dest_path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    let mut out_file = File::create(dest_path)?;
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let n = entry.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        budget.check_and_add(n as u64)?;
        io::Write::write_all(&mut out_file, &buffer[..n])?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = entry.unix_mode() {
            let _ = fs::set_permissions(dest_path, fs::Permissions::from_mode(mode));
        }
    }

    Ok(())
}

#[cfg(not(feature = "archive-zip"))]
pub(super) fn extract_zip(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
    Err(UpdateError::ArchiveExtract(
        "当前编译配置未启用 archive-zip 特性，无法解压 .zip 归档文件".to_string(),
    ))
}
