//! Tar 系列归档解压（tar.gz / tar.zst / tar.xz）。
//!
//! # 模块职责
//! 在对应特性（`archive-tar` / `archive-tar-zst` / `archive-tar-xz`）开启时提供真实解压逻辑；
//! 未开启时返回明确的领域错误。所有 tar 变体共享同一套「流式解压 + Zip Slip 路径防护」内核。

use crate::error::{Result, UpdateError};
#[cfg(any(
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
use std::fs::{self, File};
use std::path::Path;

#[cfg(any(
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
use super::budget::{ExtractionBudget, MAX_EXPANSION_RATIO, MAX_EXTRACTED_BYTES};
#[cfg(any(
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
use std::io;
#[cfg(any(
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
use std::io::Read;

#[cfg(any(
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
fn extract_tar_stream<R: Read>(
    reader: R,
    canonical_sandbox: &Path,
    max_allowed_bytes: u64,
) -> Result<()> {
    let mut tar = tar::Archive::new(reader);
    let mut budget = ExtractionBudget::new(max_allowed_bytes);

    let entries = tar
        .entries()
        .map_err(|e| UpdateError::ArchiveExtract(format!("读取 tar 条目列表失败: {}", e)))?;

    for entry_res in entries {
        let mut entry = entry_res
            .map_err(|e| UpdateError::ArchiveExtract(format!("解析 tar 条目失败: {}", e)))?;

        let entry_path = entry
            .path()
            .map_err(|e| UpdateError::ArchiveExtract(format!("读取条目路径失败: {}", e)))?
            .into_owned();

        if entry_path.is_absolute()
            || entry_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            log::warn!(
                "检测到非法 tar 条目绝对路径或回溯路径: {}",
                entry_path.display()
            );
            return Err(UpdateError::ZipSlipViolation(
                entry_path.to_string_lossy().to_string(),
            ));
        }

        let dest_path = canonical_sandbox.join(&entry_path);
        if !dest_path.starts_with(canonical_sandbox) {
            log::warn!("检测到 Tar 越界路径逃逸: {}", entry_path.display());
            return Err(UpdateError::ZipSlipViolation(
                entry_path.to_string_lossy().to_string(),
            ));
        }

        unpack_single_tar_entry(&mut entry, &dest_path, &mut budget)?;
    }

    Ok(())
}

#[cfg(feature = "archive-tar")]
pub(super) fn extract_tar_gz(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let archive_len = file.metadata()?.len();
    let max_allowed_bytes = archive_len
        .saturating_mul(MAX_EXPANSION_RATIO)
        .min(MAX_EXTRACTED_BYTES);

    let gz = flate2::read::GzDecoder::new(file);
    extract_tar_stream(gz, canonical_sandbox, max_allowed_bytes)
}

#[cfg(not(feature = "archive-tar"))]
pub(super) fn extract_tar_gz(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
    Err(UpdateError::ArchiveExtract(
        "当前编译配置未启用 archive-tar 特性，无法解压 .tar.gz 归档文件".to_string(),
    ))
}

#[cfg(feature = "archive-tar-zst")]
pub(super) fn extract_tar_zst(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let archive_len = file.metadata()?.len();
    let max_allowed_bytes = archive_len
        .saturating_mul(MAX_EXPANSION_RATIO)
        .min(MAX_EXTRACTED_BYTES);

    let zst = ruzstd::decoding::StreamingDecoder::new(file)
        .map_err(|e| UpdateError::ArchiveExtract(format!("初始化 zstd 解压器失败: {}", e)))?;
    extract_tar_stream(zst, canonical_sandbox, max_allowed_bytes)
}

#[cfg(not(feature = "archive-tar-zst"))]
pub(super) fn extract_tar_zst(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
    Err(UpdateError::ArchiveExtract(
        "当前编译配置未启用 archive-tar-zst 特性，无法解压 .tar.zst 归档文件".to_string(),
    ))
}

#[cfg(feature = "archive-tar-xz")]
/// 带有体积安全预算的写入封装（防解压炸弹）
struct BudgetedWriter<'a, W: io::Write> {
    writer: &'a mut W,
    budget: ExtractionBudget,
}

#[cfg(feature = "archive-tar-xz")]
impl<'a, W: io::Write> BudgetedWriter<'a, W> {
    fn new(writer: &'a mut W, max_allowed: u64) -> Self {
        Self {
            writer,
            budget: ExtractionBudget::new(max_allowed),
        }
    }
}

#[cfg(feature = "archive-tar-xz")]
impl<'a, W: io::Write> io::Write for BudgetedWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.budget
            .check_and_add(buf.len() as u64)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(feature = "archive-tar-xz")]
pub(super) fn extract_tar_xz(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
    use std::io::BufReader;
    let file = File::open(archive_path)?;
    let archive_len = file.metadata()?.len();
    let max_allowed_bytes = archive_len
        .saturating_mul(MAX_EXPANSION_RATIO)
        .min(MAX_EXTRACTED_BYTES);

    let temp_tar_path = canonical_sandbox.join(".shipup_decompressed.tar");
    {
        let mut reader = BufReader::new(file);
        let mut out_file = File::create(&temp_tar_path)?;
        let mut budgeted_writer = BudgetedWriter::new(&mut out_file, max_allowed_bytes);
        lzma_rs::xz_decompress(&mut reader, &mut budgeted_writer)
            .map_err(|e| UpdateError::ArchiveExtract(format!("解压 xz 数据流失败: {}", e)))?;
    }

    let tar_file = File::open(&temp_tar_path)?;
    let res = extract_tar_stream(tar_file, canonical_sandbox, max_allowed_bytes);
    let _ = fs::remove_file(&temp_tar_path);
    res
}

#[cfg(not(feature = "archive-tar-xz"))]
pub(super) fn extract_tar_xz(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
    Err(UpdateError::ArchiveExtract(
        "当前编译配置未启用 archive-tar-xz 特性，无法解压 .tar.xz 归档文件".to_string(),
    ))
}

#[cfg(any(
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
fn unpack_single_tar_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    dest_path: &Path,
    budget: &mut ExtractionBudget,
) -> Result<()> {
    let entry_type = entry.header().entry_type();
    if entry_type.is_symlink() || entry_type.is_hard_link() {
        return Ok(());
    }

    if entry_type.is_dir() {
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
        if let Ok(mode) = entry.header().mode() {
            let _ = fs::set_permissions(dest_path, fs::Permissions::from_mode(mode));
        }
    }

    Ok(())
}
