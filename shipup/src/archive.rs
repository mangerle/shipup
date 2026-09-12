//! 归档解压缩沙箱与 Zip Slip 路径逃逸防护模块。
//!
//! # 模块职责
//! 负责识别更新包归档格式（zip / tar.gz / tar.zst / tar.xz），在隔离沙箱目录内安全解压，
//! 对 Manifest 声明的关键载荷执行二次哈希校验，并最终把除主程序外的伴随资源（动态库、静态资源）
//! 同步到宿主应用目录。
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

use crate::error::{Result, UpdateError};
use std::fs::{self, File};
#[cfg(any(
    feature = "archive-zip",
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(any(
    feature = "archive-zip",
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
/// 默认解压后最大允许解压膨胀倍数（防解压炸弹）
const MAX_EXPANSION_RATIO: u64 = 10;
#[cfg(any(
    feature = "archive-zip",
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
/// 默认解压体积硬上限（1GB）
const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;

#[cfg(any(
    feature = "archive-zip",
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
/// 解压安全预算计量器（防解压炸弹）
struct ExtractionBudget {
    extracted: u64,
    max_allowed: u64,
}

#[cfg(any(
    feature = "archive-zip",
    feature = "archive-tar",
    feature = "archive-tar-zst",
    feature = "archive-tar-xz"
))]
impl ExtractionBudget {
    fn new(max_allowed: u64) -> Self {
        Self {
            extracted: 0,
            max_allowed,
        }
    }

    fn check_and_add(&mut self, bytes: u64) -> Result<()> {
        self.extracted = self.extracted.saturating_add(bytes);
        if self.extracted > self.max_allowed {
            return Err(UpdateError::ArchiveExtract(
                "解压后体积超出安全阈值，防解压炸弹机制已熔断".to_string(),
            ));
        }
        Ok(())
    }
}

/// 归档格式类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// 标准 Zip 压缩归档
    Zip,
    /// Gzip 压缩的 Tar 归档 (.tar.gz / .tgz)
    TarGz,
    /// Zstandard 压缩的 Tar 归档 (.tar.zst / .tzst)
    TarZst,
    /// XZ / LZMA2 压缩的 Tar 归档 (.tar.xz / .txz)
    TarXz,
    /// 无法从魔数或扩展名推断的格式
    Unknown,
}

/// 基于文件魔数（前 6 字节）与扩展名自动嗅探归档文件格式
pub fn detect_archive_format(path: &Path) -> ArchiveFormat {
    // 1. 优先读取文件头魔数进行精准特征匹配
    if let Ok(mut file) = File::open(path) {
        let mut magic = [0u8; 6];
        if let Ok(n) = Read::read(&mut file, &mut magic) {
            if n >= 4 && magic[..4] == [0x50, 0x4B, 0x03, 0x04] {
                return ArchiveFormat::Zip;
            }
            if n >= 2 && magic[..2] == [0x1F, 0x8B] {
                return ArchiveFormat::TarGz;
            }
            if n >= 4 && magic[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
                return ArchiveFormat::TarZst;
            }
            if n >= 6 && magic[..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
                return ArchiveFormat::TarXz;
            }
        }
    }

    // 2. 魔数未命中时回退到文件扩展名判定
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if file_name.ends_with(".zip") {
        ArchiveFormat::Zip
    } else if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
        ArchiveFormat::TarGz
    } else if file_name.ends_with(".tar.zst")
        || file_name.ends_with(".tzst")
        || file_name.ends_with(".zst")
    {
        ArchiveFormat::TarZst
    } else if file_name.ends_with(".tar.xz")
        || file_name.ends_with(".txz")
        || file_name.ends_with(".xz")
    {
        ArchiveFormat::TarXz
    } else {
        ArchiveFormat::Unknown
    }
}

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

#[cfg(feature = "archive-zip")]
fn extract_zip(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
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
fn extract_zip(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
    Err(UpdateError::ArchiveExtract(
        "当前编译配置未启用 archive-zip 特性，无法解压 .zip 归档文件".to_string(),
    ))
}

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
fn extract_tar_gz(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let archive_len = file.metadata()?.len();
    let max_allowed_bytes = archive_len
        .saturating_mul(MAX_EXPANSION_RATIO)
        .min(MAX_EXTRACTED_BYTES);

    let gz = flate2::read::GzDecoder::new(file);
    extract_tar_stream(gz, canonical_sandbox, max_allowed_bytes)
}

#[cfg(not(feature = "archive-tar"))]
fn extract_tar_gz(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
    Err(UpdateError::ArchiveExtract(
        "当前编译配置未启用 archive-tar 特性，无法解压 .tar.gz 归档文件".to_string(),
    ))
}

#[cfg(feature = "archive-tar-zst")]
fn extract_tar_zst(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
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
fn extract_tar_zst(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
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
fn extract_tar_xz(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
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
fn extract_tar_xz(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
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

/// 将解压目录中除主执行程序之外的全部依赖文件与资产子目录同步部署到目标应用目录
///
/// # 设计原理
/// - **实现初衷**：桌面软件通常包含伴随动态链接库（.dll / .so / .dylib）与静态资源目录。
///   若解压仅替换主程序，会导致应用因缺失资源文件或运行库而崩溃。
/// - **核心优势**：基于迭代式文件树遍历，排除了深层递归爆栈风险；前置排除主执行文件以交由原子替换机制处理。
///
/// # Errors
/// 当读写文件或创建目录失败时返回 [`UpdateError::Io`]。
pub fn sync_extracted_payload(
    payload_dir: &Path,
    target_dir: &Path,
    excluded_binary: &Path,
) -> Result<()> {
    log::info!(
        "正在同步解压资产文件，源目录: {}，目标目录: {}",
        payload_dir.display(),
        target_dir.display()
    );

    // 采用显式栈迭代遍历，防爆栈
    let mut stack = vec![payload_dir.to_path_buf()];

    while let Some(current_dir) = stack.pop() {
        for entry in fs::read_dir(&current_dir)? {
            let entry = entry?;
            let path = entry.path();

            // 如果是主程序文件，跳过（留待原子替换流程单独处理）
            if path == excluded_binary {
                continue;
            }

            let rel_path = match path.strip_prefix(payload_dir) {
                Ok(rel) => rel,
                Err(_) => continue,
            };
            let dest_path = target_dir.join(rel_path);

            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                fs::create_dir_all(&dest_path)?;
                stack.push(path);
            } else if file_type.is_file() {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&path, &dest_path)?;
                #[cfg(unix)]
                {
                    if let Ok(meta) = path.metadata() {
                        let _ = fs::set_permissions(&dest_path, meta.permissions());
                    }
                }
            }
        }
    }

    Ok(())
}

/// 校验归档解压目录内声明的关键文件 SHA-256 完整性
///
/// # 设计原理
/// - **实现初衷**：归档级数字签名仅覆盖压缩包原始字节；若解压器存在边界缺陷，落盘内容可能偏离原始意图。
///   通过 Manifest 声明关键文件哈希，在部署前形成二次防伪。
/// - **核心优势**：仅校验调用方声明的关键文件，避免全量扫盘的性能开销；路径强制限制在沙箱根内，防路径逃逸。
/// - **代价与局限**：发布端必须维护并更新 `payload_checksums`；未声明的文件不会被额外校验。
///
/// # Errors
/// - 当相对路径越界逃逸沙箱时返回 [`UpdateError::ZipSlipViolation`]。
/// - 当关键文件缺失时返回 [`UpdateError::ArchiveExtract`]。
/// - 当哈希不匹配时返回 [`UpdateError::ChecksumMismatch`]。
pub fn verify_extracted_payload_checksums(
    extract_root: &Path,
    expected: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }

    let canonical_root = extract_root
        .canonicalize()
        .map_err(|e| UpdateError::ArchiveExtract(format!("解压根目录规范化失败: {e}")))?;

    for (rel, checksum) in expected {
        let target = canonical_root.join(rel);
        let canonical_target = target
            .canonicalize()
            .map_err(|_| UpdateError::ArchiveExtract(format!("解压后关键文件缺失: {}", rel)))?;
        if !canonical_target.starts_with(&canonical_root) {
            return Err(UpdateError::ZipSlipViolation(rel.clone()));
        }
        if !canonical_target.is_file() {
            return Err(UpdateError::ArchiveExtract(format!(
                "解压后关键路径不是普通文件: {}",
                rel
            )));
        }
        crate::signature::verify_sha256_file(&canonical_target, checksum)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_sync_extracted_payload_copies_assets_and_excludes_binary() {
        let temp_base =
            std::env::temp_dir().join(format!("shipup_archive_test_{}", std::process::id()));
        let payload_dir = temp_base.join("payload");
        let target_dir = temp_base.join("install_dir");

        let _ = fs::remove_dir_all(&temp_base);
        fs::create_dir_all(&payload_dir).unwrap();
        fs::create_dir_all(&target_dir).unwrap();

        // 构造沙箱内的文件树
        let exe_path = payload_dir.join("myapp.exe");
        let dll_path = payload_dir.join("core.dll");
        let assets_dir = payload_dir.join("assets");
        fs::create_dir_all(&assets_dir).unwrap();
        let asset_file = assets_dir.join("logo.png");

        File::create(&exe_path)
            .unwrap()
            .write_all(b"new-exe")
            .unwrap();
        File::create(&dll_path)
            .unwrap()
            .write_all(b"new-dll")
            .unwrap();
        File::create(&asset_file)
            .unwrap()
            .write_all(b"new-logo")
            .unwrap();

        // 执行资产同步，排除 myapp.exe
        let res = sync_extracted_payload(&payload_dir, &target_dir, &exe_path);
        assert!(res.is_ok());

        // 验证主程序未被该方法直接覆盖（由原子替换接管）
        assert!(!target_dir.join("myapp.exe").exists());
        // 验证动态库与子目录资源已成功同步并完整保留
        assert!(target_dir.join("core.dll").exists());
        assert_eq!(fs::read(target_dir.join("core.dll")).unwrap(), b"new-dll");
        assert!(target_dir.join("assets").join("logo.png").exists());
        assert_eq!(
            fs::read(target_dir.join("assets").join("logo.png")).unwrap(),
            b"new-logo"
        );

        let _ = fs::remove_dir_all(&temp_base);
    }

    #[test]
    fn test_detect_archive_format_by_magic_and_extension() {
        let temp_dir =
            std::env::temp_dir().join(format!("shipup_detect_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // 1. 测试扩展名推断
        let zip_path = temp_dir.join("test.zip");
        File::create(&zip_path).unwrap();
        assert_eq!(detect_archive_format(&zip_path), ArchiveFormat::Zip);

        let targz_path = temp_dir.join("test.tar.gz");
        File::create(&targz_path).unwrap();
        assert_eq!(detect_archive_format(&targz_path), ArchiveFormat::TarGz);

        let tarzst_path = temp_dir.join("test.tar.zst");
        File::create(&tarzst_path).unwrap();
        assert_eq!(detect_archive_format(&tarzst_path), ArchiveFormat::TarZst);

        let tarxz_path = temp_dir.join("test.tar.xz");
        File::create(&tarxz_path).unwrap();
        assert_eq!(detect_archive_format(&tarxz_path), ArchiveFormat::TarXz);

        // 2. 测试基于魔数识别（无扩展名文件）
        let magic_zst = temp_dir.join("package_zst_no_ext");
        fs::write(&magic_zst, [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00]).unwrap();
        assert_eq!(detect_archive_format(&magic_zst), ArchiveFormat::TarZst);

        let magic_xz = temp_dir.join("package_xz_no_ext");
        fs::write(&magic_xz, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]).unwrap();
        assert_eq!(detect_archive_format(&magic_xz), ArchiveFormat::TarXz);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[cfg(feature = "archive-tar-xz")]
    #[test]
    fn test_extract_tar_xz_and_magic_sniffing() {
        let temp_dir =
            std::env::temp_dir().join(format!("shipup_tar_xz_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // 打包单个可执行文件进 tar
        let mut tar_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let payload_content = b"hello tar.xz payload binary";
        header.set_path("my_xz_app.exe").unwrap();
        header.set_size(payload_content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar_builder.append(&header, &payload_content[..]).unwrap();
        let tar_bytes = tar_builder.into_inner().unwrap();

        // 使用 lzma_rs 压缩为 xz 流
        let mut xz_bytes = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(tar_bytes), &mut xz_bytes).unwrap();

        // 写入无扩展名文件，验证魔数识别自动触发 xz 解压
        let archive_file = temp_dir.join("unnamed_archive_bundle");
        fs::write(&archive_file, xz_bytes).unwrap();

        let sandbox = temp_dir.join("sandbox");
        let extracted_exe =
            extract_archive(&archive_file, &sandbox, Some("my_xz_app.exe")).unwrap();

        assert!(extracted_exe.exists());
        assert_eq!(fs::read(extracted_exe).unwrap(), payload_content);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[cfg(feature = "archive-tar-zst")]
    #[test]
    fn test_extract_tar_zst_and_magic_sniffing() {
        let temp_dir =
            std::env::temp_dir().join(format!("shipup_tar_zst_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // 打包单个可执行文件进 tar
        let mut tar_builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let payload_content = b"hello tar.zst payload binary";
        header.set_path("my_zst_app.exe").unwrap();
        header.set_size(payload_content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar_builder.append(&header, &payload_content[..]).unwrap();
        let tar_bytes = tar_builder.into_inner().unwrap();

        // 使用 ruzstd 压缩为 zstd 帧
        let zst_bytes = ruzstd::encoding::compress_to_vec(
            &tar_bytes[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );

        // 写入无扩展名文件，验证魔数识别自动触发 zstd 解压
        let archive_file = temp_dir.join("unnamed_zst_archive_bundle");
        fs::write(&archive_file, zst_bytes).unwrap();

        let sandbox = temp_dir.join("sandbox");
        let extracted_exe =
            extract_archive(&archive_file, &sandbox, Some("my_zst_app.exe")).unwrap();

        assert!(extracted_exe.exists());
        assert_eq!(fs::read(extracted_exe).unwrap(), payload_content);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_verify_extracted_payload_checksums_success_and_failure() {
        use sha2::{Digest, Sha256};
        use std::collections::BTreeMap;

        let temp_dir = std::env::temp_dir().join(format!(
            "shipup_payload_checksum_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(temp_dir.join("bin")).unwrap();

        let content = b"critical-binary-content";
        let file_path = temp_dir.join("bin/app.exe");
        fs::write(&file_path, content).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(content);
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }

        let mut expected = BTreeMap::new();
        expected.insert("bin/app.exe".to_string(), format!("sha256:{hex}"));

        // 正常路径应通过
        assert!(verify_extracted_payload_checksums(&temp_dir, &expected).is_ok());

        // 篡改文件内容后应失败
        fs::write(&file_path, b"tampered").unwrap();
        assert!(matches!(
            verify_extracted_payload_checksums(&temp_dir, &expected),
            Err(UpdateError::ChecksumMismatch { .. })
        ));

        // 还原正确内容后，声明不存在的关键文件应失败
        fs::write(&file_path, content).unwrap();
        expected.insert("bin/missing.dll".to_string(), format!("sha256:{hex}"));
        assert!(matches!(
            verify_extracted_payload_checksums(&temp_dir, &expected),
            Err(UpdateError::ArchiveExtract(_))
        ));

        // 路径逃逸应被拦截
        let mut escape_map = BTreeMap::new();
        escape_map.insert("../outside.exe".to_string(), format!("sha256:{hex}"));
        assert!(verify_extracted_payload_checksums(&temp_dir, &escape_map).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
