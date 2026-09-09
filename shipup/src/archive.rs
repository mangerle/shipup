// shipup 跨平台自更新系统 - 归档解压缩沙箱与 Zip Slip 防护

use crate::error::{Result, UpdateError};
use std::fs;
#[cfg(any(feature = "archive-zip", feature = "archive-tar"))]
use std::fs::File;
#[cfg(any(feature = "archive-zip", feature = "archive-tar"))]
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[cfg(any(feature = "archive-zip", feature = "archive-tar"))]
/// 默认解压后最大允许解压膨胀倍数（防解压炸弹）
const MAX_EXPANSION_RATIO: u64 = 10;
#[cfg(any(feature = "archive-zip", feature = "archive-tar"))]
/// 默认解压体积硬上限（1GB）
const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;

#[cfg(any(feature = "archive-zip", feature = "archive-tar"))]
/// 解压安全预算计量器（防解压炸弹）
struct ExtractionBudget {
    extracted: u64,
    max_allowed: u64,
}

#[cfg(any(feature = "archive-zip", feature = "archive-tar"))]
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

/// 解压更新归档包到安全沙箱目录，并提取指定的目标可执行文件或 Bundle
///
/// # 设计原理
/// - **实现初衷**：为分发包含依赖资产或 macOS `.app` 目录树的软件提供安全的临时解压隔离区，防止直接污染安装目录。
/// - **核心优势**：强制前置规范路径校验（Canonical Path），阻断 Zip Slip 路径逃逸，并对解压总膨胀体积实施熔断限制。
/// - **代价与局限**：解压需消耗额外的磁盘临时空间，解压完成后需由调用方负责清理沙箱目录。
///
/// # 参数
/// * `archive_path`: 归档文件路径（.zip 或 .tar.gz）
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

    let file_name = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if file_name.ends_with(".zip") {
        extract_zip(archive_path, &canonical_sandbox)?;
    } else if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
        extract_tar_gz(archive_path, &canonical_sandbox)?;
    } else {
        // 未知扩展名时优先尝试按 zip 解压，若失败则尝试按 tar.gz 解压
        if extract_zip(archive_path, &canonical_sandbox).is_err() {
            extract_tar_gz(archive_path, &canonical_sandbox)?;
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
    let max_allowed_bytes = (archive_len * MAX_EXPANSION_RATIO).min(MAX_EXTRACTED_BYTES);

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

#[cfg(feature = "archive-tar")]
fn extract_tar_gz(archive_path: &Path, canonical_sandbox: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let archive_len = file.metadata()?.len();
    let max_allowed_bytes = (archive_len * MAX_EXPANSION_RATIO).min(MAX_EXTRACTED_BYTES);

    let gz = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(gz);
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

#[cfg(not(feature = "archive-tar"))]
fn extract_tar_gz(_archive_path: &Path, _canonical_sandbox: &Path) -> Result<()> {
    Err(UpdateError::ArchiveExtract(
        "当前编译配置未启用 archive-tar 特性，无法解压 .tar.gz 归档文件".to_string(),
    ))
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
}
