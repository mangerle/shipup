// shipup 跨平台自更新系统 - 平台专属抽象层

use crate::error::Result;
use crate::manifest::{InstallMode, PackageType};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

/// 外部安装器执行配置选项
///
/// # 设计原理
/// - **实现初衷**：统一收敛安装器调用参数（路径、自定义参数、标准模式、管理员提权），避免函数入参过多。
/// - **核心优势**：消除超过 3 个参数的散乱平铺，后续扩展环境变数或执行选项时不破坏下游 API 兼容性。
#[derive(Debug, Clone, Default)]
pub struct InstallerOptions<'a> {
    /// 附加或用户自定义 CLI 参数列表
    pub user_args: &'a [String],
    /// 安装器交互模式（如 Passive / Quiet / BasicUi）
    pub install_mode: Option<InstallMode>,
    /// 是否需要提升至操作系统管理员权限执行
    pub require_elevation: bool,
}

/// 清理以往更新遗留的临时或备份文件
///
/// # 设计原理
/// - **实现初衷**：在 Windows 等系统下，更新时旧进程二进制被重命名为 `.shipup.old`。新进程启动初始化时调用此方法清理，形成闭环。
/// - **核心优势**：静默容错清理，零运行时残留。
/// - **代价与局限**：仅针对当前可执行程序同级目录扫描。
pub fn cleanup_old_backups() {
    #[cfg(windows)]
    {
        windows::cleanup_old_backup_files();
    }
    #[cfg(target_os = "macos")]
    {
        macos::cleanup_old_backup_bundles();
    }
    #[cfg(target_os = "linux")]
    {
        linux::cleanup_old_backup_files();
    }
}

/// 执行原地原子替换
///
/// # 设计原理
/// - **实现初衷**：基于操作系统原语实现单二进制或 macOS Bundle 原地替换，覆盖 Windows 文件重命名绕过与 Unix 的 `unlink` 机制。
/// - **核心优势**：无需依赖外部更新助手程序，实现极低开销的原地自更新。
/// - **代价与局限**：要求对当前程序所在目录具有写入权限。
///
/// # Errors
/// 当底层操作系统拒绝访问或重命名替换失败时，返回 [`crate::error::UpdateError::SelfReplace`]。
pub fn replace_binary(new_binary_path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        windows::replace_current_binary(new_binary_path)
    }

    #[cfg(target_os = "macos")]
    {
        if new_binary_path.is_dir() {
            macos::replace_current_bundle(new_binary_path)
        } else {
            macos::replace_current_binary(new_binary_path)
        }
    }

    #[cfg(target_os = "linux")]
    {
        linux::replace_current_binary(new_binary_path)
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        self_replace::self_replace(new_binary_path).map_err(|e| {
            crate::error::UpdateError::SelfReplace(format!("未受支持平台的二进制替换: {}", e))
        })
    }
}

/// 向操作系统注册重启延迟替换任务（支持 Windows PendingFileRenameOperations）
///
/// # 设计原理
/// - **实现初衷**：为 Windows 平台常驻系统服务、被防病毒软件挂钩或排他锁定的进程提供下次启动生效的替换能力。
/// - **核心优势**：在操作系统下次引导初期完成原子替换，从系统级解决文件占用冲突。
/// - **代价与局限**：在非 Windows 平台调用将返回不受支持的错误；替换生效必须经历操作系统重启。
///
/// # Errors
/// 当在非 Windows 平台调用，或底层操作系统调用失败时返回错误。
pub fn schedule_reboot_replace(source_file: &Path, target_file: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        windows::schedule_reboot_replace(source_file, target_file)
    }

    #[cfg(not(windows))]
    {
        let _ = (source_file, target_file);
        Err(crate::error::UpdateError::SelfReplace(
            "重启延迟替换机制 (MoveFileEx) 仅在 Windows 操作系统原生支持".to_string(),
        ))
    }
}

/// 向操作系统注册重启延迟删除任务
///
/// # Errors
/// 当在非 Windows 平台调用，或底层操作系统调用失败时返回错误。
pub fn schedule_reboot_delete(file_to_delete: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        windows::schedule_reboot_delete(file_to_delete)
    }

    #[cfg(not(windows))]
    {
        let _ = file_to_delete;
        Err(crate::error::UpdateError::SelfReplace(
            "重启延迟删除机制 (MoveFileEx) 仅在 Windows 操作系统原生支持".to_string(),
        ))
    }
}

/// 拉起外部安装器
///
/// # 设计原理
/// - **实现初衷**：针对需要向系统受保护目录（如 Program Files）安装或具备复杂驱动的大型程序提供安装器接管模式。
/// - **核心优势**：自动脱离父进程进程树，主程序退出后安装器仍可无障碍运行并覆写文件。
/// - **代价与局限**：依赖操作系统已支持的安装程序格式（如 MSI, NSIS 或 PKG）。
///
/// # Errors
/// 当安装器子进程派生失败时返回 [`crate::error::UpdateError::InstallerSpawn`]。
pub fn spawn_installer(installer_path: &Path, options: &InstallerOptions<'_>) -> Result<()> {
    #[cfg(windows)]
    {
        windows::spawn_installer(installer_path, options)
    }

    #[cfg(target_os = "macos")]
    {
        macos::spawn_installer(installer_path, options)
    }

    #[cfg(target_os = "linux")]
    {
        linux::spawn_installer(installer_path, options)
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let mut cmd = std::process::Command::new(installer_path);
        cmd.args(options.user_args);
        cmd.spawn().map_err(|e| {
            crate::error::UpdateError::InstallerSpawn(format!("拉起安装器失败: {}", e))
        })?;
        Ok(())
    }
}

/// 获取同卷目录下的临时文件路径，规避跨卷 EXDEV 错误
///
/// # 设计原理
/// - **实现初衷**：如果临时目录位于 `/tmp`（通常为 `tmpfs` 内存卷），而程序安装在独立磁盘分区，跨文件系统重命名会抛出 `EXDEV`。
/// - **核心优势**：强制在当前可执行文件同目录下生成同卷临时文件，确保 `rename` 绝对为原子操作。
/// - **代价与局限**：要求程序同级目录具有写权限。
///
/// # Errors
/// 当获取当前程序物理路径失败时返回错误。
pub fn get_same_volume_temp_path() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        windows::get_same_volume_temp_path()
    }

    #[cfg(target_os = "macos")]
    {
        macos::get_same_volume_temp_path()
    }

    #[cfg(target_os = "linux")]
    {
        linux::get_same_volume_temp_path()
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let current = std::env::current_exe()?;
        let parent = current.parent().unwrap_or_else(|| Path::new("."));
        Ok(parent.join("app.shipup.tmp"))
    }
}

/// 根据更新包模式确定最佳的临时下载文件路径
///
/// # 设计原理
/// - **实现初衷**：
///   - 对于 `PackageType::Installer`，安装器是由独立子进程运行的完整安装包，无需与当前可执行文件处于同一磁盘卷，
///     且宿主程序可能安装在无写权限的受保护系统目录（如 `C:\Program Files`）。因此直接落盘至用户系统临时目录（`std::env::temp_dir()`），
///     彻底杜绝权限被拒错误。
///   - 对于 `PackageType::Binary` 和 `PackageType::Archive`，由于依赖原地原子重命名，强制优先使用同卷临时路径以规避跨卷 `EXDEV` 错误。
/// - **核心优势**：从根源消除安装器模式下的目录权限壁垒，兼顾原地原子替换与受保护路径升级能力。
///
/// # Errors
/// 当路径探测失败或系统临时目录不可用时返回错误。
/// 计算目标下载 URL 的简短确定性十六进制哈希指纹（前 12 位）
///
/// # 设计原理
/// - **实现初衷**：以确定性哈希区分不同的下载资源，避免多更新包在同一目录下发生文件名碰撞。
/// - **核心优势**：轻量快速，仅截取 SHA-256 前 6 字节（12 个十六进制字符）。
pub(crate) fn compute_url_hash_token(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(12);
    for b in &hash[..6] {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// 生成密码学安全随机十六进制字符串（8 字节随机熵，16 位十六进制字符）
///
/// # 设计原理
/// - **实现初衷**：为临时下载目录或文件注入不可预测的高熵随机性，消除在全局共享临时目录下被提前预测与预占投毒的安全风险。
/// - **核心优势**：直接调用操作系统级 CSPRNG，具备 64 位不可预测随机熵空间。
/// - **代价与局限**：在极端操作系统熵池耗尽情况下可能引发 I/O 错误。
pub(crate) fn generate_secure_random_hex() -> Result<String> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf)
        .map_err(|e| std::io::Error::other(format!("获取安全随机数失败: {e}")))?;
    let mut hex = String::with_capacity(16);
    for b in buf {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// 在指定基准目录下创建具备私有访问控制权限的专属隔离目录（Unix 权限严格限制为 0o700）
///
/// # 设计原理
/// - **实现初衷**：在多用户共享临时目录（如 `/tmp`）下，仅凭随机文件名仍可能面临目录遍历或竞态符号链接注入风险。
///   通过在独立子目录上显式赋予 `0o700`（仅所有者具备读、写、执行权限），从操作系统内核层面彻底阻断其他非特权用户的探测、抢占与注入。
/// - **核心优势**：即使本地恶意用户知晓文件名，也因无权访问父隔离目录而无法创建符号链接或投毒文件；跨平台安全优雅降级。
/// - **代价与局限**：创建目录依赖父级基准目录的写权限。
///
/// # Errors
/// 当底层操作系统拒绝访问或创建目录失败时返回 [`crate::error::UpdateError::Io`]。
pub(crate) fn create_secure_temp_dir(base_dir: &Path, dir_name: &str) -> Result<PathBuf> {
    let secure_dir = base_dir.join(dir_name);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(&secure_dir)?;
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&secure_dir)?;
    }

    Ok(secure_dir)
}

/// 根据更新包模式确定最佳的安全临时下载文件路径
///
/// # 设计原理
/// - **实现初衷**：
///   - 对于 `PackageType::Installer`，安装器是由独立子进程运行的完整安装介质，无需与宿主程序处于同卷。
///     落盘至操作系统临时目录时，强制创建带有高熵随机命名的专属子目录，并在 Unix 下赋予 `0o700` 私有权限，彻底杜绝共享 `/tmp` 下的预测与抢占投毒。
///   - 对于 `PackageType::Binary` 和 `PackageType::Archive`，为了规避跨文件系统重命名引发的 `EXDEV` 错误，
///     强制落盘至当前可执行文件同卷父目录，并追加安全随机十六进制后缀与 `.shipup.tmp` 标识，兼顾同卷原子替换与防抢占安全。
/// - **核心优势**：消除了共享临时目录下的预占投毒与符号链接利用风险，同时保持同卷原子替换与过期垃圾回收契约。
///
/// # Errors
/// 当路径探测失败或系统临时目录不可用时返回错误。
pub fn get_temp_download_path(package_type: PackageType, url: &str) -> Result<PathBuf> {
    let token = compute_url_hash_token(url);
    let random_hex = generate_secure_random_hex()?;

    if package_type == PackageType::Installer {
        let temp_dir = std::env::temp_dir();
        let url_path = Path::new(url.split('?').next().unwrap_or(url));
        let ext = url_path.extension().and_then(|s| s.to_str()).unwrap_or({
            #[cfg(windows)]
            {
                "exe"
            }
            #[cfg(target_os = "macos")]
            {
                "pkg"
            }
            #[cfg(not(any(windows, target_os = "macos")))]
            {
                "bin"
            }
        });
        let dir_name = format!("shipup_installer_{}_{}", token, random_hex);
        let secure_dir = create_secure_temp_dir(&temp_dir, &dir_name)?;
        let file_name = format!("installer.{}", ext);
        return Ok(secure_dir.join(file_name));
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("app");
        let file_name = format!("{}.{}.{}.shipup.tmp", exe_name, token, random_hex);
        return Ok(parent.join(file_name));
    }

    let fallback = get_same_volume_temp_path()?;
    let parent = fallback.parent().unwrap_or_else(|| Path::new("."));
    let file_name = format!("app.{}.{}.shipup.tmp", token, random_hex);
    Ok(parent.join(file_name))
}

/// 获取支持跨进程断点续传的确定性下载路径
///
/// # 设计原理
/// - **实现初衷**：默认临时路径每次生成高熵随机文件名，进程异常退出后无法再次定位部分下载文件，
///   导致 HTTP Range 断点续传仅在同进程内有效。开启跨进程续传时，需要基于 URL 派生确定性路径。
/// - **核心优势**：同一更新包 URL 始终映射到同一物理路径，进程重启后可直接续写；配合既有 Range
///   逻辑与本地缓存命中校验，实现真正跨进程的断点续传。
/// - **代价与局限**：路径可预测，不再具备防预占投毒的高熵随机性；仅推荐在受控环境或配合校验使用。
///
/// # Errors
/// 当路径探测失败或系统临时目录不可用时返回错误。
pub fn get_resumable_download_path(package_type: PackageType, url: &str) -> Result<PathBuf> {
    let token = compute_url_hash_token(url);

    if package_type == PackageType::Installer {
        let temp_dir = std::env::temp_dir();
        let url_path = Path::new(url.split('?').next().unwrap_or(url));
        let ext = url_path.extension().and_then(|s| s.to_str()).unwrap_or({
            #[cfg(windows)]
            {
                "exe"
            }
            #[cfg(target_os = "macos")]
            {
                "pkg"
            }
            #[cfg(not(any(windows, target_os = "macos")))]
            {
                "bin"
            }
        });
        let dir_name = format!("shipup_installer_{token}");
        let secure_dir = create_secure_temp_dir(&temp_dir, &dir_name)?;
        let file_name = format!("installer.{ext}");
        return Ok(secure_dir.join(file_name));
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("app");
        let file_name = format!("{exe_name}.{token}.shipup.partial");
        return Ok(parent.join(file_name));
    }

    let fallback = get_same_volume_temp_path()?;
    let parent = fallback.parent().unwrap_or_else(|| Path::new("."));
    let file_name = format!("app.{token}.shipup.partial");
    Ok(parent.join(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_random_hex_uniqueness_and_length() {
        let hex1 = generate_secure_random_hex().unwrap();
        let hex2 = generate_secure_random_hex().unwrap();

        assert_eq!(hex1.len(), 16);
        assert_eq!(hex2.len(), 16);
        assert_ne!(hex1, hex2, "多次生成的安全随机数应具备高熵唯一性");
    }

    #[test]
    fn test_create_secure_temp_dir_permissions() {
        let temp_base = std::env::temp_dir();
        let dir_name = format!("shipup_test_sec_{}", generate_secure_random_hex().unwrap());
        let secure_dir = create_secure_temp_dir(&temp_base, &dir_name).unwrap();

        assert!(secure_dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&secure_dir).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "Unix 下专属临时子目录权限必须严格为 0700");
        }

        let _ = std::fs::remove_dir(&secure_dir);
    }

    #[test]
    fn test_get_temp_download_path_installer_isolation() {
        let url = "https://example.com/packages/setup.exe?auth=token";
        let path1 = get_temp_download_path(PackageType::Installer, url).unwrap();
        let path2 = get_temp_download_path(PackageType::Installer, url).unwrap();

        assert_ne!(path1, path2, "每次下载必须生成独立的随机安全隔离路径");
        assert_eq!(path1.extension().and_then(|s| s.to_str()), Some("exe"));

        let parent1 = path1.parent().unwrap();
        assert!(parent1.is_dir(), "安装器父隔离目录必须已安全创建");

        let _ = std::fs::remove_dir(parent1);
        if let Some(parent2) = path2.parent() {
            let _ = std::fs::remove_dir(parent2);
        }
    }

    #[test]
    fn test_get_temp_download_path_binary_randomness() {
        let url = "https://example.com/binaries/myapp";
        let path1 = get_temp_download_path(PackageType::Binary, url).unwrap();
        let path2 = get_temp_download_path(PackageType::Binary, url).unwrap();

        assert_ne!(path1, path2, "二进制临时替换路径必须包含随机熵防抢占");
        let file_name1 = path1.file_name().and_then(|s| s.to_str()).unwrap();
        assert!(
            file_name1.ends_with(".shipup.tmp"),
            "临时二进制文件必须遵循 .shipup.tmp 命名规范以便垃圾回收"
        );
    }

    #[test]
    fn test_get_resumable_download_path_deterministic() {
        let url = "https://example.com/binaries/myapp-1.2.0.exe";
        let path1 = get_resumable_download_path(PackageType::Binary, url).unwrap();
        let path2 = get_resumable_download_path(PackageType::Binary, url).unwrap();

        assert_eq!(path1, path2, "同一 URL 的跨进程续传路径必须确定性可复现");
        let file_name = path1.file_name().and_then(|s| s.to_str()).unwrap();
        assert!(
            file_name.ends_with(".shipup.partial"),
            "跨进程续传文件必须遵循 .shipup.partial 命名规范"
        );

        // 不同 URL 必须映射到不同路径，避免更新包相互覆盖
        let other =
            get_resumable_download_path(PackageType::Binary, "https://example.com/other.exe")
                .unwrap();
        assert_ne!(path1, other);
    }

    #[test]
    fn test_get_resumable_download_path_installer_isolation() {
        let url = "https://example.com/setup.exe";
        let path = get_resumable_download_path(PackageType::Installer, url).unwrap();
        assert!(path.parent().is_some_and(|p| p.is_dir()));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
