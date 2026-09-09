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
pub fn get_temp_download_path(package_type: PackageType, url: &str) -> Result<PathBuf> {
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
        let file_name = format!("shipup_installer_{}.{}", std::process::id(), ext);
        return Ok(temp_dir.join(file_name));
    }

    get_same_volume_temp_path()
}
