// shipup 跨平台自更新系统 - 平台专属抽象层

use crate::error::Result;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

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
pub fn spawn_installer(installer_path: &Path, user_args: &[String]) -> Result<()> {
    #[cfg(windows)]
    {
        windows::spawn_installer(installer_path, user_args)
    }

    #[cfg(target_os = "macos")]
    {
        macos::spawn_installer(installer_path, user_args)
    }

    #[cfg(target_os = "linux")]
    {
        linux::spawn_installer(installer_path, user_args)
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let mut cmd = std::process::Command::new(installer_path);
        cmd.args(user_args);
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
