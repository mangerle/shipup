// shipup 跨平台自更新系统 - Linux 专属平台适配

use crate::error::{Result, UpdateError};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TEMP_SUFFIX: &str = ".shipup.tmp";

/// 为 Linux 新程序赋予 0o755 执行权限
///
/// # 设计原理
/// - **实现初衷**：从 HTTP 下载的二进制切片默认不带 Unix 可执行权限位，直接替换会导致 `Permission denied` 无法启动。
/// - **核心优势**：自动赋予标准 `rwxr-xr-x`（0o755）权限位，避免用户手动执行 `chmod +x`。
///
/// # Errors
/// 当修改文件元数据失败时返回 [`UpdateError::Io`]。
pub fn ensure_executable(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

/// Linux 原地替换可执行文件
///
/// # 设计原理
/// - **实现初衷**：在 POSIX 系统中，正在执行的文件可以通过 `unlink` 移除目录项并由新文件原子替换。
///
/// # Errors
/// 当权限修正或二进制替换失败时返回 [`UpdateError::SelfReplace`]。
pub fn replace_current_binary(new_binary_path: &Path) -> Result<()> {
    ensure_executable(new_binary_path)?;
    self_replace::self_replace(new_binary_path)
        .map_err(|e| UpdateError::SelfReplace(format!("Linux 原地替换可执行程序失败: {}", e)))?;
    Ok(())
}

/// 构建 Linux 安装器执行命令
///
/// # 设计原理
/// - **实现初衷**：Linux 桌面生态分化，包含 Debian 系 `.deb`、RedHat 系 `.rpm` 以及独立执行的 `.AppImage` 或脚本。
/// - **核心优势**：
///   - 自动识别格式：针对 `.deb` 映射为 `dpkg -i`，针对 `.rpm` 映射为 `rpm -Uvh`，针对 `.AppImage` 与脚本直接执行。
///   - 系统提权：在 `require_elevation` 为 true 时，统一调用 Linux 桌面标准 `pkexec`（PolicyKit）调度提权。
/// - **代价与局限**：依赖系统预装 `dpkg`、`rpm` 或 `pkexec`。
pub(crate) fn build_linux_installer_command(
    installer_path: &Path,
    user_args: &[String],
    require_elevation: bool,
) -> Command {
    let ext = installer_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut cmd = match ext.as_str() {
        "deb" => {
            if require_elevation {
                let mut c = Command::new("pkexec");
                c.arg("dpkg").arg("-i").arg(installer_path);
                c
            } else {
                let mut c = Command::new("dpkg");
                c.arg("-i").arg(installer_path);
                c
            }
        }
        "rpm" => {
            if require_elevation {
                let mut c = Command::new("pkexec");
                c.arg("rpm").arg("-Uvh").arg(installer_path);
                c
            } else {
                let mut c = Command::new("rpm");
                c.arg("-Uvh").arg(installer_path);
                c
            }
        }
        _ => {
            if require_elevation {
                let mut c = Command::new("pkexec");
                c.arg(installer_path);
                c
            } else {
                Command::new(installer_path)
            }
        }
    };

    if !user_args.is_empty() {
        cmd.args(user_args);
    }

    cmd
}

/// 拉起 Linux 外部安装器（支持 .deb、.rpm 包管理器与 .AppImage/脚本原生调度）
pub fn spawn_installer(
    installer_path: &Path,
    user_args: &[String],
    require_elevation: bool,
) -> Result<()> {
    let ext = installer_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // 针对非 deb/rpm 的直接可执行程序（如 AppImage 或更新脚本），必须确保具备可执行权限
    if ext != "deb" && ext != "rpm" {
        ensure_executable(installer_path)?;
    }

    let mut cmd = build_linux_installer_command(installer_path, user_args, require_elevation);

    cmd.spawn()
        .map_err(|e| UpdateError::InstallerSpawn(format!("拉起 Linux 安装器失败: {}", e)))?;

    Ok(())
}

/// 获取同卷临时文件路径
pub fn get_same_volume_temp_path() -> Result<PathBuf> {
    let current_exe = env::current_exe()?;
    let exe_name = current_exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app");
    let temp_name = format!("{}.{}.shipup.tmp", exe_name, std::process::id());

    let parent = current_exe
        .parent()
        .ok_or_else(|| UpdateError::SelfReplace("获取当前执行文件父目录失败".to_string()))?;

    Ok(parent.join(temp_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_linux_installer_command_deb() {
        let deb_path = Path::new("/tmp/myapp.deb");
        let cmd_elevated =
            build_linux_installer_command(deb_path, &["--force-confold".to_string()], true);
        assert_eq!(cmd_elevated.get_program(), "pkexec");
        let args: Vec<&std::ffi::OsStr> = cmd_elevated.get_args().collect();
        assert_eq!(args[0], "dpkg");
        assert_eq!(args[1], "-i");
        assert_eq!(args[2], deb_path.as_os_str());
        assert_eq!(args[3], "--force-confold");

        let cmd_normal = build_linux_installer_command(deb_path, &[], false);
        assert_eq!(cmd_normal.get_program(), "dpkg");
        let args_normal: Vec<&std::ffi::OsStr> = cmd_normal.get_args().collect();
        assert_eq!(args_normal[0], "-i");
        assert_eq!(args_normal[1], deb_path.as_os_str());
    }

    #[test]
    fn test_build_linux_installer_command_rpm() {
        let rpm_path = Path::new("/tmp/myapp.rpm");
        let cmd = build_linux_installer_command(rpm_path, &[], true);
        assert_eq!(cmd.get_program(), "pkexec");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args[0], "rpm");
        assert_eq!(args[1], "-Uvh");
        assert_eq!(args[2], rpm_path.as_os_str());
    }

    #[test]
    fn test_build_linux_installer_command_appimage() {
        let appimage_path = Path::new("/tmp/MyApp.AppImage");
        let cmd_elevated =
            build_linux_installer_command(appimage_path, &["--appimage-extract".to_string()], true);
        assert_eq!(cmd_elevated.get_program(), "pkexec");
        let args: Vec<&std::ffi::OsStr> = cmd_elevated.get_args().collect();
        assert_eq!(args[0], appimage_path.as_os_str());
        assert_eq!(args[1], "--appimage-extract");

        let cmd_normal = build_linux_installer_command(appimage_path, &[], false);
        assert_eq!(cmd_normal.get_program(), appimage_path.as_os_str());
        let args_normal: Vec<&std::ffi::OsStr> = cmd_normal.get_args().collect();
        assert!(args_normal.is_empty());
    }
}
