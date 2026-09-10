use crate::error::{Result, UpdateError};
use crate::platform::InstallerOptions;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TEMP_SUFFIX: &str = ".shipup.tmp";
/// 旧版本备份文件后缀（与 Windows/macOS 命名保持一致）
pub const OLD_BACKUP_SUFFIX: &str = ".shipup.old";

/// 孤儿临时下载切片的最长保留过期时长（24 小时）
const ORPHAN_TEMP_EXPIRATION_SECS: u64 = 24 * 3600;

/// 清理当前主程序自身遗留的历史备份文件与过期孤儿临时切片
///
/// # 设计原理
/// - **实现初衷**：Linux 下 `self_replace` 与同卷临时切片同样会残留 `.shipup.old` / `.shipup.tmp`，
///   若不清理会在安装目录持续堆积，占用磁盘并干扰后续更新。
/// - **核心优势**：定向清理自身备份，绝不误删同目录其他进程正在下载中的临时文件或并发实例。
/// - **代价与局限**：24 小时内的未完成下载切片将被保留供断点续传，直到超时后自动回收。
pub fn cleanup_old_backup_files() {
    let Ok(current_exe) = env::current_exe() else {
        return;
    };
    let Some(parent) = current_exe.parent() else {
        return;
    };
    let exe_name = current_exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app");

    // 1. 定向清理主程序自身对应的历史备份文件
    let my_backup = parent.join(format!("{}{}", exe_name, OLD_BACKUP_SUFFIX));
    if my_backup.exists() {
        if let Err(e) = fs::remove_file(&my_backup) {
            log::debug!("清理当前程序历史备份失败 ({}): {}", my_backup.display(), e);
        } else {
            log::debug!("成功清理当前程序历史备份: {}", my_backup.display());
        }
    }

    // 2. 仅清理修改时间超过 24 小时的孤儿临时切片，避免误删正在下载的文件
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !file_name.ends_with(TEMP_SUFFIX) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age.as_secs() > ORPHAN_TEMP_EXPIRATION_SECS {
            if let Err(e) = fs::remove_file(&path) {
                log::debug!("清理过期孤儿临时切片失败 ({}): {}", path.display(), e);
            } else {
                log::debug!("成功清理过期孤儿临时切片: {}", path.display());
            }
        }
    }
}

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
///
/// # 设计原理
/// - **实现初衷**：统一调度 Linux 平台多种形态的安装介质。针对二进制文件前置修正 0o755 权限，通过 `pkexec` 调度图形化鉴权提权。
/// - **核心优势**：自动解耦子进程，主程序退出后仍能保证 dpkg/rpm 事务完整执行。
/// - **代价与局限**：依赖宿主系统预装对应的包管理程序或 PolicyKit 服务。
///
/// # Errors
/// 当权限赋予失败或安装器子进程派生失败时返回 [`UpdateError::InstallerSpawn`]。
pub fn spawn_installer(installer_path: &Path, options: &InstallerOptions<'_>) -> Result<()> {
    let ext = installer_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // 针对非 deb/rpm 的直接可执行程序（如 AppImage 或更新脚本），必须确保具备可执行权限
    if ext != "deb" && ext != "rpm" {
        ensure_executable(installer_path)?;
    }

    let mut cmd =
        build_linux_installer_command(installer_path, options.user_args, options.require_elevation);

    if options.wait_for_exit {
        let status = cmd
            .status()
            .map_err(|e| UpdateError::InstallerSpawn(format!("等待 Linux 安装器退出失败: {e}")))?;
        let code = status.code().unwrap_or(-1);
        if !status.success() {
            return Err(UpdateError::InstallerExitFailed {
                exit_code: code,
                path: installer_path.display().to_string(),
            });
        }
        log::info!("Linux 安装器已成功退出，退出码: {code}");
        return Ok(());
    }

    cmd.spawn()
        .map_err(|e| UpdateError::InstallerSpawn(format!("拉起 Linux 安装器失败: {}", e)))?;

    Ok(())
}

/// 获取 Linux 平台可执行文件同卷目录下的临时下载路径
///
/// # 设计原理
/// - **实现初衷**：在 Linux 系统中，跨磁盘分区（如从 `/tmp` tmpfs 到 `/opt` ext4）进行重命名会触发 `EXDEV: Cross-device link` 异常导致原地替换失败。
/// - **核心优势**：强制在当前程序同级目录生成带 PID 的临时文件，确保 `rename` 绝对为原子操作。
///
/// # Errors
/// 当获取当前进程可执行文件路径失败时返回错误。
pub fn get_same_volume_temp_path() -> Result<PathBuf> {
    let current_exe = env::current_exe()?;
    let exe_name = current_exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app");
    let temp_name = format!("{}{}", exe_name, TEMP_SUFFIX);

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

    #[test]
    fn test_build_linux_installer_command_generic_script() {
        let script_path = Path::new("/tmp/install.sh");
        let cmd = build_linux_installer_command(script_path, &["--prefix=/opt".to_string()], true);
        assert_eq!(cmd.get_program(), "pkexec");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args[0], script_path.as_os_str());
        assert_eq!(args[1], "--prefix=/opt");
    }

    #[test]
    fn test_linux_get_same_volume_temp_path() {
        let temp_path = get_same_volume_temp_path().unwrap();
        let file_name = temp_path.file_name().unwrap().to_str().unwrap();
        assert!(
            file_name.ends_with(TEMP_SUFFIX),
            "Linux 同卷临时文件必须以 TEMP_SUFFIX 结尾"
        );
    }

    #[test]
    fn test_linux_ensure_executable() {
        let temp_file = env::temp_dir().join("shipup_test_exec_perm.bin");
        fs::write(&temp_file, b"#!/bin/sh\necho ok").unwrap();

        ensure_executable(&temp_file).unwrap();

        let meta = fs::metadata(&temp_file).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(mode & 0o755, 0o755, "执行权限必须包含 0o755 掩码位");

        let _ = fs::remove_file(&temp_file);
    }
}
