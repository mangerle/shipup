use crate::error::{Result, UpdateError};
use crate::platform::InstallerOptions;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TEMP_SUFFIX: &str = ".shipup.tmp";
pub const OLD_BACKUP_SUFFIX: &str = ".shipup.old";

/// 清理以往更新遗留的 .shipup.old 备份 Bundle 或文件
pub fn cleanup_old_backup_bundles() {
    if let Some(current_bundle) = find_current_app_bundle()
        && let Some(parent) = current_bundle.parent()
        && let Ok(entries) = fs::read_dir(parent)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.ends_with(OLD_BACKUP_SUFFIX)
            {
                let _ = fs::remove_dir_all(&path).or_else(|_| fs::remove_file(&path));
            }
        }
    }
}

/// 清理 macOS Gatekeeper 隔离属性（com.apple.quarantine）
///
/// # 设计原理
/// - **实现初衷**：在从公网下载并解压替换 `.app` Bundle 后，macOS 会自动附加隔离属性导致启动时弹窗报错。
/// - **核心优势**：自动调用 `xattr -cr` 递归清除隔离属性，保障更新后无需用户手动信任即可直接打开。
/// - **代价与局限**：调用系统 `xattr` 命令，若系统沙盒权限极端严格可能受限。
///
/// # Errors
/// 当派生 `xattr` 命令失败时返回 [`UpdateError::SelfReplace`]。
pub fn clear_quarantine_attribute(bundle_path: &Path) -> Result<()> {
    let status = Command::new("xattr")
        .arg("-cr")
        .arg(bundle_path)
        .status()
        .map_err(|e| UpdateError::SelfReplace(format!("执行 xattr 清理隔离属性失败: {}", e)))?;

    if !status.success() {
        log::warn!(
            "清理 macOS 隔离属性返回非零状态，路径: {}",
            bundle_path.display()
        );
    }
    Ok(())
}

/// 从当前运行的可执行文件路径向上逐级查找包含它的 .app Bundle 目录
pub fn find_current_app_bundle() -> Option<PathBuf> {
    let current_exe = env::current_exe().ok()?;
    let mut cur = current_exe.parent();
    while let Some(dir) = cur {
        if let Some(ext) = dir.extension()
            && ext.eq_ignore_ascii_case("app")
        {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

/// macOS 原地原子替换整个 .app 目录结构
///
/// # 设计原理
/// - **实现初衷**：macOS 桌面程序为 `.app` 目录树架构，单二进制替换无法更新 Info.plist、Frameworks 与 Resources。
/// - **核心优势**：通过备份重命名与原子移动，避免半更新状态，并在替换完成后自动清除 Gatekeeper 隔离属性。
///
/// # Errors
/// 当备份或移动 Bundle 失败时返回 [`UpdateError::SelfReplace`]。
pub fn replace_current_bundle(new_bundle_path: &Path) -> Result<()> {
    let current_bundle = find_current_app_bundle().ok_or_else(|| {
        UpdateError::SelfReplace("未能在当前运行路径向上查找到有效的 .app 目录".to_string())
    })?;

    log::info!(
        "正在执行 macOS .app Bundle 目录级原子替换: {} -> {}",
        new_bundle_path.display(),
        current_bundle.display()
    );

    let parent = current_bundle
        .parent()
        .ok_or_else(|| UpdateError::SelfReplace("获取 .app 所在父目录失败".to_string()))?;

    let bundle_name = current_bundle
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app.app");
    let backup_bundle = parent.join(format!("{}{}", bundle_name, OLD_BACKUP_SUFFIX));

    if backup_bundle.exists() {
        let _ = fs::remove_dir_all(&backup_bundle);
    }

    fs::rename(&current_bundle, &backup_bundle)
        .map_err(|e| UpdateError::SelfReplace(format!("备份旧 .app 目录失败: {}", e)))?;

    if let Err(e) = fs::rename(new_bundle_path, &current_bundle) {
        let _ = fs::rename(&backup_bundle, &current_bundle);
        return Err(UpdateError::SelfReplace(format!(
            "移入新 .app 目录失败，已尝试恢复旧版本: {}",
            e
        )));
    }

    if let Err(e) = clear_quarantine_attribute(&current_bundle) {
        log::warn!("清除新 .app 隔离属性失败: {}", e);
    }

    let _ = fs::remove_dir_all(&backup_bundle);
    Ok(())
}

/// macOS 原地替换单个可执行文件
pub fn replace_current_binary(new_binary_path: &Path) -> Result<()> {
    self_replace::self_replace(new_binary_path)
        .map_err(|e| UpdateError::SelfReplace(format!("macOS 原地替换可执行程序失败: {}", e)))?;

    if let Some(bundle) = find_current_app_bundle() {
        let _ = clear_quarantine_attribute(&bundle);
    } else {
        let _ = clear_quarantine_attribute(new_binary_path);
    }

    Ok(())
}

/// 构建 macOS 安装器执行命令
pub(crate) fn build_macos_installer_command(
    installer_path: &Path,
    user_args: &[String],
    require_elevation: bool,
) -> Command {
    let ext = installer_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if ext == "pkg" && require_elevation {
        let script = format!(
            "do shell script \"installer -pkg '{}' -target /\" with administrator privileges",
            installer_path.display()
        );
        let mut cmd = Command::new("osascript");
        cmd.arg("-e").arg(script);
        cmd
    } else {
        let mut cmd = Command::new("open");
        if !user_args.is_empty() {
            cmd.args(user_args);
        }
        cmd.arg(installer_path);
        cmd
    }
}

/// 拉起 macOS 外部安装程序（支持 .pkg 静默安装与 .dmg 镜像自动处理）
pub fn spawn_installer(installer_path: &Path, options: &InstallerOptions<'_>) -> Result<()> {
    let mut cmd =
        build_macos_installer_command(installer_path, options.user_args, options.require_elevation);

    cmd.spawn()
        .map_err(|e| UpdateError::InstallerSpawn(format!("拉起 macOS 安装器失败: {}", e)))?;

    Ok(())
}

/// 获取同卷临时文件路径
pub fn get_same_volume_temp_path() -> Result<PathBuf> {
    let current_exe = env::current_exe()?;
    let exe_name = current_exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app");
    let temp_name = format!("{}.{}{}", exe_name, std::process::id(), TEMP_SUFFIX);

    let parent = current_exe
        .parent()
        .ok_or_else(|| UpdateError::SelfReplace("获取当前执行文件父目录失败".to_string()))?;

    Ok(parent.join(temp_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_macos_installer_command_pkg_elevation() {
        let pkg_path = Path::new("/tmp/MyApp.pkg");
        let cmd = build_macos_installer_command(pkg_path, &[], true);
        assert_eq!(cmd.get_program(), "osascript");

        let normal_cmd = build_macos_installer_command(pkg_path, &[], false);
        assert_eq!(normal_cmd.get_program(), "open");
    }

    #[test]
    fn test_build_macos_installer_command_dmg() {
        let dmg_path = Path::new("/tmp/MyApp.dmg");
        let cmd = build_macos_installer_command(dmg_path, &["-W".to_string()], false);
        assert_eq!(cmd.get_program(), "open");
    }
}
