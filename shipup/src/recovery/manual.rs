//! 主动指定历史版本执行回滚。
//!
//! 本子模块提供宿主程序主动选择历史版本并一键恢复的能力，
//! 与被动自愈共用底层还原原语，保证两条入口行为一致。

use crate::error::Result;
use semver::Version;
use std::path::Path;

use super::history::{
    find_existing_rollback_entry, load_rollback_history, remove_history_entry,
    save_rollback_history,
};
use super::state::{clear_pending_state_file, restore_backup_to_target};

/// 执行主动回滚至指定的历史版本
///
/// # 设计原理
/// - **实现初衷**：使宿主程序具备主动指定历史版本并一键恢复的能力，突破原有"被动崩溃 3 次才回滚"的局限。
/// - **核心优势**：自动校验物理备份完整性，兼容当前运行进程原地替换与外部托管沙箱，成功后清除临时自愈标记。
///
/// # Errors
/// 当指定版本在历史中不存在、备份物理文件已丢失或原子还原替换失败时返回错误。
pub fn execute_manual_rollback_to(
    history_dir: &Path,
    current_exe: &Path,
    target_version: &Version,
) -> Result<()> {
    let mut history = load_rollback_history(history_dir);
    let entry = find_existing_rollback_entry(&history, target_version)?;

    log::warn!(
        "正在执行主动回滚: 目标历史版本 {}, 备份文件: {} -> 目标程序: {}",
        target_version,
        entry.backup_path.display(),
        current_exe.display()
    );

    restore_backup_to_target(&entry.backup_path, current_exe, "执行主动版本回滚失败")?;

    remove_history_entry(&mut history, target_version);
    let _ = save_rollback_history(history_dir, &history);
    clear_pending_state_file(history_dir);

    log::info!("主动回滚至历史版本 {} 执行成功", target_version);
    Ok(())
}
