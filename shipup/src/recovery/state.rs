//! 更新状态持久化与升级确认闭环。
//!
//! 本子模块承载 [`UpdateState`] 实体定义、状态文件的序列化读写、
//! 升级成功显式确认以及备份文件还原的底层原语。
//! 健康自检链路（[`crate::recovery::health`]）与主动回滚
//! （[`crate::recovery::manual`]）均依赖本模块提供的还原能力。

use crate::error::{Result, UpdateError};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 更新过程状态标记实体
///
/// # 设计原理
/// - **实现初衷**：在原子替换与进程重启之间建立状态持久化栅栏，解决新二进制缺失动态库或启动崩溃导致应用死锁的问题。
/// - **核心优势**：纯 JSON 文本序列化，无复杂数据库依赖；记录旧版本完整物理备份路径，支持一键反向覆写回滚。
/// - **代价与局限**：需要在程序运行根目录拥有临时状态写入权限。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateState {
    /// 目标新版本号
    pub target_version: String,
    /// 历史版本备份文件物理路径
    pub backup_path: PathBuf,
    /// 状态写入时的 Unix 毫秒时间戳
    pub updated_at: u64,
    /// 启动尝试崩溃计数器
    pub launch_attempts: u32,
    /// 上次尝试启动的 Unix 秒时间戳
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<u64>,
}

/// 在指定目录中持久化记录更新自愈状态标记与旧版本备份路径
///
/// # 设计原理
/// - **实现初衷**：在物理原子覆盖新版本前，将旧版本备份位置与目标版本号落盘，为异常崩溃提供可追溯恢复点。
/// - **核心优势**：格式简洁，崩溃计数器初始化为 0，若新版本正常启动并确认则立刻安全销毁。
///
/// # Errors
/// 当状态序列化失败或写入磁盘文件出错时返回 [`UpdateError::Io`]。
pub fn record_update_state(
    state_dir: &Path,
    target_version: &str,
    backup_path: &Path,
) -> Result<()> {
    let state_file = state_dir.join(super::UPDATE_STATE_FILENAME);
    let updated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let state = UpdateState {
        target_version: target_version.to_string(),
        backup_path: backup_path.to_path_buf(),
        updated_at,
        launch_attempts: 0,
        last_attempt_at: None,
    };

    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| UpdateError::ManifestParse(format!("序列化更新状态失败: {}", e)))?;
    fs::write(&state_file, json)?;
    log::info!(
        "已成功写入更新自愈状态标记: {}, 目标版本: {}",
        state_file.display(),
        target_version
    );
    Ok(())
}

/// 在指定目录显式确认新版本升级健康，彻底销毁旧版本备份与状态标记
///
/// # 设计原理
/// - **实现初衷**：为自动化测试沙箱或指定安装路径提供确定性的升级完成确认接口。
/// - **核心优势**：确认后立即安全删除历史 `.shipup.old` 备份与 `.shipup.state` 状态文件，解除磁盘占用。
///
/// # Errors
/// 当删除旧备份或移除状态标记遇到 IO 故障时返回 [`UpdateError::Io`]。
pub fn confirm_update_success_in_dir(state_dir: &Path) -> Result<bool> {
    let state_file = state_dir.join(super::UPDATE_STATE_FILENAME);
    if !state_file.exists() {
        return Ok(false);
    }

    if let Ok(content) = fs::read_to_string(&state_file)
        && let Ok(state) = serde_json::from_str::<UpdateState>(&content)
        && state.backup_path.exists()
    {
        if super::history::is_in_rollback_history(state_dir, &state.backup_path) {
            log::info!(
                "升级确认完成，历史备份已由版本历史管理器接管保留: {}",
                state.backup_path.display()
            );
        } else {
            if state.backup_path.is_dir() {
                let _ = fs::remove_dir_all(&state.backup_path);
            } else {
                let _ = fs::remove_file(&state.backup_path);
            }
            log::info!(
                "升级确认完成，已删除临时自愈备份: {}",
                state.backup_path.display()
            );
        }
    }

    let _ = fs::remove_file(&state_file);
    log::info!("已显式确认升级成功闭环，已移除状态标记");
    Ok(true)
}

/// 检查当前运行环境是否存在待确认的更新自愈状态标记
///
/// # 设计原理
/// - **实现初衷**：在更新器初始化或常规清理流程前进行探针检查，防止误删处于健康观察期的旧版本备份。
/// - **核心优势**：纯物理路径探测，零解析开销。
pub fn has_pending_recovery_state() -> bool {
    if let Some(dir) = crate::preference::resolve_safe_data_dir() {
        return dir.join(super::UPDATE_STATE_FILENAME).exists();
    }
    false
}

/// 检查并确认当前应用升级成功（在应用完成启动并平稳运行后调用）
///
/// # 设计原理
/// - **实现初衷**：作为宿主程序（如 UI 就绪、主业务线程正常启动后）调用的一站式健康确认接口。
///
/// # Errors
/// 当获取当前运行可执行文件路径失败时返回对应错误。
pub fn confirm_update_success() -> Result<bool> {
    if let Some(state_dir) = crate::preference::resolve_safe_data_dir() {
        confirm_update_success_in_dir(&state_dir)
    } else {
        Ok(false)
    }
}

/// 若存在待确认的更新自愈状态标记则静默清除（幂等）
pub(crate) fn clear_pending_state_file(state_dir: &Path) {
    let state_file = state_dir.join(super::UPDATE_STATE_FILENAME);
    if state_file.exists() {
        let _ = fs::remove_file(&state_file);
    }
}

/// 将备份路径还原到目标可执行文件位置
///
/// # 设计原理
/// - **实现初衷**：被动自愈回滚与主动版本回滚共用同一套物理还原路径，避免两处逻辑分叉。
/// - **核心优势**：
///   - 目录 Bundle（macOS `.app`）走 `rename` 原子移动；
///   - 普通文件若目标即当前运行进程则走 `self_replace`，否则直接覆盖；
///   - 文件还原完成后消费性删除备份，目录形态由 `rename` 天然搬移无需二次清理。
///
/// # Errors
/// 当目录重命名、自愈替换或文件拷贝失败时返回 [`UpdateError::SelfReplace`]。
pub(crate) fn restore_backup_to_target(
    backup_path: &Path,
    current_exe: &Path,
    self_replace_failure_label: &str,
) -> Result<()> {
    if backup_path.is_dir() {
        if current_exe.exists() {
            let _ = fs::remove_dir_all(current_exe);
        }
        if let Err(e) = fs::rename(backup_path, current_exe) {
            return Err(UpdateError::SelfReplace(format!(
                "还原历史 Bundle 备份失败: {}",
                e
            )));
        }
        return Ok(());
    }

    let is_running_exe = env::current_exe()
        .map(
            |running| match (running.canonicalize(), current_exe.canonicalize()) {
                (Ok(p1), Ok(p2)) => p1 == p2,
                _ => running == current_exe,
            },
        )
        .unwrap_or(false);

    if is_running_exe {
        if let Err(e) = self_replace::self_replace(backup_path) {
            return Err(UpdateError::SelfReplace(format!(
                "{self_replace_failure_label}: {}",
                e
            )));
        }
    } else {
        // 当目标并非当前正在运行的进程二进制（例如测试或外部托管沙箱）时，直接安全覆盖目标文件
        if current_exe.exists() {
            let _ = fs::remove_file(current_exe);
        }
        if let Err(e) = fs::copy(backup_path, current_exe) {
            return Err(UpdateError::SelfReplace(format!(
                "还原备份文件到目标可执行文件失败: {}",
                e
            )));
        }
    }
    let _ = fs::remove_file(backup_path);
    Ok(())
}
