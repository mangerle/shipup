//! 启动健康自检与连续崩溃自愈回滚链路。
//!
//! 本子模块实现「观察期 + 崩溃窗口」双约束的启动健康检查：
//! 每次未确认启动均累加崩溃计数器，当连续崩溃次数超过阈值时
//! 自动调用备份还原原语完成自愈回滚。

use crate::error::Result;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::state::{UpdateState, confirm_update_success_in_dir, restore_backup_to_target};

/// 启动健康检查与自愈判定结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthCheckStatus {
    /// 无待确认的更新状态（常规健康启动）
    Normal,
    /// 处于新版本健康观察期（已记录当前启动尝试次数）
    PendingConfirmation {
        /// 当前启动尝试次数
        attempts: u32,
    },
    /// 连续启动崩溃次数超过上限，已自动触发自愈并回滚至旧版本
    RolledBack {
        /// 回滚前的故障版本号
        from_version: String,
    },
}

/// 执行启动健康自检与异常连续崩溃自愈回滚
///
/// # 设计原理
/// - **实现初衷**：防范因缺少动态库、配置不兼容或新代码缺陷导致的程序连续启动崩溃死锁。
/// - **核心优势**：当崩溃次数超过阈值（`max_allowed_crashes`），自动用历史稳定备份原子覆盖当前崩溃二进制，实现无人值守自愈。
/// - **代价与局限**：每次未确认启动均会递增崩溃计数器，因此宿主程序启动平稳后必须显式调用确认函数。
///
/// # Errors
/// 当回滚覆盖底层文件失败时返回 [`crate::error::UpdateError::SelfReplace`]。
pub fn check_and_recover(
    state_dir: &Path,
    current_exe: &Path,
    max_allowed_crashes: u32,
) -> Result<HealthCheckStatus> {
    let state_file = state_dir.join(super::UPDATE_STATE_FILENAME);
    if !state_file.exists() {
        return Ok(HealthCheckStatus::Normal);
    }

    let content = match fs::read_to_string(&state_file) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("读取更新状态标记失败，清理损坏标记: {}", e);
            let _ = fs::remove_file(&state_file);
            return Ok(HealthCheckStatus::Normal);
        }
    };

    let mut state: UpdateState = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("反序列化更新状态标记失败，清理损坏标记: {}", e);
            let _ = fs::remove_file(&state_file);
            return Ok(HealthCheckStatus::Normal);
        }
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Some(last_at) = state.last_attempt_at {
        let elapsed = now_secs.saturating_sub(last_at);
        if elapsed >= super::CRASH_WINDOW_THRESHOLD_SECS {
            log::info!(
                "新版本距上次启动已平稳度过健康观察期 ({} 秒 >= {} 秒)，自动完成升级确认",
                elapsed,
                super::CRASH_WINDOW_THRESHOLD_SECS
            );
            let _ = confirm_update_success_in_dir(state_dir);
            return Ok(HealthCheckStatus::Normal);
        }
    }

    state.last_attempt_at = Some(now_secs);
    state.launch_attempts = state.launch_attempts.saturating_add(1);

    if state.launch_attempts > max_allowed_crashes {
        execute_rollback(&state, current_exe, &state_file)?;
        return Ok(HealthCheckStatus::RolledBack {
            from_version: state.target_version,
        });
    }

    // 仍在健康观察尝试期，写回累加后的计数
    if let Ok(json) = serde_json::to_string_pretty(&state) {
        let _ = fs::write(&state_file, json);
    }

    log::info!(
        "检测到新版本更新待确认状态，当前为第 {}/{} 次尝试启动",
        state.launch_attempts,
        max_allowed_crashes
    );
    Ok(HealthCheckStatus::PendingConfirmation {
        attempts: state.launch_attempts,
    })
}

fn execute_rollback(state: &UpdateState, current_exe: &Path, state_file: &Path) -> Result<()> {
    log::warn!(
        "新版本 ({}) 启动连续崩溃次数已达上限，触发自愈回滚！",
        state.target_version
    );

    if state.backup_path.exists() {
        log::info!(
            "正在将历史备份版本还原: {} -> {}",
            state.backup_path.display(),
            current_exe.display()
        );
        restore_backup_to_target(&state.backup_path, current_exe, "执行自愈回滚失败")?;
    } else {
        // 备份缺失时降级放行并清除状态标记，避免把用户永久锁死在「无法启动」状态
        log::warn!(
            "自愈回滚降级放行: 未找到历史备份文件 {}，仅清除更新状态标记",
            state.backup_path.display()
        );
    }

    let _ = fs::remove_file(state_file);
    log::info!("自愈回滚执行完成，已清除更新状态标记");
    Ok(())
}

/// 执行当前可执行文件同级目录的自检与自愈恢复（推荐在应用入口 main 首行调用）
///
/// # 设计原理
/// - **实现初衷**：在宿主加载任何重量级依赖或动态库之前前置介入自检，保证在程序因缺失新 DLL 导致崩溃时仍能被捕获。
///
/// # Errors
/// 当回滚覆盖底层失败时返回 [`crate::error::UpdateError::SelfReplace`]。
pub fn check_and_recover_current(max_allowed_crashes: u32) -> Result<HealthCheckStatus> {
    let current_exe = env::current_exe()?;
    let state_dir = crate::preference::resolve_safe_data_dir().unwrap_or_else(|| {
        current_exe
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    check_and_recover(&state_dir, &current_exe, max_allowed_crashes)
}

static RECOVERY_ONCE_GUARD: AtomicBool = AtomicBool::new(false);

/// 在当前进程生命周期内仅执行一次启动健康检查与自愈
///
/// # 设计原理
/// - **实现初衷**：防止应用内多次实例化更新器时重复累加启动崩溃计数触发误回滚。
/// - **核心优势**：基于原子布尔标志位保障线程安全，后续调用直接返回健康状态且不产生文件 I/O。
///
/// # Errors
/// 当底层执行回滚覆盖可执行文件失败时返回对应错误。
pub fn check_and_recover_once(max_allowed_crashes: u32) -> Result<HealthCheckStatus> {
    if RECOVERY_ONCE_GUARD.swap(true, Ordering::SeqCst) {
        return Ok(HealthCheckStatus::Normal);
    }
    check_and_recover_current(max_allowed_crashes)
}
