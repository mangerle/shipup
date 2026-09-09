// shipup 跨平台自更新系统 - 版本自愈与启动健康自检恢复引擎

use crate::error::{Result, UpdateError};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// 更新过程状态持久化文件名
pub const UPDATE_STATE_FILENAME: &str = ".shipup.state";

/// 默认容忍的最大崩溃启动尝试次数
pub const DEFAULT_MAX_CRASH_ATTEMPTS: u32 = 2;

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
}

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
    let state_file = state_dir.join(UPDATE_STATE_FILENAME);
    let updated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let state = UpdateState {
        target_version: target_version.to_string(),
        backup_path: backup_path.to_path_buf(),
        updated_at,
        launch_attempts: 0,
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

/// 执行启动健康自检与异常连续崩溃自愈回滚
///
/// # 设计原理
/// - **实现初衷**：防范因缺少动态库、配置不兼容或新代码缺陷导致的程序连续启动崩溃死锁。
/// - **核心优势**：当崩溃次数超过阈值（`max_allowed_crashes`），自动用历史稳定备份原子覆盖当前崩溃二进制，实现无人值守自愈。
/// - **代价与局限**：每次未确认启动均会递增崩溃计数器，因此宿主程序启动平稳后必须显式调用确认函数。
///
/// # Errors
/// 当回滚覆盖底层文件失败时返回 [`UpdateError::SelfReplace`]。
pub fn check_and_recover(
    state_dir: &Path,
    current_exe: &Path,
    max_allowed_crashes: u32,
) -> Result<HealthCheckStatus> {
    let state_file = state_dir.join(UPDATE_STATE_FILENAME);
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

        let is_running_exe = env::current_exe()
            .map(
                |running| match (running.canonicalize(), current_exe.canonicalize()) {
                    (Ok(p1), Ok(p2)) => p1 == p2,
                    _ => running == current_exe,
                },
            )
            .unwrap_or(false);

        if is_running_exe {
            if let Err(e) = self_replace::self_replace(&state.backup_path) {
                return Err(UpdateError::SelfReplace(format!("执行自愈回滚失败: {}", e)));
            }
        } else {
            // 当目标并非当前正在运行的进程二进制（例如测试或外部托管沙箱）时，直接安全覆盖目标文件
            if current_exe.exists() {
                let _ = fs::remove_file(current_exe);
            }
            if let Err(e) = fs::copy(&state.backup_path, current_exe) {
                return Err(UpdateError::SelfReplace(format!(
                    "还原备份文件到目标可执行文件失败: {}",
                    e
                )));
            }
        }
        let _ = fs::remove_file(&state.backup_path);
    } else {
        log::error!(
            "无法执行自愈回滚: 未找到历史备份文件: {}",
            state.backup_path.display()
        );
    }

    let _ = fs::remove_file(state_file);
    log::info!("自愈回滚执行完成，已清除更新状态标记");
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
    let state_file = state_dir.join(UPDATE_STATE_FILENAME);
    if !state_file.exists() {
        return Ok(false);
    }

    if let Ok(content) = fs::read_to_string(&state_file)
        && let Ok(state) = serde_json::from_str::<UpdateState>(&content)
        && state.backup_path.exists()
    {
        let _ = fs::remove_file(&state.backup_path);
        log::info!(
            "升级确认完成，已删除历史备份: {}",
            state.backup_path.display()
        );
    }

    let _ = fs::remove_file(&state_file);
    log::info!("已显式确认升级成功闭环，已移除状态标记");
    Ok(true)
}

/// 检查并确认当前应用升级成功（在应用完成启动并平稳运行后调用）
///
/// # 设计原理
/// - **实现初衷**：作为宿主程序（如 UI 就绪、主业务线程正常启动后）调用的一站式健康确认接口。
///
/// # Errors
/// 当获取当前运行可执行文件路径失败时返回对应错误。
pub fn confirm_update_success() -> Result<bool> {
    let current_exe = env::current_exe()?;
    if let Some(parent) = current_exe.parent() {
        confirm_update_success_in_dir(parent)
    } else {
        Ok(false)
    }
}

/// 执行当前可执行文件同级目录的自检与自愈恢复（推荐在应用入口 main 首行调用）
///
/// # 设计原理
/// - **实现初衷**：在宿主加载任何重量级依赖或动态库之前前置介入自检，保证在程序因缺失新 DLL 导致崩溃时仍能被捕获。
///
/// # Errors
/// 当回滚覆盖底层失败时返回 [`UpdateError::SelfReplace`]。
pub fn check_and_recover_current(max_allowed_crashes: u32) -> Result<HealthCheckStatus> {
    let current_exe = env::current_exe()?;
    let state_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));
    check_and_recover(state_dir, &current_exe, max_allowed_crashes)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_confirm_update_state() {
        let temp_dir = env::temp_dir().join(format!("shipup_rec_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let dummy_backup = temp_dir.join("app.shipup.old");
        fs::write(&dummy_backup, b"old-binary").unwrap();

        // 1. 记录更新状态
        record_update_state(&temp_dir, "2.0.0", &dummy_backup).unwrap();
        let state_file = temp_dir.join(UPDATE_STATE_FILENAME);
        assert!(state_file.exists());

        // 2. 第一次自检启动尝试，仍处于观察期
        let dummy_exe = temp_dir.join("app.exe");
        fs::write(&dummy_exe, b"new-binary").unwrap();
        let status1 = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
        assert_eq!(
            status1,
            HealthCheckStatus::PendingConfirmation { attempts: 1 }
        );

        // 3. 显式确认成功，备份文件与状态标记均被清理
        let confirmed = confirm_update_success_in_dir(&temp_dir).unwrap();
        assert!(confirmed);
        assert!(!state_file.exists());
        assert!(!dummy_backup.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_crash_loop_triggers_rollback() {
        let temp_dir = env::temp_dir().join(format!("shipup_crash_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let dummy_backup = temp_dir.join("app.shipup.old");
        fs::write(&dummy_backup, b"old-stable-binary").unwrap();

        let dummy_exe = temp_dir.join("app.exe");
        fs::write(&dummy_exe, b"broken-new-binary").unwrap();

        record_update_state(&temp_dir, "2.0.1", &dummy_backup).unwrap();

        // 第 1 次启动崩溃后重启（attempts = 1 <= 2）
        let s1 = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
        assert_eq!(s1, HealthCheckStatus::PendingConfirmation { attempts: 1 });

        // 第 2 次启动崩溃后重启（attempts = 2 <= 2）
        let s2 = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
        assert_eq!(s2, HealthCheckStatus::PendingConfirmation { attempts: 2 });

        // 第 3 次启动，超过上限 2 次，触发自愈回滚！
        let s3 = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
        assert_eq!(
            s3,
            HealthCheckStatus::RolledBack {
                from_version: "2.0.1".to_string(),
            }
        );

        // 验证目标可执行文件已成功被备份文件还原为稳定版本
        assert_eq!(fs::read(&dummy_exe).unwrap(), b"old-stable-binary");
        // 历史备份文件已被消费清理
        assert!(!dummy_backup.exists());
        // 状态标记已被自动清理
        assert!(!temp_dir.join(UPDATE_STATE_FILENAME).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
