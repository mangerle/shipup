// shipup 跨平台自更新系统 - 版本自愈与启动健康自检恢复引擎

use crate::error::{Result, UpdateError};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// 更新过程状态持久化文件名
pub const UPDATE_STATE_FILENAME: &str = ".shipup.state";

/// 历史版本回滚记录文件名
pub const ROLLBACK_HISTORY_FILENAME: &str = ".shipup.history";

/// 默认保留的最大历史版本记录数
pub const DEFAULT_MAX_ROLLBACK_ENTRIES: usize = 3;

/// 默认容忍的最大崩溃启动尝试次数
pub const DEFAULT_MAX_CRASH_ATTEMPTS: u32 = 2;

/// 启动崩溃判定时间窗口（秒），两次启动间隔超过此窗口即视为上次已平稳运行
pub const CRASH_WINDOW_THRESHOLD_SECS: u64 = 30;

/// 历史回滚版本记录条目
///
/// # 设计原理
/// - **实现初衷**：持久化记录历史版本号与对应的物理备份文件路径，使系统具备确定性的主动回滚与版本追溯能力。
/// - **核心优势**：记录版本元数据与时间戳，支持按版本号精确回滚和基于时间倒序的回溯。
/// - **代价与局限**：需要在程序运行根目录拥有文件创建与读写权限。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEntry {
    /// 备份对应的旧版本号
    pub version: Version,
    /// 历史版本备份文件物理路径
    pub backup_path: PathBuf,
    /// 备份创建时的 Unix 毫秒时间戳
    pub backed_up_at: u64,
}

/// 历史版本回滚持久化记录清单
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackHistory {
    /// 历史备份条目列表（按备份时间倒序，最新备份在前）
    pub entries: Vec<RollbackEntry>,
}

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

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Some(last_at) = state.last_attempt_at {
        let elapsed = now_secs.saturating_sub(last_at);
        if elapsed >= CRASH_WINDOW_THRESHOLD_SECS {
            log::info!(
                "新版本距上次启动已平稳度过健康观察期 ({} 秒 >= {} 秒)，自动完成升级确认",
                elapsed,
                CRASH_WINDOW_THRESHOLD_SECS
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

        if state.backup_path.is_dir() {
            if current_exe.exists() {
                let _ = fs::remove_dir_all(current_exe);
            }
            if let Err(e) = fs::rename(&state.backup_path, current_exe) {
                return Err(UpdateError::SelfReplace(format!(
                    "还原历史 Bundle 备份失败: {}",
                    e
                )));
            }
        } else {
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
        }
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
        if is_in_rollback_history(state_dir, &state.backup_path) {
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
        return dir.join(UPDATE_STATE_FILENAME).exists();
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

/// 执行当前可执行文件同级目录的自检与自愈恢复（推荐在应用入口 main 首行调用）
///
/// # 设计原理
/// - **实现初衷**：在宿主加载任何重量级依赖或动态库之前前置介入自检，保证在程序因缺失新 DLL 导致崩溃时仍能被捕获。
///
/// # Errors
/// 当回滚覆盖底层失败时返回 [`UpdateError::SelfReplace`]。
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

/// 从指定目录加载历史版本记录清单（若文件不存在或反序列化失败则返回空集合）
///
/// # 设计原理
/// - **实现初衷**：为版本历史查询与回滚提供持久化元数据读取能力。
/// - **核心优势**：静默容错降级，文件损坏时不阻塞系统启动。
pub fn load_rollback_history(history_dir: &Path) -> RollbackHistory {
    let history_file = history_dir.join(ROLLBACK_HISTORY_FILENAME);
    if !history_file.exists() {
        return RollbackHistory::default();
    }
    match fs::read_to_string(&history_file) {
        Ok(content) => serde_json::from_str::<RollbackHistory>(&content).unwrap_or_default(),
        Err(e) => {
            log::warn!("读取历史版本记录文件失败: {}", e);
            RollbackHistory::default()
        }
    }
}

/// 将历史版本记录清单持久化保存至指定目录
///
/// # Errors
/// 当序列化失败或写入文件出错时返回 [`UpdateError`]。
pub fn save_rollback_history(history_dir: &Path, history: &RollbackHistory) -> Result<()> {
    let history_file = history_dir.join(ROLLBACK_HISTORY_FILENAME);
    let json = serde_json::to_string_pretty(history)
        .map_err(|e| UpdateError::ManifestParse(format!("序列化历史版本记录失败: {}", e)))?;
    fs::write(&history_file, json)?;
    Ok(())
}

/// 判断指定物理路径是否被登记在版本历史记录中
///
/// # 设计原理
/// - **实现初衷**：在确认更新成功时区分临时自愈备份与历史版本备份，防止误删历史归档。
pub fn is_in_rollback_history(history_dir: &Path, backup_path: &Path) -> bool {
    let history = load_rollback_history(history_dir);
    history.entries.iter().any(|entry| {
        match (entry.backup_path.canonicalize(), backup_path.canonicalize()) {
            (Ok(p1), Ok(p2)) => p1 == p2,
            _ => entry.backup_path == backup_path,
        }
    })
}

/// 在指定目录登记一条新的历史回滚版本，并清理超出保留上限的最旧备份文件
///
/// # 设计原理
/// - **实现初衷**：在更新替换时自动将旧版本纳入版本历史，自动轮转清理超出上限的最旧文件。
/// - **核心优势**：自动过滤物理已丢失的孤儿记录，确保历史清单与物理磁盘严格同步。
///
/// # Errors
/// 当持久化历史清单失败时返回 [`UpdateError`]。
pub fn record_rollback_version(
    history_dir: &Path,
    version: &Version,
    backup_path: &Path,
    max_entries: usize,
) -> Result<()> {
    let mut history = load_rollback_history(history_dir);
    history.entries.retain(|e| e.backup_path.exists());

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let new_entry = RollbackEntry {
        version: version.clone(),
        backup_path: backup_path.to_path_buf(),
        backed_up_at: now_ms,
    };

    history.entries.retain(|e| e.version != *version);
    history.entries.insert(0, new_entry);

    let capacity = if max_entries == 0 {
        DEFAULT_MAX_ROLLBACK_ENTRIES
    } else {
        max_entries
    };

    while history.entries.len() > capacity {
        if let Some(removed) = history.entries.pop()
            && removed.backup_path.exists()
        {
            if removed.backup_path.is_dir() {
                let _ = fs::remove_dir_all(&removed.backup_path);
            } else {
                let _ = fs::remove_file(&removed.backup_path);
            }
            log::info!(
                "已自动淘汰并清理超出上限的最旧版本备份: {} (版本: {})",
                removed.backup_path.display(),
                removed.version
            );
        }
    }

    save_rollback_history(history_dir, &history)?;
    log::info!(
        "已成功登记历史版本回滚条目: 版本 {}, 备份路径: {}",
        version,
        backup_path.display()
    );
    Ok(())
}

/// 查询当前所有物理文件依然存在的可用回滚版本列表（按时间倒序排列，最新在最前）
pub fn list_available_rollback_versions(history_dir: &Path) -> Vec<Version> {
    let history = load_rollback_history(history_dir);
    history
        .entries
        .into_iter()
        .filter(|e| e.backup_path.exists())
        .map(|e| e.version)
        .collect()
}

/// 执行主动回滚至指定的历史版本
///
/// # 设计原理
/// - **实现初衷**：使宿主程序具备主动指定历史版本并一键恢复的能力，突破原有“被动崩溃 3 次才回滚”的局限。
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

    let entry_pos = history
        .entries
        .iter()
        .position(|e| e.version == *target_version && e.backup_path.exists());

    let entry = match entry_pos {
        Some(idx) => history.entries[idx].clone(),
        None => {
            return Err(UpdateError::RollbackVersionNotFound(
                target_version.to_string(),
            ));
        }
    };

    log::warn!(
        "正在执行主动回滚: 目标历史版本 {}, 备份文件: {} -> 目标程序: {}",
        target_version,
        entry.backup_path.display(),
        current_exe.display()
    );

    if entry.backup_path.is_dir() {
        if current_exe.exists() {
            let _ = fs::remove_dir_all(current_exe);
        }
        if let Err(e) = fs::rename(&entry.backup_path, current_exe) {
            return Err(UpdateError::SelfReplace(format!(
                "还原历史 Bundle 备份失败: {}",
                e
            )));
        }
    } else {
        let is_running_exe = env::current_exe()
            .map(
                |running| match (running.canonicalize(), current_exe.canonicalize()) {
                    (Ok(p1), Ok(p2)) => p1 == p2,
                    _ => running == current_exe,
                },
            )
            .unwrap_or(false);

        if is_running_exe {
            if let Err(e) = self_replace::self_replace(&entry.backup_path) {
                return Err(UpdateError::SelfReplace(format!(
                    "执行主动版本回滚失败: {}",
                    e
                )));
            }
        } else {
            if current_exe.exists() {
                let _ = fs::remove_file(current_exe);
            }
            if let Err(e) = fs::copy(&entry.backup_path, current_exe) {
                return Err(UpdateError::SelfReplace(format!(
                    "还原备份文件到目标可执行文件失败: {}",
                    e
                )));
            }
        }
        let _ = fs::remove_file(&entry.backup_path);
    }

    if let Some(idx) = history
        .entries
        .iter()
        .position(|e| e.version == *target_version)
    {
        history.entries.remove(idx);
    }
    let _ = save_rollback_history(history_dir, &history);

    let state_file = history_dir.join(UPDATE_STATE_FILENAME);
    if state_file.exists() {
        let _ = fs::remove_file(&state_file);
    }

    log::info!("主动回滚至历史版本 {} 执行成功", target_version);
    Ok(())
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

    #[test]
    fn test_healthy_interval_clears_recovery_state() {
        let temp_dir = env::temp_dir().join(format!("shipup_healthy_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let dummy_backup = temp_dir.join("app.shipup.old");
        fs::write(&dummy_backup, b"old-binary").unwrap();
        let dummy_exe = temp_dir.join("app.exe");
        fs::write(&dummy_exe, b"new-binary").unwrap();

        let state_file = temp_dir.join(UPDATE_STATE_FILENAME);
        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(60); // 模拟 60 秒前启动过

        let state = UpdateState {
            target_version: "2.1.0".to_string(),
            backup_path: dummy_backup.clone(),
            updated_at: past_time * 1000,
            launch_attempts: 1,
            last_attempt_at: Some(past_time),
        };
        fs::write(&state_file, serde_json::to_string(&state).unwrap()).unwrap();

        // 执行检查：由于距上次启动已过去 60 秒（>= 30 秒阈值），判定平稳运行，自动确认成功
        let status = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
        assert_eq!(status, HealthCheckStatus::Normal);

        // 状态标记与历史备份均被自动清理
        assert!(!state_file.exists());
        assert!(!dummy_backup.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_record_rollback_history_and_prune() {
        let temp_dir = env::temp_dir().join(format!("shipup_hist_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let v1_backup = temp_dir.join("app.shipup.1.0.0.old");
        let v2_backup = temp_dir.join("app.shipup.1.1.0.old");
        let v3_backup = temp_dir.join("app.shipup.1.2.0.old");
        fs::write(&v1_backup, b"v1-binary").unwrap();
        fs::write(&v2_backup, b"v2-binary").unwrap();
        fs::write(&v3_backup, b"v3-binary").unwrap();

        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("1.1.0").unwrap();
        let v3 = Version::parse("1.2.0").unwrap();

        // 容量限制为 2
        record_rollback_version(&temp_dir, &v1, &v1_backup, 2).unwrap();
        record_rollback_version(&temp_dir, &v2, &v2_backup, 2).unwrap();

        let available = list_available_rollback_versions(&temp_dir);
        assert_eq!(available, vec![v2.clone(), v1.clone()]);
        assert!(v1_backup.exists());
        assert!(v2_backup.exists());

        // 插入第 3 个版本，应自动淘汰最古老的 v1
        record_rollback_version(&temp_dir, &v3, &v3_backup, 2).unwrap();
        let available2 = list_available_rollback_versions(&temp_dir);
        assert_eq!(available2, vec![v3.clone(), v2.clone()]);

        // 最旧的 v1 物理文件已被自动淘汰清理
        assert!(!v1_backup.exists());
        assert!(v2_backup.exists());
        assert!(v3_backup.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_manual_rollback_to_specific_version() {
        let temp_dir = env::temp_dir().join(format!("shipup_manual_rb_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let v1_backup = temp_dir.join("app.shipup.1.0.0.old");
        let current_exe = temp_dir.join("app.exe");
        fs::write(&v1_backup, b"v1-stable-code").unwrap();
        fs::write(&current_exe, b"v2-broken-code").unwrap();

        let v1 = Version::parse("1.0.0").unwrap();
        record_rollback_version(&temp_dir, &v1, &v1_backup, 2).unwrap();

        // 模拟当前存在自愈状态
        record_update_state(&temp_dir, "2.0.0", &v1_backup).unwrap();
        assert!(temp_dir.join(UPDATE_STATE_FILENAME).exists());

        // 执行主动回滚至 1.0.0
        execute_manual_rollback_to(&temp_dir, &current_exe, &v1).unwrap();

        // 验证当前二进制已被成功还原为 v1
        assert_eq!(fs::read(&current_exe).unwrap(), b"v1-stable-code");
        // 验证自愈状态标记已被安全清除
        assert!(!temp_dir.join(UPDATE_STATE_FILENAME).exists());
        // 验证可用历史中已无该条目
        let available = list_available_rollback_versions(&temp_dir);
        assert!(available.is_empty());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_manual_rollback_version_not_found() {
        let temp_dir = env::temp_dir().join(format!("shipup_rb_nf_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let current_exe = temp_dir.join("app.exe");
        fs::write(&current_exe, b"current-code").unwrap();

        let non_existent = Version::parse("9.9.9").unwrap();
        let result = execute_manual_rollback_to(&temp_dir, &current_exe, &non_existent);
        assert!(result.is_err());
        match result {
            Err(UpdateError::RollbackVersionNotFound(v)) => {
                assert_eq!(v, "9.9.9");
            }
            other => panic!("预期 RollbackVersionNotFound，但获得 {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_confirm_update_keeps_registered_history() {
        let temp_dir = env::temp_dir().join(format!("shipup_keep_hist_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let dummy_backup = temp_dir.join("app.shipup.1.0.0.old");
        fs::write(&dummy_backup, b"old-binary").unwrap();
        let v1 = Version::parse("1.0.0").unwrap();

        // 登记入版本历史并记录更新状态
        record_rollback_version(&temp_dir, &v1, &dummy_backup, 2).unwrap();
        record_update_state(&temp_dir, "2.0.0", &dummy_backup).unwrap();

        // 确认升级成功
        let confirmed = confirm_update_success_in_dir(&temp_dir).unwrap();
        assert!(confirmed);
        // 状态标记已被清理
        assert!(!temp_dir.join(UPDATE_STATE_FILENAME).exists());
        // 物理备份因登记在版本历史中而被妥善保留供后续手动回滚！
        assert!(dummy_backup.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
