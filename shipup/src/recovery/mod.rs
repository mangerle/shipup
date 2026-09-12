//! 版本自愈与启动健康自检恢复引擎模块。
//!
//! # 模块职责
//! 维护更新状态与回滚历史两套持久化记录，并据此提供：
//! - 启动健康自检：[`check_and_recover`] 系列在启动阶段累加崩溃计数并判定是否需要回滚；
//! - 升级确认闭环：[`confirm_update_success`] 系列在程序平稳运行后清除观察期标记；
//! - 主动回滚：列出可用历史版本并执行降级替换。
//!
//! # 设计原理
//! - **实现初衷**：新版本「能装上」不等于「能跑起来」。若缺少启动自检，
//!   一个必然崩溃的新版本会把用户永久锁死在无法启动的状态，且不提供任何自救路径。
//! - **核心优势**：
//!   - 采用「观察期 + 崩溃窗口」双约束：必须在限定时间窗口内连续多次启动失败才触发回滚，
//!     避免用户手动反复重启被误判为崩溃循环；
//!   - 回滚前会校验物理备份文件是否仍然存在，自动过滤掉文件已丢失的孤儿记录；
//!   - 主动回滚与被动自愈共用同一套执行路径，保证两条入口行为一致。
//! - **代价与局限**：需要保留历史可执行文件副本，占用与主程序体积相当的额外磁盘空间；
//!   保留数量由 `max_rollback_entries` 约束并自动淘汰最旧条目。
//!
//! # 状态机
//! 正常 → 更新后进入观察期 → （确认成功）正常 / （窗口内连续崩溃超阈值）回滚并回归正常。
//!
//! # 子模块划分
//! - [`state`]：[`UpdateState`] 结构定义、状态文件读写与升级确认闭环；
//! - [`health`]：启动健康自检链路，含崩溃窗口判定与自愈回滚触发；
//! - [`history`]：[`RollbackEntry`] / [`RollbackHistory`] 持久化读写与版本登记淘汰；
//! - [`manual`]：主动指定历史版本执行回滚。

mod health;
mod history;
mod manual;
mod state;

#[cfg(test)]
mod tests;

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

pub use health::{HealthCheckStatus, check_and_recover_current, check_and_recover_once};
pub use history::{
    RollbackEntry, RollbackHistory, list_available_rollback_versions, load_rollback_history,
    record_rollback_version,
};
pub use manual::execute_manual_rollback_to;
pub use state::{
    confirm_update_success, confirm_update_success_in_dir, has_pending_recovery_state,
    record_update_state,
};
