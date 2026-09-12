//! 历史版本回滚记录持久化管理。
//!
//! 本子模块承载 [`RollbackEntry`] / [`RollbackHistory`] 实体定义，
//! 提供历史版本的登记、查询、淘汰清理以及物理备份存在性校验能力。

use crate::error::{Result, UpdateError};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// 从指定目录加载历史版本记录清单（若文件不存在或反序列化失败则返回空集合）
///
/// # 设计原理
/// - **实现初衷**：为版本历史查询与回滚提供持久化元数据读取能力。
/// - **核心优势**：静默容错降级，文件损坏时不阻塞系统启动。
pub fn load_rollback_history(history_dir: &Path) -> RollbackHistory {
    let history_file = history_dir.join(super::ROLLBACK_HISTORY_FILENAME);
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
    let history_file = history_dir.join(super::ROLLBACK_HISTORY_FILENAME);
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
        super::DEFAULT_MAX_ROLLBACK_ENTRIES
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

/// 在历史清单中定位物理备份仍存在的目标版本条目
///
/// # Errors
/// 当目标版本未登记或备份文件已丢失时返回 [`UpdateError::RollbackVersionNotFound`]。
pub(crate) fn find_existing_rollback_entry(
    history: &RollbackHistory,
    target_version: &Version,
) -> Result<RollbackEntry> {
    history
        .entries
        .iter()
        .find(|e| e.version == *target_version && e.backup_path.exists())
        .cloned()
        .ok_or_else(|| UpdateError::RollbackVersionNotFound(target_version.to_string()))
}

/// 从历史清单中移除指定版本条目（若存在）
pub(crate) fn remove_history_entry(history: &mut RollbackHistory, target_version: &Version) {
    if let Some(idx) = history
        .entries
        .iter()
        .position(|e| e.version == *target_version)
    {
        history.entries.remove(idx);
    }
}
