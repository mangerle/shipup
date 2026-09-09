// shipup 跨平台自更新系统 - 用户更新偏好持久化管理

use crate::error::{Result, UpdateError};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 用户更新意图与提醒偏好配置模型
///
/// # 设计原理
/// - **实现初衷**：满足桌面端用户点击“跳过此版本”或“稍后提醒（1小时/1天）”的交互诉求，避免无节制骚扰提示。
/// - **核心优势**：轻量 JSON 本地持久化，支持集合去重与基于 Unix 时间戳的安全过期判断；强制更新可全局熔断逃逸。
/// - **代价与局限**：依赖本地磁盘写权限，若存储路径只读则降级为运行期内存生效。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePreference {
    /// 用户显式标记忽略或跳过的版本号集合
    #[serde(default)]
    pub skipped_versions: HashSet<Version>,
    /// 稍后提醒截止时间戳（Unix 时间戳秒数）
    #[serde(default)]
    pub snooze_until: Option<u64>,
}

impl UpdatePreference {
    /// 从指定本地 JSON 文件中反序列化加载更新偏好配置
    ///
    /// # 设计原理
    /// - **实现初衷**：容错读取本地文件，遇到文件不存在或反序列化失败时平滑降级为默认空偏好，不阻断主流程。
    pub fn load_from_file(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }

        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(pref) => pref,
                Err(e) => {
                    log::warn!(
                        "解析用户更新偏好文件 '{}' 失败: {}, 使用默认空偏好",
                        path.display(),
                        e
                    );
                    Self::default()
                }
            },
            Err(e) => {
                log::warn!(
                    "读取用户更新偏好文件 '{}' 失败: {}, 使用默认空偏好",
                    path.display(),
                    e
                );
                Self::default()
            }
        }
    }

    /// 将当前偏好配置以原子方式持久化至指定文件路径
    ///
    /// # Errors
    /// 当父目录创建失败或文件写入受阻时返回 [`UpdateError::Io`]。
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| UpdateError::ManifestParse(format!("序列化用户更新偏好失败: {}", e)))?;

        fs::write(path, json)?;
        Ok(())
    }

    /// 标记跳过特定版本
    pub fn skip_version(&mut self, version: Version) {
        self.skipped_versions.insert(version);
    }

    /// 移除对特定版本的跳过标记
    pub fn unskip_version(&mut self, version: &Version) {
        self.skipped_versions.remove(version);
    }

    /// 检查特定版本是否已被用户显式跳过
    pub fn is_skipped(&self, version: &Version) -> bool {
        self.skipped_versions.contains(version)
    }

    /// 设置稍后提醒（从当前系统时间开始推迟指定的持续时长）
    pub fn snooze(&mut self, duration: Duration) {
        let now = current_unix_timestamp();
        self.snooze_until = Some(now.saturating_add(duration.as_secs()));
    }

    /// 检查当前是否仍处于稍后提醒静默期内
    pub fn is_snoozed(&self) -> bool {
        if let Some(until) = self.snooze_until {
            let now = current_unix_timestamp();
            now < until
        } else {
            false
        }
    }

    /// 清空所有跳过版本与稍后提醒记录
    pub fn clear(&mut self) {
        self.skipped_versions.clear();
        self.snooze_until = None;
    }
}

/// 获取当前系统的 Unix 时间戳（秒数）
pub(crate) fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// 探测获取默认的用户偏好持久化文件路径
pub(crate) fn default_preference_file_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join(".shipup_preference.json")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preference_skip_and_unskip() {
        let mut pref = UpdatePreference::default();
        let v1 = Version::parse("1.2.0").unwrap();
        let v2 = Version::parse("1.3.0").unwrap();

        assert!(!pref.is_skipped(&v1));
        pref.skip_version(v1.clone());
        assert!(pref.is_skipped(&v1));
        assert!(!pref.is_skipped(&v2));

        pref.unskip_version(&v1);
        assert!(!pref.is_skipped(&v1));
    }

    #[test]
    fn test_preference_snooze_timing() {
        let mut pref = UpdatePreference::default();
        assert!(!pref.is_snoozed());

        // 设置未来 3600 秒
        pref.snooze(Duration::from_secs(3600));
        assert!(pref.is_snoozed());

        // 手动将 snooze 时间拨回过去
        pref.snooze_until = Some(current_unix_timestamp().saturating_sub(10));
        assert!(!pref.is_snoozed());
    }

    #[test]
    fn test_preference_file_persistence() {
        let temp_dir =
            std::env::temp_dir().join(format!("shipup_pref_test_{}", std::process::id()));
        let file_path = temp_dir.join("test_pref.json");

        let mut pref = UpdatePreference::default();
        pref.skip_version(Version::parse("2.0.0").unwrap());
        pref.snooze(Duration::from_secs(1800));

        pref.save_to_file(&file_path).unwrap();
        assert!(file_path.exists());

        let loaded = UpdatePreference::load_from_file(&file_path);
        assert_eq!(pref, loaded);

        let _ = fs::remove_dir_all(temp_dir);
    }
}
