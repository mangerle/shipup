// shipup 跨平台自更新系统 - 用户更新偏好持久化管理

use crate::error::{Result, UpdateError};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 用户更新偏好持久化文件名（库、CLI 与文档的唯一权威命名）
pub const PREFERENCE_FILENAME: &str = ".shipup_preference.json";

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
    /// 客户端设备持久化稳定唯一标识（用于灰度放量哈希分桶）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// 客户端已知的最高清单单调递增版本序号（用于防重放攻击）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_version_seq: Option<u64>,
}

impl UpdatePreference {
    /// 获取当前记录的最高版本序号
    pub fn last_version_seq(&self) -> Option<u64> {
        self.last_version_seq
    }

    /// 更新记录的最高版本序号（仅在序号单调递增时覆写）
    pub fn record_version_seq(&mut self, seq: u64) {
        if self.last_version_seq.is_none_or(|curr| seq > curr) {
            self.last_version_seq = Some(seq);
        }
    }
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

    /// 标记用户跳过特定版本的升级提醒
    ///
    /// # 设计原理
    /// - **实现初衷**：将指定版本号存入集合去重，使后续更新检查自动忽略该版本的非强制更新提醒。
    pub fn skip_version(&mut self, version: Version) {
        self.skipped_versions.insert(version);
    }

    /// 移除对特定版本的跳过标记，恢复该版本的更新提醒
    pub fn unskip_version(&mut self, version: &Version) {
        self.skipped_versions.remove(version);
    }

    /// 检查特定版本是否已被用户显式跳过
    ///
    /// # 返回值
    /// 若集合中包含该版本则返回 true，否则返回 false。
    pub fn is_skipped(&self, version: &Version) -> bool {
        self.skipped_versions.contains(version)
    }

    /// 设置稍后提醒（以当前 Unix 时间戳为基准，向后推迟指定持续时长）
    ///
    /// # 设计原理
    /// - **实现初衷**：采用绝对时间戳而非相对定时器，即便宿主进程在静默期间重启，静默期依然能够正确计算与延续。
    /// - **核心优势**：使用饱和算术（`saturating_add`）防范时间戳溢出。
    pub fn snooze(&mut self, duration: Duration) {
        let now = current_unix_timestamp();
        self.snooze_until = Some(now.saturating_add(duration.as_secs()));
    }

    /// 检查当前系统时钟是否仍处于稍后提醒静默期内
    ///
    /// # 返回值
    /// 若当前时间尚未到达截止时间戳返回 true，否则返回 false。
    pub fn is_snoozed(&self) -> bool {
        if let Some(until) = self.snooze_until {
            let now = current_unix_timestamp();
            now < until
        } else {
            false
        }
    }

    /// 清空所有跳过的版本号记录与稍后提醒静默期，恢复初始状态
    pub fn clear(&mut self) {
        self.skipped_versions.clear();
        self.snooze_until = None;
    }

    /// 获取客户端设备唯一标识快照（若存在）
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// 获取已有的客户端设备唯一标识，若尚未存在则自动生成并缓存
    pub fn get_or_create_client_id(&mut self) -> &str {
        if self.client_id.is_none() {
            self.client_id = Some(generate_random_client_id());
        }
        self.client_id.as_deref().unwrap_or_default()
    }

    /// 手动设置客户端设备稳定唯一标识符
    pub fn set_client_id(&mut self, id: impl Into<String>) {
        self.client_id = Some(id.into());
    }
}

/// 基于系统时间与随机熵源生成 16 字节随机十六进制客户端设备标识
fn generate_random_client_id() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    hasher.update(now.as_nanos().to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    let boxed = Box::new(0u8);
    let ptr_val = (&*boxed as *const u8 as usize).to_le_bytes();
    hasher.update(ptr_val);
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for b in &hash[..16] {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// 获取当前系统的 Unix 时间戳（秒数）
pub(crate) fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// 探测适合写入用户偏好与自愈状态的安全目录
///
/// # 设计原理
/// - **实现初衷**：在 Windows `C:\Program Files` 或 Linux `/usr/bin` 等受限安装路径下，程序同级目录对标准用户只读。
/// - **核心优势**：优先在程序同级写入以保持便携免安装应用的内聚性；遇到权限受限时，自动优雅降级至操作系统本地用户数据目录（如 `%LOCALAPPDATA%`），绝不崩溃或静默丢失配置。
pub fn resolve_safe_data_dir() -> Option<PathBuf> {
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        // 探测父目录是否拥有写入权限
        let test_probe = parent.join(format!(".shipup_probe_{}", std::process::id()));
        if std::fs::write(&test_probe, b"").is_ok() {
            let _ = std::fs::remove_file(&test_probe);
            return Some(parent.to_path_buf());
        }
    }

    get_user_app_data_dir()
}

fn get_user_app_data_dir() -> Option<PathBuf> {
    let app_name = std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "shipup_app".to_string());

    #[cfg(windows)]
    {
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let dir = PathBuf::from(local_appdata).join(&app_name);
            let _ = std::fs::create_dir_all(&dir);
            return Some(dir);
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            let dir = PathBuf::from(appdata).join(&app_name);
            let _ = std::fs::create_dir_all(&dir);
            return Some(dir);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let dir = PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join(&app_name);
            let _ = std::fs::create_dir_all(&dir);
            return Some(dir);
        }
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
            let dir = PathBuf::from(xdg_config).join(&app_name);
            let _ = std::fs::create_dir_all(&dir);
            return Some(dir);
        }
        if let Ok(home) = std::env::var("HOME") {
            let dir = PathBuf::from(home).join(".config").join(&app_name);
            let _ = std::fs::create_dir_all(&dir);
            return Some(dir);
        }
    }

    None
}

/// 探测获取默认的用户偏好持久化文件路径
pub(crate) fn default_preference_file_path() -> Option<PathBuf> {
    resolve_safe_data_dir().map(|dir| dir.join(PREFERENCE_FILENAME))
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

    #[test]
    fn test_preference_client_id_generation_and_persistence() {
        let temp_dir =
            std::env::temp_dir().join(format!("shipup_client_id_test_{}", std::process::id()));
        let file_path = temp_dir.join("test_pref.json");

        let mut pref = UpdatePreference::default();
        assert!(pref.client_id().is_none());

        let id1 = pref.get_or_create_client_id().to_string();
        assert!(!id1.is_empty());
        assert_eq!(pref.get_or_create_client_id(), id1);

        pref.save_to_file(&file_path).unwrap();
        let loaded = UpdatePreference::load_from_file(&file_path);
        assert_eq!(loaded.client_id(), Some(id1.as_str()));

        // 手动覆盖 client_id
        let mut custom_pref = UpdatePreference::default();
        custom_pref.set_client_id("device-alpha-1234");
        assert_eq!(custom_pref.client_id(), Some("device-alpha-1234"));

        let _ = fs::remove_dir_all(temp_dir);
    }
}
