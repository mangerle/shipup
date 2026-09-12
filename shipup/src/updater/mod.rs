//! 更新器总控门面模块。
//!
//! # 模块职责
//! 定义自更新系统对外的两个顶层实体：
//! - [`Updater`]：只读的更新引擎门面，持有版本基准、端点列表、通道与安全策略，对外提供
//!   更新检查、用户偏好管理（跳过版本 / 稍后提醒）、历史回滚与后台轮询派生能力；
//! - [`UpdaterInner`]：`Updater` 的内部共享状态，被 `Arc` 包裹以实现廉价 `Clone`。
//!
//! # 设计原理
//! - **实现初衷**：把「检查」与「安装」两类职责拆到兄弟子模块
//!   （[`check`] 与 [`release`] / [`install`]），本模块只保留状态定义与轻量访问器，
//!   避免单一文件膨胀为难以审查的「上帝模块」。
//! - **核心优势**：`Updater` 本身无状态可变字段，全部策略在构建期固化。
//!   默认构造不做任何磁盘写入，仅静默清理 Windows 历史锁残留，可在宿主启动阶段安全调用。
//! - **代价与局限**：实例构建完成后不可动态更换目标端点、通道或验签模式；
//!   需要不同策略时须重新构建实例。
//!
//! # 兄弟模块导航
//! - [`config`]：网络传输与数字签名安全配置实体；
//! - [`http`]：同步/异步 HTTP 客户端构建与清单拉取；
//! - [`check`]：更新检查、版本评估与灰度放量裁决；
//! - [`release`]：已确认更新实体的下载与验签；
//! - [`install`]：更新包物理落盘、备份与安装器派生。

#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

use crate::builder::{UpdaterBuilder, UpdaterConfig, VersionComparator};
use crate::error::{Result, UpdateError};
use crate::manifest::Manifest;
use crate::platform::cleanup_old_backups;
use crate::preference::{self, UpdatePreference};
use crate::provider::ReleaseProvider;
use semver::Version;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) mod check;
pub(crate) mod config;
pub(crate) mod http;
pub(crate) mod install;
pub(crate) mod release;

pub(crate) use config::NetworkSecurityConfig;
pub use release::{DownloadedUpdate, Update};

/// 更新器内部共享核心状态实体
struct UpdaterInner {
    current_version: Version,
    endpoints: Vec<String>,
    provider: Option<Arc<dyn ReleaseProvider>>,
    channel: Option<String>,
    target: String,
    allow_downgrade: bool,
    config: Arc<NetworkSecurityConfig>,
    version_comparator: Option<VersionComparator>,
    preference: Mutex<UpdatePreference>,
    preference_path: Option<PathBuf>,
    fallback_manifest: Option<Manifest>,
}

impl std::fmt::Debug for UpdaterInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdaterInner")
            .field("current_version", &self.current_version)
            .field("endpoints", &self.endpoints)
            .field("has_provider", &self.provider.is_some())
            .field("channel", &self.channel)
            .field("target", &self.target)
            .field("allow_downgrade", &self.allow_downgrade)
            .field("config", &self.config)
            .field(
                "has_custom_version_comparator",
                &self.version_comparator.is_some(),
            )
            .field("preference_path", &self.preference_path)
            .field("has_fallback_manifest", &self.fallback_manifest.is_some())
            .finish()
    }
}

/// 客户端更新器统一生命周期管理器
///
/// # 设计原理
/// - **实现初衷**：作为更新引擎对外的总控门面，统一封装元数据检测、多端点故障转移、版本比较裁决与用户更新偏好。
/// - **核心优势**：
///   - 状态轻量且通过 `Arc` 内部共享，实现廉价 `Clone`，可安全在多线程与异步任务间传递。
///   - 默认构造时保持纯净无副作用，仅静默清理 Windows 历史锁残留，不产生多余磁盘写入。
/// - **代价与局限**：实例不可变借用，更新策略在构建完成后固定，无法动态修改目标端点或验签模式。
#[derive(Debug, Clone)]
pub struct Updater {
    inner: Arc<UpdaterInner>,
}

impl Updater {
    /// 获取 UpdaterBuilder 构建器入口
    ///
    /// 提供流式、强类型的链式配置接口，用于逐步设定版本、端点、公钥及策略。
    pub fn builder() -> UpdaterBuilder {
        UpdaterBuilder::new()
    }

    /// 获取当前配置的全部更新检查端点列表切片
    pub fn endpoints(&self) -> &[String] {
        &self.inner.endpoints
    }

    /// 获取当前配置的动态发布源提供者（若未配置则返回 None）
    pub fn provider(&self) -> Option<&Arc<dyn ReleaseProvider>> {
        self.inner.provider.as_ref()
    }

    /// 获取当前配置的内嵌 Fallback Manifest 兜底清单只读引用（若未配置则返回 None）
    pub fn fallback_manifest(&self) -> Option<&Manifest> {
        self.inner.fallback_manifest.as_ref()
    }

    /// 获取当前客户端设备稳定唯一标识符（字符串副本）
    pub fn client_id(&self) -> String {
        let pref = self
            .inner
            .preference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pref.client_id().unwrap_or_default().to_string()
    }

    /// 标记跳过特定版本升级提醒并持久化到磁盘
    ///
    /// # 设计原理
    /// - **实现初衷**：响应用户在界面上点击“跳过此版本”的交互诉求，后续检查版本时将自动忽略该版本。
    /// - **核心优势**：内存状态即刻生效并同步原子写入磁盘，进程重启后偏好依然生效；强制更新（mandatory）可自动绕过此限制。
    ///
    /// # Errors
    /// 当磁盘写权限不足或偏好文件序列化失败时，返回 [`UpdateError::Io`]。
    pub fn skip_version(&self, version: Version) -> Result<()> {
        let mut pref = self
            .inner
            .preference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pref.skip_version(version);
        if let Some(ref path) = self.inner.preference_path {
            pref.save_to_file(path)?;
        }
        Ok(())
    }

    /// 撤销对特定版本的跳过标记并持久化到磁盘
    ///
    /// # 设计原理
    /// - **实现初衷**：允许用户在设置中心重置或恢复特定版本的升级提醒。
    ///
    /// # Errors
    /// 当偏好文件写入磁盘受阻时返回对应底层错误。
    pub fn unskip_version(&self, version: &Version) -> Result<()> {
        let mut pref = self
            .inner
            .preference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pref.unskip_version(version);
        if let Some(ref path) = self.inner.preference_path {
            pref.save_to_file(path)?;
        }
        Ok(())
    }

    /// 设置稍后提醒静默期并持久化到磁盘
    ///
    /// # 设计原理
    /// - **实现初衷**：响应用户“稍后提醒（如 1 小时或 1 天后）”诉求，在此期间内忽略所有非强制更新弹窗。
    /// - **核心优势**：基于绝对 Unix 时间戳计算截止时间，不受系统短暂停机影响；过期后自动恢复提醒。
    ///
    /// # 参数
    /// * `duration`: 静默持续时长
    ///
    /// # Errors
    /// 当偏好文件写入磁盘失败时返回错误。
    pub fn snooze(&self, duration: Duration) -> Result<()> {
        let mut pref = self
            .inner
            .preference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pref.snooze(duration);
        if let Some(ref path) = self.inner.preference_path {
            pref.save_to_file(path)?;
        }
        Ok(())
    }

    /// 清空所有用户偏好（包括所有已跳过版本与稍后提醒记录）并持久化
    ///
    /// # Errors
    /// 当偏好文件写入磁盘失败时返回错误。
    pub fn clear_preferences(&self) -> Result<()> {
        let mut pref = self
            .inner
            .preference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pref.clear();
        if let Some(ref path) = self.inner.preference_path {
            pref.save_to_file(path)?;
        }
        Ok(())
    }

    /// 获取当前用户偏好配置的只读快照副本
    pub fn preferences(&self) -> UpdatePreference {
        self.inner
            .preference
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// 解析更新状态与历史记录存放目录
    fn resolve_state_dir(&self) -> PathBuf {
        crate::preference::resolve_safe_data_dir().unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                .unwrap_or_else(|| PathBuf::from("."))
        })
    }

    /// 获取当前所有物理备份依然存在的可用回滚历史版本列表（按时间倒序排列，最新备份在前）
    ///
    /// # 设计原理
    /// - **实现初衷**：向宿主 UI 或控制台暴露历史上可用于安全降级回滚的稳定版本清单。
    /// - **核心优势**：自动过滤物理文件已丢失的孤儿记录，确保返回的版本均可被成功执行回滚。
    pub fn available_rollback_versions(&self) -> Vec<Version> {
        let state_dir = self.resolve_state_dir();
        crate::recovery::list_available_rollback_versions(&state_dir)
    }

    /// 主动回滚至指定的历史版本
    ///
    /// # 设计原理
    /// - **实现初衷**：将原本“只能依赖连续崩溃超阈值被动自愈”的回滚机制升级为宿主可主动触发的确定性运维能力。
    /// - **核心优势**：校验物理文件完整性，兼容当前运行二进制自替换与外部托管沙箱，回滚完成后自动解除自愈观察期标记。
    ///
    /// # Errors
    /// 当目标版本在历史中不存在、物理备份文件已丢失或执行文件原子替换失败时返回 [`UpdateError`]。
    pub fn rollback_to(&self, target_version: &Version) -> Result<()> {
        let state_dir = self.resolve_state_dir();
        let current_exe = std::env::current_exe()?;
        crate::recovery::execute_manual_rollback_to(&state_dir, &current_exe, target_version)
    }

    /// 主动回滚至最近的一个历史备份版本
    ///
    /// # 设计原理
    /// - **实现初衷**：提供一键回退到“上一个可用版本”的极简接口，常用于用户在设置中点击“回滚上个版本”按钮。
    /// - **核心优势**：自动获取时间戳最新的可用历史版本执行回滚，无须调用方手动查找比对版本号。
    ///
    /// # Errors
    /// 当系统无任何可用的历史备份或物理替换执行失败时返回 [`UpdateError`]。
    pub fn rollback_to_previous(&self) -> Result<Version> {
        let versions = self.available_rollback_versions();
        let target = versions.first().ok_or_else(|| {
            UpdateError::RollbackVersionNotFound(
                "当前系统未检测到任何可用的历史回滚版本".to_string(),
            )
        })?;
        let version_cloned = target.clone();
        self.rollback_to(&version_cloned)?;
        Ok(version_cloned)
    }

    /// 由 [`UpdaterBuilder::build`] 内部调用，完成配置固化与偏好文件装载。
    ///
    /// 本构造器刻意保持「近乎无副作用」：仅在确实没有待确认的更新状态时清理历史备份残留，
    /// 并且只有在显式开启 `auto_recover_on_init` 时才执行一次启动自愈检查，
    /// 以免宿主多次构建实例（例如测试或插件热加载）导致崩溃计数被反复累加而误触发回滚。
    pub(crate) fn new(config: UpdaterConfig) -> Self {
        if config.auto_recover_on_init {
            // 仅在显式声明时执行单次启动自愈检查，防止多实例重复自增计数误触发回滚
            if let Ok(status) =
                crate::recovery::check_and_recover_once(crate::recovery::DEFAULT_MAX_CRASH_ATTEMPTS)
            {
                match status {
                    crate::recovery::HealthCheckStatus::RolledBack { from_version } => {
                        log::warn!(
                            "检测到新版本 ({}) 启动多次异常崩溃，已触发自愈并回滚至历史正常版本",
                            from_version
                        );
                    }
                    crate::recovery::HealthCheckStatus::PendingConfirmation { attempts } => {
                        log::info!("当前版本处于更新健康确认观察期，启动计数: {}", attempts);
                    }
                    crate::recovery::HealthCheckStatus::Normal => {
                        cleanup_old_backups();
                    }
                }
            } else if !crate::recovery::has_pending_recovery_state() {
                cleanup_old_backups();
            }
        } else if !crate::recovery::has_pending_recovery_state() {
            // 默认构造器保持纯净无副作用，仅在无未确认更新状态时清理历史残留旧副本
            cleanup_old_backups();
        }

        let preference_path = config
            .preference_path
            .or_else(preference::default_preference_file_path);
        let mut preference = if let Some(ref path) = preference_path {
            UpdatePreference::load_from_file(path)
        } else {
            UpdatePreference::default()
        };

        if let Some(custom_id) = config.client_id {
            preference.set_client_id(custom_id);
        } else {
            let _ = preference.get_or_create_client_id();
        }

        if let Some(ref path) = preference_path {
            let _ = preference.save_to_file(path);
        }

        Self {
            inner: Arc::new(UpdaterInner {
                current_version: config.current_version,
                endpoints: config.endpoints,
                provider: config.provider,
                channel: config.channel,
                target: config.target,
                allow_downgrade: config.allow_downgrade,
                config: Arc::new(NetworkSecurityConfig {
                    public_keys: config.public_keys,
                    timeout: config.timeout,
                    user_agent: config.user_agent,
                    headers: config.headers,
                    proxy: config.proxy,
                    max_retries: config.max_retries,
                    retry_delay: config.retry_delay,
                    dangerous_insecure_transport_protocol: config
                        .dangerous_insecure_transport_protocol,
                    require_signature: config.require_signature,
                    max_bytes_per_sec: config.max_bytes_per_sec,
                    allow_file_protocol: config.allow_file_protocol,
                    allow_reboot_deferred_replace: config.allow_reboot_deferred_replace,
                    max_rollback_entries: config.max_rollback_entries,
                    root_certificates_pem: config.root_certificates_pem,
                    signature_threshold: config.signature_threshold,
                    endpoint_racing: config.endpoint_racing,
                    stagger_delay: config.stagger_delay,
                    chunked_download: config.chunked_download,
                    chunked_concurrency: config.chunked_concurrency,
                    chunk_size: config.chunk_size,
                    download_mirrors: config.download_mirrors,
                    resumable_download: config.resumable_download,
                }),
                version_comparator: config.version_comparator,
                preference: Mutex::new(preference),
                preference_path,
                fallback_manifest: config.fallback_manifest,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PackageInfo, PackageType, ResolvedRelease};
    use crate::updater::check::compute_rollout_bucket;
    use std::collections::HashMap;
    use std::fs;

    #[cfg(feature = "async")]
    use crate::updater::http::build_async_http_client;
    #[cfg(feature = "blocking")]
    use crate::updater::http::build_blocking_http_client;

    #[test]
    fn test_custom_version_comparator() {
        let manifest_json = r#"{
            "version": "1.0.1",
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-1.0.1.zip",
                    "package_type": "archive",
                    "checksum": "sha256:abc"
                }
            }
        }"#;

        // 默认情况下 1.0.0 -> 1.0.1 会检测到更新
        let updater_default = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .manifest_url("https://example.com/manifest.json")
            .require_signature(false)
            .build()
            .unwrap();
        let res = updater_default.evaluate_manifest(manifest_json).unwrap();
        assert!(res.is_some());

        // 使用自定义比较器：只有 Major 版本变化才升级，此时 1.0.0 到 1.0.1 不应触发升级
        let updater_major_only = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .manifest_url("https://example.com/manifest.json")
            .require_signature(false)
            .version_comparator(|current, remote| remote.major > current.major)
            .build()
            .unwrap();
        let res2 = updater_major_only.evaluate_manifest(manifest_json).unwrap();
        assert!(res2.is_none());
    }

    #[test]
    fn test_preference_skip_and_snooze_filtering() {
        let manifest_json = r#"{
            "version": "1.0.1",
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-1.0.1.zip",
                    "package_type": "archive",
                    "checksum": "sha256:abc"
                }
            }
        }"#;

        let mandatory_manifest_json = r#"{
            "version": "1.0.1",
            "force_update": true,
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-1.0.1.zip",
                    "package_type": "archive",
                    "checksum": "sha256:abc"
                }
            }
        }"#;

        let temp_pref =
            std::env::temp_dir().join(format!("test_pref_snooze_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&temp_pref);

        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .manifest_url("https://example.com/manifest.json")
            .preference_path(&temp_pref)
            .require_signature(false)
            .build()
            .unwrap();

        // 1. 初始未设置偏好，可正常发现更新
        assert!(updater.evaluate_manifest(manifest_json).unwrap().is_some());

        // 2. 标记跳过 1.0.1 版本后，常规更新被过滤忽略
        updater
            .skip_version(Version::parse("1.0.1").unwrap())
            .unwrap();
        assert!(updater.evaluate_manifest(manifest_json).unwrap().is_none());

        // 3. 强制更新 (force_update: true) 即使被跳过也必须不受限放行
        assert!(
            updater
                .evaluate_manifest(mandatory_manifest_json)
                .unwrap()
                .is_some()
        );

        // 4. 撤销跳过标记之后，常规更新恢复
        updater
            .unskip_version(&Version::parse("1.0.1").unwrap())
            .unwrap();
        assert!(updater.evaluate_manifest(manifest_json).unwrap().is_some());

        // 5. 设置稍后提醒（3600秒），在静默期内常规更新被过滤
        updater.snooze(Duration::from_secs(3600)).unwrap();
        assert!(updater.evaluate_manifest(manifest_json).unwrap().is_none());

        // 6. 清空偏好后，更新再次恢复
        updater.clear_preferences().unwrap();
        assert!(updater.evaluate_manifest(manifest_json).unwrap().is_some());
        let _ = std::fs::remove_file(&temp_pref);
    }

    #[test]
    fn test_downloaded_update_properties() {
        let release = ResolvedRelease {
            version: Version::parse("1.2.0").unwrap(),
            min_supported_version: None,
            is_mandatory: false,
            pub_date: Some("2026-09-09".to_string()),
            notes: Some("更新说明".to_string()),
            package: PackageInfo {
                url: "https://example.com/app.exe".to_string(),
                mirrors: vec![],
                signature: None,
                signatures: vec![],
                checksum: None,
                package_type: PackageType::Binary,
                install_mode: None,
                install_args: vec![],
                executable_path: None,
                require_elevation: false,
                wait_for_exit: false,
                payload_checksums: Default::default(),
                size: None,
            },
            rollout_percentage: None,
        };

        let temp_path = PathBuf::from("C:\\temp\\app.exe.shipup.tmp");
        let downloaded = DownloadedUpdate {
            current_version: Version::parse("1.0.0").unwrap(),
            release,
            downloaded_path: temp_path.clone(),
            max_rollback_entries: crate::recovery::DEFAULT_MAX_ROLLBACK_ENTRIES,
            allow_reboot_deferred_replace: false,
        };

        assert_eq!(downloaded.version(), &Version::parse("1.2.0").unwrap());
        assert_eq!(
            downloaded.current_version(),
            &Version::parse("1.0.0").unwrap()
        );
        assert_eq!(downloaded.downloaded_path(), temp_path.as_path());
    }

    #[test]
    fn test_downloaded_update_cleanup_removes_temp_file() {
        let release = ResolvedRelease {
            version: Version::parse("1.2.0").unwrap(),
            min_supported_version: None,
            is_mandatory: false,
            pub_date: None,
            notes: None,
            package: PackageInfo {
                url: "https://example.com/app.exe".to_string(),
                mirrors: vec![],
                signature: None,
                signatures: vec![],
                checksum: None,
                package_type: PackageType::Binary,
                install_mode: None,
                install_args: vec![],
                executable_path: None,
                require_elevation: false,
                wait_for_exit: false,
                payload_checksums: Default::default(),
                size: None,
            },
            rollout_percentage: None,
        };

        let temp_path = std::env::temp_dir().join(format!(
            "shipup_cleanup_test_{}.shipup.tmp",
            std::process::id()
        ));
        fs::write(&temp_path, b"pending-update-payload").unwrap();

        let downloaded = DownloadedUpdate {
            current_version: Version::parse("1.0.0").unwrap(),
            release,
            downloaded_path: temp_path.clone(),
            max_rollback_entries: crate::recovery::DEFAULT_MAX_ROLLBACK_ENTRIES,
            allow_reboot_deferred_replace: false,
        };

        assert!(temp_path.exists());
        downloaded.cleanup().unwrap();
        assert!(!temp_path.exists());

        // 幂等：文件已不存在时再次清理仍应成功
        downloaded.cleanup().unwrap();
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_offline_fallback_manifest_activation() {
        let manifest_json = r#"{
            "version": "2.0.0",
            "notes": "离线兜底版本更新",
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-2.0.0.zip",
                    "package_type": "archive"
                }
            }
        }"#;

        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .endpoint("https://127.0.0.1:9/unreachable/manifest.json")
            .timeout(Duration::from_millis(50))
            .max_retries(0)
            .fallback_manifest_json(manifest_json)
            .unwrap()
            .require_signature(false)
            .build()
            .unwrap();

        let update = updater.check().unwrap();
        assert!(update.is_some());
        assert_eq!(update.unwrap().version(), &Version::parse("2.0.0").unwrap());
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_offline_file_protocol_check() {
        let temp_dir = std::env::temp_dir();
        let manifest_file = temp_dir.join(format!("offline_manifest_{}.json", std::process::id()));
        let manifest_content = r#"{
            "version": "2.1.0",
            "notes": "file 协议测试",
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-2.1.0.zip",
                    "package_type": "archive"
                }
            }
        }"#;
        fs::write(&manifest_file, manifest_content).unwrap();

        let file_url = if cfg!(windows) {
            format!(
                "file:///{}",
                manifest_file.display().to_string().replace('\\', "/")
            )
        } else {
            format!("file://{}", manifest_file.display())
        };

        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .manifest_url(&file_url)
            .allow_file_protocol(true)
            .require_signature(false)
            .build()
            .unwrap();

        let update = updater.check().unwrap();
        assert!(update.is_some());
        assert_eq!(update.unwrap().version(), &Version::parse("2.1.0").unwrap());

        let _ = fs::remove_file(&manifest_file);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_endpoints_racing_blocking_success() {
        let temp_dir = std::env::temp_dir();
        let manifest_file =
            temp_dir.join(format!("racing_manifest_blk_{}.json", std::process::id()));
        let manifest_content = r#"{
            "version": "2.2.0",
            "notes": "同步竞速测试",
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-2.2.0.zip",
                    "package_type": "archive"
                }
            }
        }"#;
        fs::write(&manifest_file, manifest_content).unwrap();

        let valid_file_url = if cfg!(windows) {
            format!(
                "file:///{}",
                manifest_file.display().to_string().replace('\\', "/")
            )
        } else {
            format!("file://{}", manifest_file.display())
        };
        let invalid_file_url = "file:///tmp/non_existent_racing_file.json".to_string();

        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .endpoint(&invalid_file_url)
            .endpoint(&valid_file_url)
            .endpoint_racing(true)
            .stagger_delay(Duration::from_millis(5))
            .allow_file_protocol(true)
            .require_signature(false)
            .build()
            .unwrap();

        let update = updater.check().unwrap();
        assert!(update.is_some());
        assert_eq!(update.unwrap().version(), &Version::parse("2.2.0").unwrap());

        let _ = fs::remove_file(&manifest_file);
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_endpoints_racing_async_success() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let temp_dir = std::env::temp_dir();
            let manifest_file =
                temp_dir.join(format!("racing_manifest_async_{}.json", std::process::id()));
            let manifest_content = r#"{
                "version": "2.3.0",
                "notes": "异步竞速测试",
                "packages": {
                    "x86_64-pc-windows-msvc": {
                        "url": "https://example.com/app-2.3.0.zip",
                        "package_type": "archive"
                    }
                }
            }"#;
            fs::write(&manifest_file, manifest_content).unwrap();

            let valid_file_url = if cfg!(windows) {
                format!(
                    "file:///{}",
                    manifest_file.display().to_string().replace('\\', "/")
                )
            } else {
                format!("file://{}", manifest_file.display())
            };
            let invalid_file_url = "file:///tmp/non_existent_racing_async.json".to_string();

            let updater = UpdaterBuilder::new()
                .current_version("1.0.0")
                .unwrap()
                .target("x86_64-pc-windows-msvc")
                .endpoint(&invalid_file_url)
                .endpoint(&valid_file_url)
                .endpoint_racing(true)
                .stagger_delay(Duration::from_millis(5))
                .allow_file_protocol(true)
                .require_signature(false)
                .build()
                .unwrap();

            let update = updater.check_async().await.unwrap();
            assert!(update.is_some());
            assert_eq!(update.unwrap().version(), &Version::parse("2.3.0").unwrap());

            let _ = fs::remove_file(&manifest_file);
        });
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_endpoints_racing_all_failed_fallback() {
        let manifest_json = r#"{
            "version": "2.4.0",
            "notes": "竞速全失败降级测试",
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-2.4.0.zip",
                    "package_type": "archive"
                }
            }
        }"#;

        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .endpoint("file:///tmp/not_found_1.json")
            .endpoint("file:///tmp/not_found_2.json")
            .fallback_manifest_json(manifest_json)
            .unwrap()
            .endpoint_racing(true)
            .stagger_delay(Duration::from_millis(5))
            .allow_file_protocol(true)
            .require_signature(false)
            .build()
            .unwrap();

        let update = updater.check().unwrap();
        assert!(update.is_some());
        assert_eq!(update.unwrap().version(), &Version::parse("2.4.0").unwrap());
    }

    #[test]
    fn test_compute_rollout_bucket_bounds_and_determinism() {
        let v = Version::parse("1.2.0").unwrap();
        // 确定性：相同 client_id 与 version 结果必须恒定一致
        let bucket1 = compute_rollout_bucket("client-node-01", &v);
        let bucket2 = compute_rollout_bucket("client-node-01", &v);
        assert_eq!(bucket1, bucket2);
        assert!(bucket1 < 100);

        // 离散性：不同 client_id 落在合理区间
        for i in 0..50 {
            let b = compute_rollout_bucket(&format!("device-{i}"), &v);
            assert!(b < 100);
        }
    }

    #[test]
    fn test_rollout_percentage_filtering() {
        let temp_pref =
            std::env::temp_dir().join(format!("test_pref_rollout_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&temp_pref);

        let v2 = Version::parse("2.0.0").unwrap();
        let test_client_id = "test-rollout-device";
        let bucket = compute_rollout_bucket(test_client_id, &v2);

        // 1. 若 rollout_percentage <= bucket，未命中灰度，evaluate 应当返回 None
        let low_manifest_json = format!(
            r#"{{
                "version": "2.0.0",
                "rollout_percentage": {percentage},
                "packages": {{
                    "x86_64-pc-windows-msvc": {{
                        "url": "https://example.com/app-2.0.0.zip",
                        "package_type": "archive"
                    }}
                }}
            }}"#,
            percentage = bucket
        );

        let updater_blocked = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .client_id(test_client_id)
            .manifest_url("https://example.com/manifest.json")
            .preference_path(&temp_pref)
            .require_signature(false)
            .build()
            .unwrap();

        assert!(
            updater_blocked
                .evaluate_manifest(&low_manifest_json)
                .unwrap()
                .is_none()
        );

        // 2. 若 rollout_percentage > bucket，命中灰度，evaluate 返回更新
        let high_manifest_json = format!(
            r#"{{
                "version": "2.0.0",
                "rollout_percentage": {percentage},
                "packages": {{
                    "x86_64-pc-windows-msvc": {{
                        "url": "https://example.com/app-2.0.0.zip",
                        "package_type": "archive"
                    }}
                }}
            }}"#,
            percentage = bucket.saturating_add(1)
        );

        let updater_allowed = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .client_id(test_client_id)
            .manifest_url("https://example.com/manifest.json")
            .preference_path(&temp_pref)
            .require_signature(false)
            .build()
            .unwrap();

        assert!(
            updater_allowed
                .evaluate_manifest(&high_manifest_json)
                .unwrap()
                .is_some()
        );
        let _ = std::fs::remove_file(&temp_pref);

        // 3. 若 force_update = true，即使未命中灰度比例也必须放行
        let mandatory_manifest_json = format!(
            r#"{{
                "version": "2.0.0",
                "force_update": true,
                "rollout_percentage": {percentage},
                "packages": {{
                    "x86_64-pc-windows-msvc": {{
                        "url": "https://example.com/app-2.0.0.zip",
                        "package_type": "archive"
                    }}
                }}
            }}"#,
            percentage = 0
        );
        assert!(
            updater_blocked
                .evaluate_manifest(&mandatory_manifest_json)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn test_evaluate_manifest_expired_rejected() {
        let temp_pref = std::env::temp_dir().join(format!(
            "test_pref_exp_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .manifest_url("https://example.com/manifest.json")
            .preference_path(&temp_pref)
            .require_signature(false)
            .build()
            .unwrap();

        // 设定过期时间为过去的某个时间点（1970年）
        let expired_manifest_json = r#"{
            "version": "2.0.0",
            "expires_at": "1970-01-01T00:00:00Z",
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-2.0.0.zip",
                    "package_type": "archive"
                }
            }
        }"#;

        let result = updater.evaluate_manifest(expired_manifest_json);
        assert!(matches!(result, Err(UpdateError::ManifestExpired(_))));
        let _ = std::fs::remove_file(&temp_pref);
    }

    #[test]
    fn test_evaluate_manifest_version_seq_anti_replay() {
        let temp_pref = std::env::temp_dir().join(format!(
            "test_pref_seq_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .manifest_url("https://example.com/manifest.json")
            .preference_path(&temp_pref)
            .require_signature(false)
            .build()
            .unwrap();

        // 1. 首次处理高版本序号 version_seq = 100
        let manifest_v100 = r#"{
            "version": "2.0.0",
            "version_seq": 100,
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-2.0.0.zip",
                    "package_type": "archive"
                }
            }
        }"#;
        assert!(updater.evaluate_manifest(manifest_v100).unwrap().is_some());
        assert_eq!(updater.preferences().last_version_seq(), Some(100));

        // 2. 攻击者尝试重放低版本序号 version_seq = 90 的旧清单
        let stale_manifest = r#"{
            "version": "2.0.0",
            "version_seq": 90,
            "packages": {
                "x86_64-pc-windows-msvc": {
                    "url": "https://example.com/app-2.0.0.zip",
                    "package_type": "archive"
                }
            }
        }"#;
        let err = updater.evaluate_manifest(stale_manifest);
        assert!(matches!(
            err,
            Err(UpdateError::StaleManifestVersion {
                current: 100,
                remote: 90
            })
        ));

        let _ = std::fs::remove_file(&temp_pref);
    }

    #[test]
    fn test_verify_downloaded_payload_rejects_missing_signature_with_keys() {
        use base64::Engine;
        let temp_dir = std::env::temp_dir().join(format!("test_a6_sig_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let temp_bin = temp_dir.join("payload.bin");
        fs::write(&temp_bin, b"sample binary payload").unwrap();

        let dummy_key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);

        let update = Update {
            current_version: Version::parse("1.0.0").unwrap(),
            release: ResolvedRelease {
                version: Version::parse("2.0.0").unwrap(),
                min_supported_version: None,
                notes: None,
                pub_date: None,
                is_mandatory: false,
                rollout_percentage: None,
                package: crate::manifest::PackageInfo {
                    url: "https://example.com/payload.bin".to_string(),
                    mirrors: vec![],
                    signature: None, // 未提供数字签名
                    signatures: vec![],
                    checksum: None,
                    package_type: PackageType::Binary,
                    install_mode: None,
                    install_args: vec![],
                    executable_path: None,
                    require_elevation: false,
                    wait_for_exit: false,
                    payload_checksums: Default::default(),
                    size: None,
                },
            },
            config: Arc::new(NetworkSecurityConfig {
                public_keys: vec![dummy_key],
                timeout: Duration::from_secs(5),
                user_agent: None,
                headers: HashMap::new(),
                proxy: None,
                max_retries: 0,
                retry_delay: Duration::from_millis(100),
                dangerous_insecure_transport_protocol: false,
                require_signature: false, // 即使显式设置了 false，因配置了公钥，也绝不允许未签名放行！
                max_bytes_per_sec: None,
                allow_file_protocol: true,
                allow_reboot_deferred_replace: false,
                max_rollback_entries: 3,
                root_certificates_pem: Vec::new(),
                signature_threshold: 1,
                endpoint_racing: false,
                stagger_delay: Duration::from_millis(250),
                chunked_download: false,
                chunked_concurrency: 4,
                chunk_size: 4 * 1024 * 1024,
                download_mirrors: Vec::new(),
                resumable_download: false,
            }),
        };

        let mut events = Vec::new();
        let res = update.verify_downloaded_payload(&temp_bin, &mut |ev| events.push(ev));
        assert!(matches!(res, Err(UpdateError::MissingSignature)));
        // 验证失败后物理临时文件已被确定性清理
        assert!(!temp_bin.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_verify_downloaded_payload_missing_public_key_cleans_file() {
        let temp_dir = std::env::temp_dir().join(format!("test_a6_pk_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let temp_bin = temp_dir.join("payload.bin");
        fs::write(&temp_bin, b"sample binary payload").unwrap();

        let update = Update {
            current_version: Version::parse("1.0.0").unwrap(),
            release: ResolvedRelease {
                version: Version::parse("2.0.0").unwrap(),
                min_supported_version: None,
                notes: None,
                pub_date: None,
                is_mandatory: false,
                rollout_percentage: None,
                package: crate::manifest::PackageInfo {
                    url: "https://example.com/payload.bin".to_string(),
                    mirrors: vec![],
                    signature: Some("dummy_sig".to_string()),
                    signatures: vec![],
                    checksum: None,
                    package_type: PackageType::Binary,
                    install_mode: None,
                    install_args: vec![],
                    executable_path: None,
                    require_elevation: false,
                    wait_for_exit: false,
                    payload_checksums: Default::default(),
                    size: None,
                },
            },
            config: Arc::new(NetworkSecurityConfig {
                public_keys: vec![], // 未配置公钥
                timeout: Duration::from_secs(5),
                user_agent: None,
                headers: HashMap::new(),
                proxy: None,
                max_retries: 0,
                retry_delay: Duration::from_millis(100),
                dangerous_insecure_transport_protocol: false,
                require_signature: true, // 强制验签但无公钥
                max_bytes_per_sec: None,
                allow_file_protocol: true,
                allow_reboot_deferred_replace: false,
                max_rollback_entries: 3,
                root_certificates_pem: Vec::new(),
                signature_threshold: 1,
                endpoint_racing: false,
                stagger_delay: Duration::from_millis(250),
                chunked_download: false,
                chunked_concurrency: 4,
                chunk_size: 4 * 1024 * 1024,
                download_mirrors: Vec::new(),
                resumable_download: false,
            }),
        };

        let mut events = Vec::new();
        let res = update.verify_downloaded_payload(&temp_bin, &mut |ev| events.push(ev));
        assert!(matches!(res, Err(UpdateError::MissingPublicKey)));
        assert!(!temp_bin.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_build_blocking_http_client_with_invalid_certificate_rejected() {
        let invalid_pem = vec![
            b"-----BEGIN CERTIFICATE-----\ninvalid_corrupt_base64\n-----END CERTIFICATE-----"
                .to_vec(),
        ];
        let res = build_blocking_http_client(
            Duration::from_secs(5),
            None,
            &HashMap::new(),
            None,
            &invalid_pem,
        );
        assert!(res.is_err());
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_build_async_http_client_with_invalid_certificate_rejected() {
        let invalid_pem = vec![
            b"-----BEGIN CERTIFICATE-----\ninvalid_corrupt_base64\n-----END CERTIFICATE-----"
                .to_vec(),
        ];
        let res = build_async_http_client(
            Duration::from_secs(5),
            None,
            &HashMap::new(),
            None,
            &invalid_pem,
        );
        assert!(res.is_err());
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_build_blocking_http_client_defaults() {
        let res =
            build_blocking_http_client(Duration::from_secs(5), None, &HashMap::new(), None, &[]);
        assert!(res.is_ok());
    }
}
