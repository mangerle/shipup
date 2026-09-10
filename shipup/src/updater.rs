#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

// shipup 跨平台自更新系统 - Updater 与 Update 核心交互实体

use crate::archive::{extract_archive, sync_extracted_payload};
use crate::builder::{UpdaterBuilder, UpdaterConfig, VersionComparator, is_insecure_http_url};
use crate::download::{self, DownloadOptions};
use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use crate::manifest::{Manifest, PackageType, ResolveOptions, ResolvedRelease};
use crate::platform::{
    InstallerOptions, cleanup_old_backups, get_resumable_download_path, get_temp_download_path,
    replace_binary, spawn_installer,
};
use crate::preference::{self, UpdatePreference};
use crate::provider::ReleaseProvider;
use crate::restart::{RestartContext, restart_with};
use crate::signature::{verify_ed25519_file_threshold, verify_sha256_file};
use crate::template::{TemplateContext, resolve_url_template};
use semver::Version;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::Proxy;
#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

/// 网络传输与数字签名安全配置内部聚合实体
///
/// # 设计原理
/// - **实现初衷**：将网络请求策略（超时、代理、重试、请求头）与加密签名策略（多公钥、TLS 防护、强制验签）内聚为不可变的上下文配置。
/// - **核心优势**：配置通过 `Arc` 跨线程安全共享，不可被外部篡改，杜绝运行时竞争性安全降级。
/// - **代价与局限**：一旦初始化完成，运行时连接参数即固定不可动态重载。
pub(crate) struct NetworkSecurityConfig {
    pub public_keys: Vec<String>,
    pub timeout: Duration,
    pub user_agent: Option<String>,
    pub headers: HashMap<String, String>,
    pub proxy: Option<String>,
    pub max_retries: u32,
    pub retry_delay: Duration,
    pub dangerous_insecure_transport_protocol: bool,
    pub require_signature: bool,
    pub max_bytes_per_sec: Option<u64>,
    pub allow_file_protocol: bool,
    pub allow_reboot_deferred_replace: bool,
    pub max_rollback_entries: usize,
    pub root_certificates_pem: Vec<Vec<u8>>,
    pub signature_threshold: usize,
    pub endpoint_racing: bool,
    pub stagger_delay: Duration,
    pub chunked_download: bool,
    pub chunked_concurrency: usize,
    pub chunk_size: usize,
    pub download_mirrors: Vec<String>,
    pub resumable_download: bool,
}

impl std::fmt::Debug for NetworkSecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_headers: HashMap<&str, String> = self
            .headers
            .iter()
            .map(|(k, v)| {
                let lower = k.to_ascii_lowercase();
                let sensitive = lower == "authorization"
                    || lower == "cookie"
                    || lower == "proxy-authorization"
                    || lower == "set-cookie";
                (
                    k.as_str(),
                    if sensitive {
                        "***".to_string()
                    } else {
                        v.clone()
                    },
                )
            })
            .collect();

        f.debug_struct("NetworkSecurityConfig")
            .field("public_keys_count", &self.public_keys.len())
            .field("timeout", &self.timeout)
            .field("user_agent", &self.user_agent)
            .field("headers", &redacted_headers)
            .field("proxy", &self.proxy)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .field(
                "dangerous_insecure_transport_protocol",
                &self.dangerous_insecure_transport_protocol,
            )
            .field("require_signature", &self.require_signature)
            .field("max_bytes_per_sec", &self.max_bytes_per_sec)
            .field("allow_file_protocol", &self.allow_file_protocol)
            .field(
                "allow_reboot_deferred_replace",
                &self.allow_reboot_deferred_replace,
            )
            .field("max_rollback_entries", &self.max_rollback_entries)
            .field("root_certificates_count", &self.root_certificates_pem.len())
            .field("signature_threshold", &self.signature_threshold)
            .field("endpoint_racing", &self.endpoint_racing)
            .field("stagger_delay", &self.stagger_delay)
            .field("chunked_download", &self.chunked_download)
            .field("chunked_concurrency", &self.chunked_concurrency)
            .field("chunk_size", &self.chunk_size)
            .field("download_mirrors", &self.download_mirrors)
            .field("resumable_download", &self.resumable_download)
            .finish()
    }
}

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

    #[cfg(feature = "blocking")]
    /// 同步阻塞检查是否有可用更新（支持多端点自动故障转移）
    ///
    /// # 设计原理
    /// - **实现初衷**：在单次调用中按优先级轮询所有端点，单个端点故障自动降级切换至下一个端点。
    /// - **核心优势**：提升 CDN 与更新源的高可用性，单点宕机不会导致客户端更新中断。
    ///
    /// # Errors
    /// 当所有配置的更新端点均无法连通或解析失败时返回最终错误。
    pub fn check(&self) -> Result<Option<Update>> {
        if let Some(ref provider) = self.inner.provider {
            log::info!("正在通过动态发布源 ReleaseProvider 获取清单...");
            match provider.fetch_manifest_blocking() {
                Ok(manifest) => {
                    log::info!("动态发布源清单获取成功 (版本: {})", manifest.version);
                    return self.evaluate_manifest_struct(&manifest);
                }
                Err(e) => {
                    log::warn!("通过动态发布源获取清单失败: {}, 尝试降级至静态端点", e);
                    if self.inner.endpoints.is_empty() {
                        if let Some(ref fallback) = self.inner.fallback_manifest {
                            log::warn!(
                                "动态发布源失败且无备用端点，降级采用内嵌 Fallback Manifest 评估更新"
                            );
                            return self.evaluate_manifest_struct(fallback);
                        }
                        return Err(e);
                    }
                }
            }
        }

        let client = build_blocking_http_client(
            self.inner.config.timeout,
            self.inner.config.user_agent.as_deref(),
            &self.inner.config.headers,
            self.inner.config.proxy.as_deref(),
            &self.inner.config.root_certificates_pem,
        )?;

        let template_ctx = TemplateContext {
            target: &self.inner.target,
            current_version: &self.inner.current_version,
            channel: self.inner.channel.as_deref(),
        };

        if self.inner.endpoints.len() > 1 && self.inner.config.endpoint_racing {
            return self.check_endpoints_racing_blocking(&client, &template_ctx);
        }

        let mut last_error = None;
        for (idx, raw_endpoint) in self.inner.endpoints.iter().enumerate() {
            let endpoint = resolve_url_template(raw_endpoint, &template_ctx);
            log::info!(
                "发起更新检查端点 [{}/{}]: {}",
                idx + 1,
                self.inner.endpoints.len(),
                endpoint
            );

            let fetch_result = if download::is_file_url(&endpoint) {
                if !self.inner.config.allow_file_protocol {
                    Err(UpdateError::FileProtocolNotAllowed(endpoint.clone()))
                } else {
                    let path = download::parse_file_url_to_path(&endpoint)?;
                    fs::read_to_string(&path).map_err(UpdateError::Io)
                }
            } else {
                fetch_manifest_blocking(&client, &endpoint)
            };

            match fetch_result {
                Ok(body) => match self.evaluate_manifest(&body) {
                    Ok(res) => return Ok(res),
                    Err(e) => {
                        log::warn!(
                            "端点 '{}' 返回的 Manifest 解析失败: {}, 尝试下一备用端点",
                            endpoint,
                            e
                        );
                        last_error = Some(e);
                    }
                },
                Err(e) => {
                    log::warn!("请求端点 '{}' 失败: {}, 尝试下一备用端点", endpoint, e);
                    last_error = Some(e);
                }
            }
        }

        if let Some(ref fallback) = self.inner.fallback_manifest {
            log::warn!("所有配置的更新源端点均无法连通，降级采用内嵌 Fallback Manifest 评估更新");
            return self.evaluate_manifest_struct(fallback);
        }

        Err(last_error.unwrap_or_else(|| {
            UpdateError::Network("所有配置的更新源端点均无法连接访问".to_string())
        }))
    }

    #[cfg(feature = "async")]
    /// 异步检查是否有可用更新（支持多端点自动故障转移与 URL 模板渲染）
    ///
    /// # 设计原理
    /// - **实现初衷**：契合 Tokio 异步运行时，无需派生额外线程即可非阻塞拉取远端 Manifest。
    /// - **核心优势**：遇到单点故障自动异步降级切换，无死锁与跨 await 持锁风险。
    ///
    /// # Errors
    /// 当所有配置的端点均异步失败时返回最终错误。
    pub async fn check_async(&self) -> Result<Option<Update>> {
        if let Some(ref provider) = self.inner.provider {
            log::info!("正在异步通过动态发布源 ReleaseProvider 获取清单...");
            match provider.fetch_manifest_async().await {
                Ok(manifest) => {
                    log::info!("异步动态发布源清单获取成功 (版本: {})", manifest.version);
                    return self.evaluate_manifest_struct(&manifest);
                }
                Err(e) => {
                    log::warn!("异步通过动态发布源获取清单失败: {}, 尝试降级至静态端点", e);
                    if self.inner.endpoints.is_empty() {
                        if let Some(ref fallback) = self.inner.fallback_manifest {
                            log::warn!(
                                "动态发布源失败且无备用端点，降级采用内嵌 Fallback Manifest 评估更新"
                            );
                            return self.evaluate_manifest_struct(fallback);
                        }
                        return Err(e);
                    }
                }
            }
        }

        let client = build_async_http_client(
            self.inner.config.timeout,
            self.inner.config.user_agent.as_deref(),
            &self.inner.config.headers,
            self.inner.config.proxy.as_deref(),
            &self.inner.config.root_certificates_pem,
        )?;

        let template_ctx = TemplateContext {
            target: &self.inner.target,
            current_version: &self.inner.current_version,
            channel: self.inner.channel.as_deref(),
        };

        if self.inner.endpoints.len() > 1 && self.inner.config.endpoint_racing {
            return self
                .check_endpoints_racing_async(&client, &template_ctx)
                .await;
        }

        let mut last_error = None;
        for (idx, raw_endpoint) in self.inner.endpoints.iter().enumerate() {
            let endpoint = resolve_url_template(raw_endpoint, &template_ctx);
            log::info!(
                "发起异步更新检查端点 [{}/{}]: {}",
                idx + 1,
                self.inner.endpoints.len(),
                endpoint
            );

            let fetch_result = if download::is_file_url(&endpoint) {
                if !self.inner.config.allow_file_protocol {
                    Err(UpdateError::FileProtocolNotAllowed(endpoint.clone()))
                } else {
                    let path = download::parse_file_url_to_path(&endpoint)?;
                    tokio::fs::read_to_string(&path)
                        .await
                        .map_err(UpdateError::Io)
                }
            } else {
                fetch_manifest_async(&client, &endpoint).await
            };

            match fetch_result {
                Ok(body) => match self.evaluate_manifest(&body) {
                    Ok(res) => return Ok(res),
                    Err(e) => {
                        log::warn!(
                            "端点 '{}' 返回的 Manifest 解析失败: {}, 尝试下一备用端点",
                            endpoint,
                            e
                        );
                        last_error = Some(e);
                    }
                },
                Err(e) => {
                    log::warn!("异步请求端点 '{}' 失败: {}, 尝试下一备用端点", endpoint, e);
                    last_error = Some(e);
                }
            }
        }

        if let Some(ref fallback) = self.inner.fallback_manifest {
            log::warn!(
                "所有配置的更新源端点均无法异步连通，降级采用内嵌 Fallback Manifest 评估更新"
            );
            return self.evaluate_manifest_struct(fallback);
        }

        Err(last_error.unwrap_or_else(|| {
            UpdateError::Network("所有配置的更新源端点均无法连接访问".to_string())
        }))
    }

    #[cfg(feature = "blocking")]
    /// 同步阻塞多更新源并发竞速 (Happy Eyeballs) 探测
    ///
    /// # 设计原理
    /// - **实现初衷**：在配置多个更新端点（主 CDN、备用 CDN 等）时，按错峰延迟并发发起连接与 Manifest 请求。
    /// - **核心优势**：最快成功返回并校验通过的端点直接采纳；通过原子取消标志位让尚未起步的竞速线程立即放弃，
    ///   避免胜出后仍继续发起无谓网络请求。
    /// - **代价与局限**：已进入网络 IO 的阻塞请求无法中途强杀（reqwest blocking 限制），但结果会被直接丢弃。
    fn check_endpoints_racing_blocking(
        &self,
        client: &reqwest::blocking::Client,
        template_ctx: &TemplateContext<'_>,
    ) -> Result<Option<Update>> {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering as AtomicOrdering;

        let endpoints: Vec<String> = self
            .inner
            .endpoints
            .iter()
            .map(|raw| resolve_url_template(raw, template_ctx))
            .collect();

        let total = endpoints.len();
        log::info!(
            "启动同步更新源端点并发竞速 (端点数: {}, 错峰间隔: {}ms)",
            total,
            self.inner.config.stagger_delay.as_millis()
        );

        let settled = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        for (idx, endpoint) in endpoints.into_iter().enumerate() {
            let stagger = self
                .inner
                .config
                .stagger_delay
                .saturating_mul(u32::try_from(idx).unwrap_or(u32::MAX));
            let client_cloned = client.clone();
            let allow_file = self.inner.config.allow_file_protocol;
            let tx_cloned = tx.clone();
            let updater = self.clone();
            let settled_cloned = Arc::clone(&settled);

            std::thread::spawn(move || {
                if !stagger.is_zero() {
                    std::thread::sleep(stagger);
                }

                // 胜出后尚未真正发起请求的线程直接放弃，杜绝冗余流量
                if settled_cloned.load(AtomicOrdering::Acquire) {
                    return;
                }

                let fetch_res = if download::is_file_url(&endpoint) {
                    if !allow_file {
                        Err(UpdateError::FileProtocolNotAllowed(endpoint.clone()))
                    } else {
                        match download::parse_file_url_to_path(&endpoint) {
                            Ok(path) => fs::read_to_string(&path).map_err(UpdateError::Io),
                            Err(e) => Err(e),
                        }
                    }
                } else {
                    fetch_manifest_blocking(&client_cloned, &endpoint)
                };

                let eval_res = match fetch_res {
                    Ok(body) => updater.evaluate_manifest(&body),
                    Err(e) => Err(e),
                };

                let _ = tx_cloned.send((endpoint, eval_res));
            });
        }
        drop(tx);

        let mut last_err = None;
        let mut completed = 0usize;
        while let Ok((endpoint, result)) = rx.recv() {
            completed = completed.saturating_add(1);
            match result {
                Ok(opt_update) => {
                    // 先置位取消标志，再返回结果，通知其余线程放弃后续请求
                    settled.store(true, AtomicOrdering::Release);
                    log::info!("多更新源端点竞速胜出: {}", endpoint);
                    return Ok(opt_update);
                }
                Err(e) => {
                    log::debug!("竞速端点 '{}' 失败: {}", endpoint, e);
                    last_err = Some(e);
                }
            }
            if completed >= total {
                break;
            }
        }

        settled.store(true, AtomicOrdering::Release);

        if let Some(ref fallback) = self.inner.fallback_manifest {
            log::warn!("所有竞速端点均请求失败，降级采用内嵌 Fallback Manifest 评估更新");
            return self.evaluate_manifest_struct(fallback);
        }

        Err(last_err.unwrap_or_else(|| {
            UpdateError::Network("所有竞速更新源端点均无法连接访问".to_string())
        }))
    }

    #[cfg(feature = "async")]
    /// 异步非阻塞多更新源并发竞速 (Happy Eyeballs) 探测
    ///
    /// # 设计原理
    /// - **实现初衷**：借助 Tokio 异步调度器，在错峰间隔后异步拉取各个端点的清单数据。
    /// - **核心优势**：首个合法返回立刻响应，并自动取消其余迟缓异步请求，兼顾极速与资源防泄漏。
    /// - **代价与局限**：多端点并发时消耗少量短暂的 Tokio 任务调度开销。
    async fn check_endpoints_racing_async(
        &self,
        client: &reqwest::Client,
        template_ctx: &TemplateContext<'_>,
    ) -> Result<Option<Update>> {
        let endpoints: Vec<String> = self
            .inner
            .endpoints
            .iter()
            .map(|raw| resolve_url_template(raw, template_ctx))
            .collect();

        log::info!(
            "启动异步更新源端点并发竞速 (端点数: {}, 错峰间隔: {}ms)",
            endpoints.len(),
            self.inner.config.stagger_delay.as_millis()
        );

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut join_handles = Vec::with_capacity(endpoints.len());

        for (idx, endpoint) in endpoints.into_iter().enumerate() {
            let stagger = self
                .inner
                .config
                .stagger_delay
                .saturating_mul(u32::try_from(idx).unwrap_or(u32::MAX));
            let client_cloned = client.clone();
            let allow_file = self.inner.config.allow_file_protocol;
            let tx_cloned = tx.clone();
            let updater = self.clone();

            let handle = tokio::spawn(async move {
                if !stagger.is_zero() {
                    tokio::time::sleep(stagger).await;
                }
                let fetch_res = if download::is_file_url(&endpoint) {
                    if !allow_file {
                        Err(UpdateError::FileProtocolNotAllowed(endpoint.clone()))
                    } else {
                        match download::parse_file_url_to_path(&endpoint) {
                            Ok(path) => tokio::fs::read_to_string(&path)
                                .await
                                .map_err(UpdateError::Io),
                            Err(e) => Err(e),
                        }
                    }
                } else {
                    fetch_manifest_async(&client_cloned, &endpoint).await
                };

                let eval_res = match fetch_res {
                    Ok(body) => updater.evaluate_manifest(&body),
                    Err(e) => Err(e),
                };

                match eval_res {
                    Ok(opt_update) => {
                        let _ = tx_cloned.send((endpoint, Ok(opt_update))).await;
                    }
                    Err(e) => {
                        log::debug!("异步竞速端点 '{}' 失败: {}", endpoint, e);
                        let _ = tx_cloned.send((endpoint, Err(e))).await;
                    }
                }
            });
            join_handles.push(handle);
        }
        drop(tx);

        let mut last_err = None;
        let mut success_res = None;

        while let Some((endpoint, result)) = rx.recv().await {
            match result {
                Ok(opt_update) => {
                    log::info!("异步多更新源端点竞速胜出: {}", endpoint);
                    success_res = Some(opt_update);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        for h in join_handles {
            h.abort();
        }

        if let Some(opt_update) = success_res {
            return Ok(opt_update);
        }

        if let Some(ref fallback) = self.inner.fallback_manifest {
            log::warn!("所有异步竞速端点均请求失败，降级采用内嵌 Fallback Manifest 评估更新");
            return self.evaluate_manifest_struct(fallback);
        }

        Err(last_err.unwrap_or_else(|| {
            UpdateError::Network("所有竞速更新源端点均无法连接访问".to_string())
        }))
    }

    /// 解析并评估 Manifest 文本信息
    fn evaluate_manifest(&self, manifest_json: &str) -> Result<Option<Update>> {
        let manifest = Manifest::from_json_str(manifest_json)?;
        self.evaluate_manifest_struct(&manifest)
    }

    /// 针对 Manifest 实体结构执行验签与版本评估
    fn evaluate_manifest_struct(&self, manifest: &Manifest) -> Result<Option<Update>> {
        // 1. 校验 Manifest 有效期限，防范过期清单重放攻击
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        manifest.verify_freshness(now_unix)?;

        // 2. 校验 Manifest 清单自身数字签名
        if !self.inner.config.public_keys.is_empty() {
            let all_sigs = manifest.all_signatures();
            if !all_sigs.is_empty() {
                manifest.verify_signatures_threshold(
                    &self.inner.config.public_keys,
                    self.inner.config.signature_threshold,
                )?;
                log::info!(
                    "更新源 Manifest 清单自身 TUF 门限数字签名防伪验证通过 (门限: {})",
                    self.inner.config.signature_threshold
                );
            } else if self.inner.config.require_signature {
                log::debug!("当前 Manifest 未附带根级数字签名，将严格依赖后续安装包体级数字签名");
            }
        }

        // 3. 校验单调递增版本序号（防重放与版本逆向），并在合法时更新偏好
        if let Some(remote_seq) = manifest.version_seq {
            let mut pref = self
                .inner
                .preference
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(current_seq) = pref.last_version_seq()
                && remote_seq < current_seq
            {
                return Err(UpdateError::StaleManifestVersion {
                    current: current_seq,
                    remote: remote_seq,
                });
            }
            let is_newer = pref.last_version_seq().is_none_or(|curr| remote_seq > curr);
            if is_newer {
                pref.record_version_seq(remote_seq);
                if let Some(ref path) = self.inner.preference_path {
                    let _ = pref.save_to_file(path);
                }
            }
        }

        let options = ResolveOptions {
            channel: self.inner.channel.as_deref(),
            target: &self.inner.target,
            current_version: &self.inner.current_version,
        };
        let mut release = manifest.resolve(&options)?;

        // 若 package.url 为相对路径且当前端点为本地 file://，自动展开为绝对 file:// URL
        if !release.package.url.contains("://")
            && let Some(endpoint) = self.inner.endpoints.first()
            && crate::offline::is_file_protocol(endpoint)
            && let Ok(resolved_url) =
                crate::offline::resolve_relative_file_url(endpoint, &release.package.url)
        {
            release.package.url = resolved_url;
        }

        let is_available = if let Some(ref comparator) = self.inner.version_comparator {
            comparator(&self.inner.current_version, &release.version)
        } else if self.inner.allow_downgrade {
            release.version != self.inner.current_version
        } else {
            release.version > self.inner.current_version
        };

        if !is_available {
            log::info!(
                "根据版本策略评估，远端版本 ({}) 无需更新（本地当前版本: {}）",
                release.version,
                self.inner.current_version
            );
            return Ok(None);
        }

        // 检查用户更新偏好设置（强制更新不受跳过与稍后提醒限制）
        if !release.is_mandatory {
            let pref = self
                .inner
                .preference
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            if pref.is_snoozed() {
                log::info!(
                    "当前处于稍后提醒静默期内，忽略本次更新提醒（版本: {}）",
                    release.version
                );
                return Ok(None);
            }

            if pref.is_skipped(&release.version) {
                log::info!("用户已设置跳过版本 {}，忽略本次更新提醒", release.version);
                return Ok(None);
            }
        }

        // 灰度放量拦截：若配置了 rollout_percentage（0..=100）且非强制更新，进行客户端稳定哈希分桶评估
        if !release.is_mandatory
            && let Some(percentage) = release.rollout_percentage
        {
            let pref = self
                .inner
                .preference
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let client_id = pref.client_id().unwrap_or_default();
            let bucket = compute_rollout_bucket(client_id, &release.version);
            if bucket >= percentage {
                log::info!(
                    "新版本 {} 处于灰度放量中（灰度比例: {}%，客户端分桶: {}），未命中灰度，暂不提示更新",
                    release.version,
                    percentage,
                    bucket
                );
                return Ok(None);
            }
            log::info!(
                "新版本 {} 处于灰度放量中（灰度比例: {}%，客户端分桶: {}），已命中灰度放量",
                release.version,
                percentage,
                bucket
            );
        }

        log::info!("发现可用更新版本: {}", release.version);
        Ok(Some(Update {
            current_version: self.inner.current_version.clone(),
            release,
            config: Arc::clone(&self.inner.config),
        }))
    }

    #[cfg(feature = "blocking")]
    /// 启动基于独立 OS 线程的后台同步静默轮询工作器
    ///
    /// # 设计原理
    /// - **实现初衷**：为传统同步桌面程序提供开箱即用的常驻后台更新检测与静默预载服务，无需宿主手动维护工作线程。
    /// - **核心优势**：在后台独立执行网络轮询与更新包下载，期间不阻塞宿主主界面的事件循环。
    /// - **代价与局限**：每个轮询器占用一个系统原生线程栈，通过毫秒级切片睡眠响应退出，保障随进程优雅关闭。
    ///
    /// # 参数
    /// * `options`: 轮询周期、首次触发及静默下载选项
    /// * `callback`: 事件通知闭包，跨线程接收检查、下载中及更新就绪等事件
    ///
    /// # Errors
    /// 当操作系统创建原生线程受限时返回 [`std::io::Error`]。
    pub fn start_polling_thread<F>(
        &self,
        options: crate::poller::AutoPollOptions,
        callback: F,
    ) -> std::io::Result<crate::poller::AutoPollerHandle>
    where
        F: FnMut(crate::poller::AutoPollEvent) + Send + 'static,
    {
        crate::poller::spawn_polling_thread(self.clone(), options, callback)
    }

    #[cfg(feature = "async")]
    /// 启动基于 Tokio 的后台异步静默轮询任务
    ///
    /// # 设计原理
    /// - **实现初衷**：在异步应用（如 GPUI 或 Tokio 后端）中以协作式轻量级协程常驻运行，实现极低内存开销的更新监控。
    /// - **核心优势**：采用 Tokio 原生定时器与异步网络请求，零额外系统线程开销。
    /// - **代价与局限**：要求调用上下文处于活跃的 Tokio 异步运行时中。
    ///
    /// # 参数
    /// * `options`: 轮询周期、首次触发及静默下载选项
    /// * `callback`: 事件通知闭包，接收检查、下载中及更新就绪等事件
    pub fn start_polling_task<F>(
        &self,
        options: crate::poller::AutoPollOptions,
        callback: F,
    ) -> crate::poller::AutoPollerHandle
    where
        F: FnMut(crate::poller::AutoPollEvent) + Send + 'static,
    {
        crate::poller::spawn_polling_task(self.clone(), options, callback)
    }
}

/// 表示已确认可用的新版本更新对象
///
/// # 设计原理
/// - **实现初衷**：代表已通过通道与平台路由鉴权确认可用的新版本，封装后续的下载校验、归档解压与部署替换。
/// - **核心优势**：保证只有在真正存在新版本时才能持有该对象，从类型系统上排除对“最新版本”执行下载的非法调用。
#[derive(Debug, Clone)]
pub struct Update {
    current_version: Version,
    release: ResolvedRelease,
    config: Arc<NetworkSecurityConfig>,
}

impl Update {
    /// 获取当前本地版本
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }

    /// 获取目标新版本
    pub fn version(&self) -> &Version {
        &self.release.version
    }

    /// 获取版本发布说明日志
    pub fn notes(&self) -> Option<&str> {
        self.release.notes.as_deref()
    }

    /// 获取版本发布时间戳
    pub fn pub_date(&self) -> Option<&str> {
        self.release.pub_date.as_deref()
    }

    /// 是否为强制更新
    pub fn is_mandatory(&self) -> bool {
        self.release.is_mandatory
    }

    /// 获取更新包安装形态
    pub fn package_type(&self) -> PackageType {
        self.release.package.package_type
    }

    #[cfg(feature = "blocking")]
    /// 同步执行更新包下载与完整性验签，暂存至临时目录并返回待安装实体（不修改任何本地文件）
    ///
    /// # 设计原理
    /// - **实现初衷**：解耦更新生命周期中的“网络下载/验签”与“物理替换/安装”两阶段，支持后台静默预载。
    /// - **核心优势**：下载与验签完成后不产生任何正在运行进程的文件覆盖破坏，由调用方自主决定何时安装。
    ///
    /// # Errors
    /// 当下载失败、哈希不匹配或数字签名校验失败时返回对应错误。
    pub fn download<F>(&self, callback: F) -> Result<DownloadedUpdate>
    where
        F: FnMut(UpdateEvent),
    {
        self.download_with_cancellation(None, callback)
    }

    #[cfg(feature = "blocking")]
    /// 支持主动取消标记的同步下载与验签（不修改任何本地运行文件）
    ///
    /// # Errors
    /// 当流程被主动取消或校验失败时返回对应错误。
    pub fn download_with_cancellation<F>(
        &self,
        cancel_flag: Option<Arc<AtomicBool>>,
        mut callback: F,
    ) -> Result<DownloadedUpdate>
    where
        F: FnMut(UpdateEvent),
    {
        if !self.config.dangerous_insecure_transport_protocol
            && is_insecure_http_url(&self.release.package.url)
        {
            return Err(UpdateError::InsecureTransportProtocol(
                self.release.package.url.clone(),
            ));
        }

        if !self.config.allow_file_protocol && download::is_file_url(&self.release.package.url) {
            return Err(UpdateError::FileProtocolNotAllowed(
                self.release.package.url.clone(),
            ));
        }

        let client = build_blocking_http_client(
            self.config.timeout,
            self.config.user_agent.as_deref(),
            &self.config.headers,
            self.config.proxy.as_deref(),
            &self.config.root_certificates_pem,
        )?;

        let temp_download_path = self.resolve_download_path()?;
        let options = DownloadOptions {
            url: &self.release.package.url,
            target_path: &temp_download_path,
            cancel_flag,
            max_retries: self.config.max_retries,
            retry_delay: self.config.retry_delay,
            expected_checksum: self.release.package.checksum.as_deref(),
            expected_size: self.release.package.size,
            max_bytes_per_sec: self.config.max_bytes_per_sec,
        };

        let mut mirrors = self.release.package.mirrors.clone();
        for m in &self.config.download_mirrors {
            if !mirrors.contains(m) {
                mirrors.push(m.clone());
            }
        }

        if let Err(e) = (|| -> Result<()> {
            if self.config.chunked_download {
                let chunked_opts = download::ChunkedDownloadOptions {
                    base: options,
                    mirrors: &mirrors,
                    concurrency: self.config.chunked_concurrency,
                    chunk_size: self.config.chunk_size,
                };
                download::download_file_chunked_blocking(&client, &chunked_opts, &mut callback)?;
            } else {
                download::download_file_blocking(&client, &options, &mut callback)?;
            }
            self.verify_downloaded_payload(&temp_download_path, &mut callback)?;
            Ok(())
        })() {
            callback(UpdateEvent::Failed {
                reason: e.to_string(),
            });
            return Err(e);
        }

        Ok(DownloadedUpdate {
            current_version: self.current_version.clone(),
            release: self.release.clone(),
            downloaded_path: temp_download_path,
            max_rollback_entries: self.config.max_rollback_entries,
            allow_reboot_deferred_replace: self.config.allow_reboot_deferred_replace,
        })
    }

    #[cfg(feature = "blocking")]
    /// 同步下载并完成更新安装（复合便捷方法）
    ///
    /// # Errors
    /// 下载、验签、解压或安装失败时返回对应错误。
    pub fn download_and_install<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        let downloaded = self.download_with_cancellation(None, &mut callback)?;
        downloaded.install(callback)
    }

    #[cfg(feature = "blocking")]
    /// 支持主动取消标记的同步下载与安装（复合便捷方法）
    ///
    /// # Errors
    /// 当流程被主动取消或安装失败时返回对应错误。
    pub fn download_and_install_with_cancellation<F>(
        &self,
        cancel_flag: Option<Arc<AtomicBool>>,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        let downloaded = self.download_with_cancellation(cancel_flag, &mut callback)?;
        downloaded.install(callback)
    }

    #[cfg(feature = "async")]
    /// 异步执行更新包下载与完整性验签，暂存至临时目录并返回待安装实体（不修改任何本地文件）
    ///
    /// # Errors
    /// 当异步下载失败、校验错误时返回对应错误。
    pub async fn download_async<F>(&self, callback: F) -> Result<DownloadedUpdate>
    where
        F: FnMut(UpdateEvent) + Send,
    {
        self.download_with_cancellation_async(None, callback).await
    }

    #[cfg(feature = "async")]
    /// 支持主动取消标记的异步下载与验签（不修改任何本地运行文件）
    ///
    /// # Errors
    /// 当异步流程被取消或签名校验失败时返回对应错误。
    pub async fn download_with_cancellation_async<F>(
        &self,
        cancel_flag: Option<Arc<AtomicBool>>,
        mut callback: F,
    ) -> Result<DownloadedUpdate>
    where
        F: FnMut(UpdateEvent) + Send,
    {
        if !self.config.dangerous_insecure_transport_protocol
            && is_insecure_http_url(&self.release.package.url)
        {
            return Err(UpdateError::InsecureTransportProtocol(
                self.release.package.url.clone(),
            ));
        }

        if !self.config.allow_file_protocol && download::is_file_url(&self.release.package.url) {
            return Err(UpdateError::FileProtocolNotAllowed(
                self.release.package.url.clone(),
            ));
        }

        let client = build_async_http_client(
            self.config.timeout,
            self.config.user_agent.as_deref(),
            &self.config.headers,
            self.config.proxy.as_deref(),
            &self.config.root_certificates_pem,
        )?;

        let temp_download_path = self.resolve_download_path()?;
        let options = DownloadOptions {
            url: &self.release.package.url,
            target_path: &temp_download_path,
            cancel_flag,
            max_retries: self.config.max_retries,
            retry_delay: self.config.retry_delay,
            expected_checksum: self.release.package.checksum.as_deref(),
            expected_size: self.release.package.size,
            max_bytes_per_sec: self.config.max_bytes_per_sec,
        };

        let mut mirrors = self.release.package.mirrors.clone();
        for m in &self.config.download_mirrors {
            if !mirrors.contains(m) {
                mirrors.push(m.clone());
            }
        }

        let download_and_verify_result: Result<()> = async {
            if self.config.chunked_download {
                let chunked_opts = download::ChunkedDownloadOptions {
                    base: options,
                    mirrors: &mirrors,
                    concurrency: self.config.chunked_concurrency,
                    chunk_size: self.config.chunk_size,
                };
                download::download_file_chunked_async(&client, &chunked_opts, &mut callback)
                    .await?;
            } else {
                download::download_file_async(&client, &options, &mut callback).await?;
            }

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let this = self.clone();
            let target_temp_path = temp_download_path.clone();

            let blocking_handle = tokio::task::spawn_blocking(move || {
                this.verify_downloaded_payload(&target_temp_path, &mut |event| {
                    let _ = tx.send(event);
                })
            });

            while let Some(event) = rx.recv().await {
                callback(event);
            }

            match blocking_handle.await {
                Ok(res) => res?,
                Err(join_err) => {
                    return Err(UpdateError::SelfReplace(format!(
                        "后台签名校验任务异常中止: {}",
                        join_err
                    )));
                }
            }

            Ok(())
        }
        .await;

        if let Err(e) = download_and_verify_result {
            callback(UpdateEvent::Failed {
                reason: e.to_string(),
            });
            return Err(e);
        }

        Ok(DownloadedUpdate {
            current_version: self.current_version.clone(),
            release: self.release.clone(),
            downloaded_path: temp_download_path,
            max_rollback_entries: self.config.max_rollback_entries,
            allow_reboot_deferred_replace: self.config.allow_reboot_deferred_replace,
        })
    }

    #[cfg(feature = "async")]
    /// 异步下载并完成更新安装（复合便捷方法）
    ///
    /// # Errors
    /// 当异步流程失败时返回对应错误。
    pub async fn download_and_install_async<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(UpdateEvent) + Send,
    {
        let downloaded = self
            .download_with_cancellation_async(None, &mut callback)
            .await?;
        downloaded.install(callback)
    }

    #[cfg(feature = "async")]
    /// 支持主动取消标记的异步下载与安装（复合便捷方法）
    ///
    /// # Errors
    /// 当流程被取消或安装失败时返回对应错误。
    pub async fn download_and_install_with_cancellation_async<F>(
        &self,
        cancel_flag: Option<Arc<AtomicBool>>,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(UpdateEvent) + Send,
    {
        let downloaded = self
            .download_with_cancellation_async(cancel_flag, &mut callback)
            .await?;
        downloaded.install(callback)
    }

    /// 根据配置解析下载落盘路径
    ///
    /// # 设计原理
    /// - **实现初衷**：将“高熵随机临时路径”与“跨进程确定性续传路径”的选择收敛到单一决策点，
    ///   避免同步与异步下载入口各自散落判断逻辑导致行为漂移。
    /// - **核心优势**：开启 `resumable_download` 后进程重启可定位未完成分片；默认关闭时保持防预占投毒随机性。
    fn resolve_download_path(&self) -> Result<PathBuf> {
        if self.config.resumable_download {
            get_resumable_download_path(
                self.release.package.package_type,
                &self.release.package.url,
            )
        } else {
            get_temp_download_path(self.release.package.package_type, &self.release.package.url)
        }
    }

    fn verify_downloaded_payload<F>(&self, temp_path: &Path, callback: &mut F) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        if let Some(ref checksum) = self.release.package.checksum {
            callback(UpdateEvent::VerifyingChecksum);
            if let Err(e) = verify_sha256_file(temp_path, checksum) {
                let _ = fs::remove_file(temp_path);
                return Err(e);
            }
        }

        // 数字签名校验：只要开启了 require_signature 或配置了验签公钥列表，就必须强制执行签名防伪核验
        if self.config.require_signature || !self.config.public_keys.is_empty() {
            callback(UpdateEvent::VerifyingSignature);
            if self.config.public_keys.is_empty() {
                let _ = fs::remove_file(temp_path);
                return Err(UpdateError::MissingPublicKey);
            }
            let all_sigs = self.release.package.all_signatures();
            if all_sigs.is_empty() {
                let _ = fs::remove_file(temp_path);
                return Err(UpdateError::MissingSignature);
            }
            if let Err(e) = verify_ed25519_file_threshold(
                temp_path,
                &all_sigs,
                &self.config.public_keys,
                self.config.signature_threshold,
            ) {
                let _ = fs::remove_file(temp_path);
                return Err(e);
            }
        }

        Ok(())
    }

    /// 优雅重启宿主程序，并在进程退出前执行清理闭包
    ///
    /// # Errors
    /// 当拉起新进程失败时返回 [`UpdateError::SelfReplace`]。若新进程拉起成功，将在执行清理闭包后退出当前进程，正常情况下不会返回。
    pub fn restart_with<F>(&self, cleanup: F) -> Result<Infallible>
    where
        F: FnOnce(&mut RestartContext),
    {
        restart_with(cleanup)
    }

    /// 直接重启宿主程序
    ///
    /// # Errors
    /// 当拉起新进程失败时返回 [`UpdateError::SelfReplace`]。若新进程拉起成功，将退出当前进程，正常情况下不会返回。
    pub fn restart(&self) -> Result<Infallible> {
        restart_with(|_| {})
    }
}

/// 已下载并完成哈希与数字签名验证的待安装更新实体
///
/// # 设计原理
/// - **实现初衷**：彻底解耦更新生命周期中的“网络下载/验签”与“物理磁盘覆盖/安装器派生”两阶段。
/// - **核心优势**：支持静默后台预下载更新包（不产生任何正在运行进程的文件覆盖破坏），在用户空闲或确认时再调用 `install()`。
/// - **代价与局限**：安装前更新包暂存于操作系统临时目录中。
#[derive(Debug, Clone)]
pub struct DownloadedUpdate {
    current_version: Version,
    release: ResolvedRelease,
    downloaded_path: PathBuf,
    max_rollback_entries: usize,
    allow_reboot_deferred_replace: bool,
}

impl DownloadedUpdate {
    /// 获取宿主程序当前运行的本地版本号
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }

    /// 获取即将安装的目标新版本号
    pub fn version(&self) -> &Version {
        &self.release.version
    }

    /// 获取已完成网络下载且通过完整性哈希与多公钥数字签名的本地暂存文件物理路径
    ///
    /// # 设计原理
    /// - **实现初衷**：向宿主暴露物理文件句柄，便于上层需要展示文件信息或在沙箱内进一步自检。
    pub fn downloaded_path(&self) -> &Path {
        &self.downloaded_path
    }

    /// 获取匹配解析后的完整版本发布元数据引用
    pub fn release(&self) -> &ResolvedRelease {
        &self.release
    }

    /// 显式清理已下载的本地暂存更新包
    ///
    /// # 设计原理
    /// - **实现初衷**：当用户取消升级或预载后放弃安装时，需要主动回收磁盘上的临时更新包，避免长期残留。
    /// - **核心优势**：幂等安全，文件不存在时静默成功；不依赖 `Drop`，避免 `Clone` 语义下误删共享副本。
    /// - **代价与局限**：清理后本实例不可再调用 `install()`；若存在其他克隆副本共享同一路径，安装能力同样失效。
    ///
    /// # Errors
    /// 当底层文件删除失败时返回 [`UpdateError::Io`]。
    pub fn cleanup(&self) -> Result<()> {
        if self.downloaded_path.exists() {
            fs::remove_file(&self.downloaded_path).map_err(UpdateError::Io)?;
            log::info!("已清理本地暂存更新包: {}", self.downloaded_path.display());
        }
        Ok(())
    }

    /// 执行物理安装、解压替换或拉起外部安装器
    ///
    /// # 设计原理
    /// - **实现初衷**：将实际对本地磁盘运行程序的修改收敛至调用端显式触发的受控时机。
    /// - **核心优势**：
    ///   - 对于二进制模式（Binary），基于同卷原子重命名替换正在运行的文件并记录自愈标记；
    ///   - 对于归档模式（Archive），在隔离沙箱内解压验证并同步非二进制资源，防范 Zip Slip 攻击；
    ///   - 对于安装器模式（Installer），根据 Windows/macOS/Linux 平台特性展开标准静默参数并脱离父进程树派生。
    ///
    /// # 参数
    /// * `callback`: 安装进度事件回调闭包，按顺序接收 [`UpdateEvent::Installing`]、[`UpdateEvent::ReadyToRestart`] 等通知。
    ///
    /// # Errors
    /// 当解压归档包、二进制原地重命名或派生拉起安装器失败时返回对应的 [`UpdateError`]。
    pub fn install<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        match apply_downloaded_payload(
            &self.current_version,
            &self.release,
            &self.downloaded_path,
            self.max_rollback_entries,
            self.allow_reboot_deferred_replace,
            &mut callback,
        ) {
            Ok(()) => {
                callback(UpdateEvent::Completed);
                Ok(())
            }
            Err(e) => {
                callback(UpdateEvent::Failed {
                    reason: e.to_string(),
                });
                Err(e)
            }
        }
    }
}

/// 执行二进制替换，若原地替换受阻且配置了允许重启延迟替换则安全降级
fn perform_replace_with_fallback<F>(
    new_binary: &Path,
    version: &str,
    allow_reboot_deferred: bool,
    callback: &mut F,
) -> Result<bool>
where
    F: FnMut(UpdateEvent),
{
    match replace_binary(new_binary) {
        Ok(()) => Ok(false),
        Err(e) => {
            #[cfg(windows)]
            if allow_reboot_deferred {
                log::warn!(
                    "Windows 原地替换可执行程序受阻 ({e})，尝试降级为系统重启延迟替换 (MoveFileEx)..."
                );
                let current_exe = std::env::current_exe()?;
                let parent = current_exe.parent().unwrap_or_else(|| Path::new("."));
                let pending_path =
                    parent.join(format!(".shipup_reboot_pending_{}.exe", std::process::id()));
                fs::copy(new_binary, &pending_path)?;
                crate::platform::schedule_reboot_replace(&pending_path, &current_exe)?;
                callback(UpdateEvent::DeferredToReboot {
                    version: version.to_string(),
                    pending_path,
                });
                return Ok(true);
            }
            #[cfg(not(windows))]
            let _ = (version, allow_reboot_deferred, &mut *callback);

            Err(e)
        }
    }
}

fn apply_downloaded_payload<F>(
    current_version: &Version,
    release: &ResolvedRelease,
    temp_path: &Path,
    max_rollback_entries: usize,
    allow_reboot_deferred_replace: bool,
    callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    match release.package.package_type {
        PackageType::Binary => {
            callback(UpdateEvent::Installing);
            let backup_path = prepare_backup_before_replace(current_version)?;
            let is_deferred = perform_replace_with_fallback(
                temp_path,
                &release.version.to_string(),
                allow_reboot_deferred_replace,
                callback,
            )?;
            let _ = fs::remove_file(temp_path);
            record_state_if_possible(
                current_version,
                &release.version,
                backup_path.as_deref(),
                max_rollback_entries,
            );
            if !is_deferred {
                callback(UpdateEvent::ReadyToRestart);
            }
        }
        PackageType::Archive => {
            callback(UpdateEvent::ExtractingArchive);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let sandbox_name = format!("shipup_sandbox_{}_{}", std::process::id(), timestamp);
            let sandbox_dir = temp_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(sandbox_name);

            let apply_result = (|| -> Result<(Option<PathBuf>, bool)> {
                let extracted_binary = extract_archive(
                    temp_path,
                    &sandbox_dir,
                    release.package.executable_path.as_deref(),
                )?;

                // 解压后对 Manifest 声明的关键文件执行二次哈希防伪
                if !release.package.payload_checksums.is_empty() {
                    let extract_root = extracted_binary
                        .parent()
                        .unwrap_or(&sandbox_dir)
                        .to_path_buf();
                    crate::archive::verify_extracted_payload_checksums(
                        &extract_root,
                        &release.package.payload_checksums,
                    )?;
                }

                callback(UpdateEvent::Installing);

                // 同步解压目录中除主程序外的全部伴随依赖（动态库、静态资源等）到宿主应用目录
                let current_exe = std::env::current_exe()?;
                if let Some(target_dir) = current_exe.parent() {
                    let payload_dir = extracted_binary.parent().unwrap_or(&sandbox_dir);
                    sync_extracted_payload(payload_dir, target_dir, &extracted_binary)?;
                }

                let backup_path = prepare_backup_before_replace(current_version)?;
                let is_deferred = perform_replace_with_fallback(
                    &extracted_binary,
                    &release.version.to_string(),
                    allow_reboot_deferred_replace,
                    callback,
                )?;
                Ok((backup_path, is_deferred))
            })();

            let _ = fs::remove_dir_all(&sandbox_dir);
            let _ = fs::remove_file(temp_path);
            let (backup_path, is_deferred) = apply_result?;

            record_state_if_possible(
                current_version,
                &release.version,
                backup_path.as_deref(),
                max_rollback_entries,
            );
            if !is_deferred {
                callback(UpdateEvent::ReadyToRestart);
            }
        }
        PackageType::Installer => {
            callback(UpdateEvent::Installing);
            let installer_options = InstallerOptions {
                user_args: &release.package.install_args,
                install_mode: release.package.install_mode,
                require_elevation: release.package.require_elevation,
                wait_for_exit: release.package.wait_for_exit,
            };
            spawn_installer(temp_path, &installer_options)?;
            callback(UpdateEvent::ReadyToRestart);
        }
    }

    Ok(())
}

fn prepare_backup_before_replace(current_version: &Version) -> Result<Option<PathBuf>> {
    #[cfg(target_os = "macos")]
    {
        if let Some(bundle) = crate::platform::macos::find_current_app_bundle() {
            if let Some(parent) = bundle.parent() {
                let bundle_name = bundle
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("app.app");
                let backup_bundle =
                    parent.join(format!("{}.shipup.{}.old", bundle_name, current_version));
                return Ok(Some(backup_bundle));
            }
        }
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("app");
        let backup_path = parent.join(format!("{}.shipup.{}.old", exe_name, current_version));
        if backup_path.exists() {
            let _ = fs::remove_file(&backup_path);
        }
        if let Err(e) = fs::copy(&current_exe, &backup_path) {
            log::warn!("创建当前可执行文件物理备份失败: {}", e);
            return Ok(None);
        }
        log::info!("已创建历史可执行文件物理备份: {}", backup_path.display());
        return Ok(Some(backup_path));
    }

    Ok(None)
}

fn record_state_if_possible(
    current_version: &Version,
    target_version: &Version,
    backup_path: Option<&Path>,
    max_rollback_entries: usize,
) {
    let target_dir = crate::preference::resolve_safe_data_dir().or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    });

    if let Some(dir) = target_dir
        && let Some(backup) = backup_path
        && backup.exists()
    {
        let _ = crate::recovery::record_update_state(&dir, &target_version.to_string(), backup);
        let _ = crate::recovery::record_rollback_version(
            &dir,
            current_version,
            backup,
            max_rollback_entries,
        );
    }
}

#[cfg(any(feature = "blocking", feature = "async"))]
fn parse_header_map(headers: &HashMap<String, String>) -> Result<Option<HeaderMap>> {
    if headers.is_empty() {
        return Ok(None);
    }
    let mut header_map = HeaderMap::with_capacity(headers.len());
    for (k, v) in headers {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| UpdateError::Network(format!("无效的 HTTP 请求头名称 '{}': {}", k, e)))?;
        let val = HeaderValue::from_str(v)
            .map_err(|e| UpdateError::Network(format!("无效的 HTTP 请求头数值 '{}': {}", v, e)))?;
        header_map.insert(name, val);
    }
    Ok(Some(header_map))
}

#[cfg(any(feature = "blocking", feature = "async"))]
fn parse_proxy(proxy: Option<&str>) -> Result<Option<Proxy>> {
    match proxy {
        Some(proxy_url) => {
            let proxy_config = Proxy::all(proxy_url).map_err(|e| {
                UpdateError::Network(format!("配置代理服务器 '{}' 失败: {}", proxy_url, e))
            })?;
            Ok(Some(proxy_config))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "blocking")]
fn build_blocking_http_client(
    timeout: Duration,
    user_agent: Option<&str>,
    headers: &HashMap<String, String>,
    proxy: Option<&str>,
    root_certificates_pem: &[Vec<u8>],
) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .min_tls_version(reqwest::tls::Version::TLS_1_2);

    for pem_bytes in root_certificates_pem {
        let cert = reqwest::Certificate::from_pem(pem_bytes)
            .map_err(|e| UpdateError::Network(format!("加载自定义受信任根证书失败: {}", e)))?;
        builder = builder.add_root_certificate(cert);
    }

    if let Some(ua) = user_agent {
        builder = builder.user_agent(ua);
    }
    if let Some(header_map) = parse_header_map(headers)? {
        builder = builder.default_headers(header_map);
    }
    if let Some(proxy_config) = parse_proxy(proxy)? {
        builder = builder.proxy(proxy_config);
    }
    builder
        .build()
        .map_err(|e| UpdateError::Network(format!("初始化 HTTP 客户端失败: {}", e)))
}

#[cfg(feature = "async")]
fn build_async_http_client(
    timeout: Duration,
    user_agent: Option<&str>,
    headers: &HashMap<String, String>,
    proxy: Option<&str>,
    root_certificates_pem: &[Vec<u8>],
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .min_tls_version(reqwest::tls::Version::TLS_1_2);

    for pem_bytes in root_certificates_pem {
        let cert = reqwest::Certificate::from_pem(pem_bytes)
            .map_err(|e| UpdateError::Network(format!("加载自定义受信任根证书失败: {}", e)))?;
        builder = builder.add_root_certificate(cert);
    }

    if let Some(ua) = user_agent {
        builder = builder.user_agent(ua);
    }
    if let Some(header_map) = parse_header_map(headers)? {
        builder = builder.default_headers(header_map);
    }
    if let Some(proxy_config) = parse_proxy(proxy)? {
        builder = builder.proxy(proxy_config);
    }
    builder
        .build()
        .map_err(|e| UpdateError::Network(format!("初始化异步 HTTP 客户端失败: {}", e)))
}

#[cfg(feature = "blocking")]
fn fetch_manifest_blocking(client: &reqwest::blocking::Client, endpoint: &str) -> Result<String> {
    let response = client
        .get(endpoint)
        .send()
        .map_err(|e| UpdateError::Network(format!("连接更新端点 '{}' 失败: {}", endpoint, e)))?;

    let status = response.status();
    if !status.is_success() {
        return Err(UpdateError::HttpStatus {
            status_code: status.as_u16(),
            message: format!("端点 '{}' 返回异常 HTTP 状态码: {}", endpoint, status),
        });
    }

    response
        .text()
        .map_err(|e| UpdateError::Network(format!("读取端点 '{}' 响应失败: {}", endpoint, e)))
}

#[cfg(feature = "async")]
async fn fetch_manifest_async(client: &reqwest::Client, endpoint: &str) -> Result<String> {
    let response = client.get(endpoint).send().await.map_err(|e| {
        UpdateError::Network(format!("异步连接更新端点 '{}' 失败: {}", endpoint, e))
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(UpdateError::HttpStatus {
            status_code: status.as_u16(),
            message: format!("端点 '{}' 返回异常 HTTP 状态码: {}", endpoint, status),
        });
    }

    response
        .text()
        .await
        .map_err(|e| UpdateError::Network(format!("异步读取端点 '{}' 响应失败: {}", endpoint, e)))
}

/// 计算客户端设备针对特定发布版本的灰度分桶哈希值（范围 0..=99）
///
/// # 设计原理
/// - **实现初衷**：确保同一台客户端对相同版本评估时分桶保持恒定，且不同发布版本间分桶呈雪崩离散均匀分布。
/// - **核心优势**：采用 SHA-256 计算 `client_id:version` 哈希值并对 100 取模，杜绝伪随机数重置或分桶漂移。
pub(crate) fn compute_rollout_bucket(client_id: &str, version: &Version) -> u8 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(client_id.as_bytes());
    hasher.update(b":");
    hasher.update(version.to_string().as_bytes());
    let digest = hasher.finalize();
    let sample = u16::from_be_bytes([digest[0], digest[1]]);
    (sample % 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PackageInfo;

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
