#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

// shipup 跨平台自更新系统 - Updater 与 Update 核心交互实体

use crate::archive::{extract_archive, sync_extracted_payload};
use crate::builder::{UpdaterBuilder, UpdaterConfig, VersionComparator};
use crate::download::{self, DownloadOptions};
use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use crate::manifest::{Manifest, PackageType, ResolveOptions, ResolvedRelease};
use crate::platform::{
    InstallerOptions, cleanup_old_backups, get_temp_download_path, replace_binary, spawn_installer,
};
use crate::preference::{self, UpdatePreference};
use crate::restart::{RestartContext, restart_with};
use crate::signature::{verify_ed25519_file_any_key, verify_sha256_file};
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

/// 更新器核心实体
///
/// # 设计原理
/// - **实现初衷**：作为客户端更新系统的统一生命周期管理器，封装检查元数据、路由选择及防降级判断。
/// - **核心优势**：在初始化时自动静默清理 Windows 旧副本锁残留，状态内聚且无全局可变状态污染。
/// - **代价与局限**：实例不可变借用，配置在构建完成后不可动态篡改。
#[derive(Debug)]
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
}

struct UpdaterInner {
    current_version: Version,
    endpoints: Vec<String>,
    channel: Option<String>,
    target: String,
    allow_downgrade: bool,
    config: Arc<NetworkSecurityConfig>,
    version_comparator: Option<VersionComparator>,
    preference: Mutex<UpdatePreference>,
    preference_path: Option<PathBuf>,
}

impl std::fmt::Debug for UpdaterInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdaterInner")
            .field("current_version", &self.current_version)
            .field("endpoints", &self.endpoints)
            .field("channel", &self.channel)
            .field("target", &self.target)
            .field("allow_downgrade", &self.allow_downgrade)
            .field("config", &self.config)
            .field(
                "has_custom_version_comparator",
                &self.version_comparator.is_some(),
            )
            .field("preference_path", &self.preference_path)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct Updater {
    inner: Arc<UpdaterInner>,
}

impl Updater {
    /// 获取 UpdaterBuilder 构建器入口
    pub fn builder() -> UpdaterBuilder {
        UpdaterBuilder::new()
    }

    /// 获取配置的更新检查端点列表切片
    pub fn endpoints(&self) -> &[String] {
        &self.inner.endpoints
    }

    /// 标记跳过特定版本升级提醒并持久化
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

    /// 撤销对特定版本的跳过标记并持久化
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

    /// 设置稍后提醒（在指定时间内静默忽略非强制更新提醒）并持久化
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

    /// 清空所有用户偏好（跳过版本与稍后提醒）并持久化
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
            } else {
                cleanup_old_backups();
            }
        } else {
            // 默认构造器保持纯净无副作用，仅清理历史备份锁残留
            cleanup_old_backups();
        }

        let preference_path = config
            .preference_path
            .or_else(preference::default_preference_file_path);
        let preference = if let Some(ref path) = preference_path {
            UpdatePreference::load_from_file(path)
        } else {
            UpdatePreference::default()
        };

        Self {
            inner: Arc::new(UpdaterInner {
                current_version: config.current_version,
                endpoints: config.endpoints,
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
                }),
                version_comparator: config.version_comparator,
                preference: Mutex::new(preference),
                preference_path,
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
        let client = build_blocking_http_client(
            self.inner.config.timeout,
            self.inner.config.user_agent.as_deref(),
            &self.inner.config.headers,
            self.inner.config.proxy.as_deref(),
        )?;

        let template_ctx = TemplateContext {
            target: &self.inner.target,
            current_version: &self.inner.current_version,
            channel: self.inner.channel.as_deref(),
        };

        let mut last_error = None;
        for (idx, raw_endpoint) in self.inner.endpoints.iter().enumerate() {
            let endpoint = resolve_url_template(raw_endpoint, &template_ctx);
            log::info!(
                "发起更新检查端点 [{}/{}]: {}",
                idx + 1,
                self.inner.endpoints.len(),
                endpoint
            );

            match fetch_manifest_blocking(&client, &endpoint) {
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
        let client = build_async_http_client(
            self.inner.config.timeout,
            self.inner.config.user_agent.as_deref(),
            &self.inner.config.headers,
            self.inner.config.proxy.as_deref(),
        )?;

        let template_ctx = TemplateContext {
            target: &self.inner.target,
            current_version: &self.inner.current_version,
            channel: self.inner.channel.as_deref(),
        };

        let mut last_error = None;
        for (idx, raw_endpoint) in self.inner.endpoints.iter().enumerate() {
            let endpoint = resolve_url_template(raw_endpoint, &template_ctx);
            log::info!(
                "发起异步更新检查端点 [{}/{}]: {}",
                idx + 1,
                self.inner.endpoints.len(),
                endpoint
            );

            match fetch_manifest_async(&client, &endpoint).await {
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

        Err(last_error.unwrap_or_else(|| {
            UpdateError::Network("所有配置的更新源端点均无法连接访问".to_string())
        }))
    }

    /// 解析并评估 Manifest 版本信息
    fn evaluate_manifest(&self, manifest_json: &str) -> Result<Option<Update>> {
        let manifest = Manifest::from_json_str(manifest_json)?;
        let options = ResolveOptions {
            channel: self.inner.channel.as_deref(),
            target: &self.inner.target,
            current_version: &self.inner.current_version,
        };
        let release = manifest.resolve(&options)?;

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
    /// # Errors
    /// 当派生操作系统线程失败时返回 [`std::io::Error`]。
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
            && self.release.package.url.starts_with("http://")
        {
            return Err(UpdateError::InsecureTransportProtocol(
                self.release.package.url.clone(),
            ));
        }

        let client = build_blocking_http_client(
            self.config.timeout,
            self.config.user_agent.as_deref(),
            &self.config.headers,
            self.config.proxy.as_deref(),
        )?;

        let temp_download_path =
            get_temp_download_path(self.release.package.package_type, &self.release.package.url)?;
        let options = DownloadOptions {
            url: &self.release.package.url,
            target_path: &temp_download_path,
            cancel_flag,
            max_retries: self.config.max_retries,
            retry_delay: self.config.retry_delay,
            expected_checksum: self.release.package.checksum.as_deref(),
        };

        download::download_file_blocking(&client, &options, &mut callback)?;
        self.verify_downloaded_payload(&temp_download_path, &mut callback)?;

        Ok(DownloadedUpdate {
            current_version: self.current_version.clone(),
            release: self.release.clone(),
            downloaded_path: temp_download_path,
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
            && self.release.package.url.starts_with("http://")
        {
            return Err(UpdateError::InsecureTransportProtocol(
                self.release.package.url.clone(),
            ));
        }

        let client = build_async_http_client(
            self.config.timeout,
            self.config.user_agent.as_deref(),
            &self.config.headers,
            self.config.proxy.as_deref(),
        )?;

        let temp_download_path =
            get_temp_download_path(self.release.package.package_type, &self.release.package.url)?;
        let options = DownloadOptions {
            url: &self.release.package.url,
            target_path: &temp_download_path,
            cancel_flag,
            max_retries: self.config.max_retries,
            retry_delay: self.config.retry_delay,
            expected_checksum: self.release.package.checksum.as_deref(),
        };

        download::download_file_async(&client, &options, &mut callback).await?;

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

        Ok(DownloadedUpdate {
            current_version: self.current_version.clone(),
            release: self.release.clone(),
            downloaded_path: temp_download_path,
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

        if self.config.require_signature {
            callback(UpdateEvent::VerifyingSignature);
            if self.config.public_keys.is_empty() {
                return Err(UpdateError::MissingPublicKey);
            }
            let sig = self.release.package.signature.as_deref().ok_or_else(|| {
                let _ = fs::remove_file(temp_path);
                UpdateError::MissingSignature
            })?;
            if let Err(e) = verify_ed25519_file_any_key(temp_path, sig, &self.config.public_keys) {
                let _ = fs::remove_file(temp_path);
                return Err(e);
            }
        } else if !self.config.public_keys.is_empty() {
            callback(UpdateEvent::VerifyingSignature);
            match self.release.package.signature {
                Some(ref sig) => {
                    if let Err(e) =
                        verify_ed25519_file_any_key(temp_path, sig, &self.config.public_keys)
                    {
                        let _ = fs::remove_file(temp_path);
                        return Err(e);
                    }
                }
                None => {
                    let _ = fs::remove_file(temp_path);
                    return Err(UpdateError::MissingSignature);
                }
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
}

impl DownloadedUpdate {
    /// 获取当前本地版本
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }

    /// 获取目标新版本
    pub fn version(&self) -> &Version {
        &self.release.version
    }

    /// 获取已下载并验签完毕的本地文件物理路径
    pub fn downloaded_path(&self) -> &Path {
        &self.downloaded_path
    }

    /// 获取解析后的版本元数据引用
    pub fn release(&self) -> &ResolvedRelease {
        &self.release
    }

    /// 执行物理安装、解压替换或派生拉起外部安装器
    ///
    /// # Errors
    /// 当解压、二进制替换或安装器派生失败时返回对应错误。
    pub fn install<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        apply_downloaded_payload(&self.release, &self.downloaded_path, &mut callback)
    }
}

fn apply_downloaded_payload<F>(
    release: &ResolvedRelease,
    temp_path: &Path,
    callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    match release.package.package_type {
        PackageType::Binary => {
            callback(UpdateEvent::Installing);
            replace_binary(temp_path)?;
            let _ = fs::remove_file(temp_path);
            record_state_if_possible(&release.version);
            callback(UpdateEvent::ReadyToRestart);
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

            let apply_result = (|| -> Result<()> {
                let extracted_binary = extract_archive(
                    temp_path,
                    &sandbox_dir,
                    release.package.executable_path.as_deref(),
                )?;

                callback(UpdateEvent::Installing);

                // 同步解压目录中除主程序外的全部伴随依赖（动态库、静态资源等）到宿主应用目录
                let current_exe = std::env::current_exe()?;
                if let Some(target_dir) = current_exe.parent() {
                    let payload_dir = extracted_binary.parent().unwrap_or(&sandbox_dir);
                    sync_extracted_payload(payload_dir, target_dir, &extracted_binary)?;
                }

                replace_binary(&extracted_binary)?;
                Ok(())
            })();

            let _ = fs::remove_dir_all(&sandbox_dir);
            let _ = fs::remove_file(temp_path);
            apply_result?;

            record_state_if_possible(&release.version);
            callback(UpdateEvent::ReadyToRestart);
        }
        PackageType::Installer => {
            callback(UpdateEvent::Installing);
            let installer_options = InstallerOptions {
                user_args: &release.package.install_args,
                install_mode: release.package.install_mode,
                require_elevation: release.package.require_elevation,
            };
            spawn_installer(temp_path, &installer_options)?;
            callback(UpdateEvent::ReadyToRestart);
        }
    }

    Ok(())
}

fn record_state_if_possible(target_version: &Version) {
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(target_dir) = current_exe.parent()
    {
        let backup_path = target_dir.join(format!(
            "{}.shipup.old",
            current_exe
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ));
        let _ = crate::recovery::record_update_state(
            target_dir,
            &target_version.to_string(),
            &backup_path,
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
) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder().timeout(timeout);
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
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
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

        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .target("x86_64-pc-windows-msvc")
            .manifest_url("https://example.com/manifest.json")
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
                signature: None,
                checksum: None,
                package_type: PackageType::Binary,
                install_mode: None,
                install_args: vec![],
                executable_path: None,
                require_elevation: false,
            },
        };

        let temp_path = PathBuf::from("C:\\temp\\app.exe.shipup.tmp");
        let downloaded = DownloadedUpdate {
            current_version: Version::parse("1.0.0").unwrap(),
            release,
            downloaded_path: temp_path.clone(),
        };

        assert_eq!(downloaded.version(), &Version::parse("1.2.0").unwrap());
        assert_eq!(
            downloaded.current_version(),
            &Version::parse("1.0.0").unwrap()
        );
        assert_eq!(downloaded.downloaded_path(), temp_path.as_path());
    }
}
