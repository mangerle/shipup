#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

// shipup 跨平台自更新系统 - Updater 与 Update 核心交互实体

use crate::archive::{extract_archive, sync_extracted_payload};
use crate::builder::{UpdaterBuilder, UpdaterConfig};
use crate::download::{self, DownloadOptions};
use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use crate::manifest::{Manifest, PackageType, ResolveOptions, ResolvedRelease};
use crate::platform::{
    cleanup_old_backups, get_temp_download_path, replace_binary, spawn_installer,
};
use crate::restart::{RestartContext, restart_with};
use crate::signature::{verify_ed25519_file, verify_sha256_file};
use semver::Version;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
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
    pub public_key: Option<String>,
    pub timeout: Duration,
    pub user_agent: Option<String>,
    pub headers: HashMap<String, String>,
    pub proxy: Option<String>,
    pub max_retries: u32,
    pub retry_delay: Duration,
    pub dangerous_insecure_transport_protocol: bool,
    pub require_signature: bool,
}

#[derive(Debug)]
struct UpdaterInner {
    current_version: Version,
    manifest_url: String,
    channel: Option<String>,
    target: String,
    allow_downgrade: bool,
    config: Arc<NetworkSecurityConfig>,
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

        Self {
            inner: Arc::new(UpdaterInner {
                current_version: config.current_version,
                manifest_url: config.manifest_url,
                channel: config.channel,
                target: config.target,
                allow_downgrade: config.allow_downgrade,
                config: Arc::new(NetworkSecurityConfig {
                    public_key: config.public_key,
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
            }),
        }
    }

    #[cfg(feature = "blocking")]
    /// 同步阻塞检查是否有可用更新
    ///
    /// # 设计原理
    /// - **实现初衷**：在单次调用中完成 HTTP 请求与 Manifest 评估，适合在后台线程直接运行。
    ///
    /// # Errors
    /// 当网络请求失败、HTTP 响应非 2xx 或 JSON 反序列化失败时返回对应错误。
    pub fn check(&self) -> Result<Option<Update>> {
        log::info!(
            "正在发起同步更新检查，远端地址: {}",
            self.inner.manifest_url
        );
        let client = build_blocking_http_client(
            self.inner.config.timeout,
            self.inner.config.user_agent.as_deref(),
            &self.inner.config.headers,
            self.inner.config.proxy.as_deref(),
        )?;

        let response = client
            .get(&self.inner.manifest_url)
            .send()
            .map_err(|e| UpdateError::Network(format!("获取 Manifest 失败: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(UpdateError::HttpStatus {
                status_code: status.as_u16(),
                message: format!("请求 Manifest 返回异常状态码: {}", status),
            });
        }

        let body = response
            .text()
            .map_err(|e| UpdateError::Network(format!("读取 Manifest 响应失败: {}", e)))?;

        self.evaluate_manifest(&body)
    }

    #[cfg(feature = "async")]
    /// 异步检查是否有可用更新
    ///
    /// # 设计原理
    /// - **实现初衷**：契合 Tokio 异步运行时，无需派生额外线程即可非阻塞拉取远端 Manifest。
    ///
    /// # Errors
    /// 当异步网络请求失败或 Manifest 解析错误时返回相应错误。
    pub async fn check_async(&self) -> Result<Option<Update>> {
        log::info!(
            "正在发起异步更新检查，远端地址: {}",
            self.inner.manifest_url
        );
        let client = build_async_http_client(
            self.inner.config.timeout,
            self.inner.config.user_agent.as_deref(),
            &self.inner.config.headers,
            self.inner.config.proxy.as_deref(),
        )?;

        let response = client
            .get(&self.inner.manifest_url)
            .send()
            .await
            .map_err(|e| UpdateError::Network(format!("异步获取 Manifest 失败: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(UpdateError::HttpStatus {
                status_code: status.as_u16(),
                message: format!("请求 Manifest 返回异常状态码: {}", status),
            });
        }

        let body = response
            .text()
            .await
            .map_err(|e| UpdateError::Network(format!("异步读取 Manifest 响应失败: {}", e)))?;

        self.evaluate_manifest(&body)
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

        if !self.inner.allow_downgrade && release.version <= self.inner.current_version {
            log::info!(
                "远端版本 ({}) 未高于本地当前版本 ({})，忽略更新",
                release.version,
                self.inner.current_version
            );
            return Ok(None);
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
    /// 同步下载并完成更新安装
    ///
    /// # Errors
    /// 下载、验签、解压或安装失败时返回对应错误。
    pub fn download_and_install<F>(&self, callback: F) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        self.download_and_install_with_cancellation(None, callback)
    }

    #[cfg(feature = "blocking")]
    /// 支持主动取消标记的同步下载与安装
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
        self.verify_and_apply(&temp_download_path, callback)
    }

    #[cfg(feature = "async")]
    /// 异步下载并完成更新安装
    ///
    /// # Errors
    /// 当异步流程失败时返回对应错误。
    pub async fn download_and_install_async<F>(&self, callback: F) -> Result<()>
    where
        F: FnMut(UpdateEvent) + Send,
    {
        self.download_and_install_with_cancellation_async(None, callback)
            .await
    }

    #[cfg(feature = "async")]
    /// 支持主动取消标记的异步下载与安装
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
            this.verify_and_apply(&target_temp_path, |event| {
                let _ = tx.send(event);
            })
        });

        while let Some(event) = rx.recv().await {
            callback(event);
        }

        match blocking_handle.await {
            Ok(res) => res,
            Err(join_err) => Err(UpdateError::SelfReplace(format!(
                "后台安装验证任务异常中止: {}",
                join_err
            ))),
        }
    }

    fn verify_and_apply<F>(&self, temp_path: &Path, mut callback: F) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        self.verify_downloaded_payload(temp_path, &mut callback)?;
        self.apply_downloaded_payload(temp_path, &mut callback)?;
        Ok(())
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
            let pub_key = self
                .config
                .public_key
                .as_deref()
                .ok_or(UpdateError::MissingPublicKey)?;
            let sig = self.release.package.signature.as_deref().ok_or_else(|| {
                let _ = fs::remove_file(temp_path);
                UpdateError::MissingSignature
            })?;
            if let Err(e) = verify_ed25519_file(temp_path, sig, pub_key) {
                let _ = fs::remove_file(temp_path);
                return Err(e);
            }
        } else if let Some(ref pub_key) = self.config.public_key {
            callback(UpdateEvent::VerifyingSignature);
            match self.release.package.signature {
                Some(ref sig) => {
                    if let Err(e) = verify_ed25519_file(temp_path, sig, pub_key) {
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

    fn apply_downloaded_payload<F>(&self, temp_path: &Path, callback: &mut F) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        match self.release.package.package_type {
            PackageType::Binary => {
                callback(UpdateEvent::Installing);
                replace_binary(temp_path)?;
                let _ = fs::remove_file(temp_path);
                self.record_state_if_possible();
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
                        self.release.package.executable_path.as_deref(),
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

                self.record_state_if_possible();
                callback(UpdateEvent::ReadyToRestart);
            }
            PackageType::Installer => {
                callback(UpdateEvent::Installing);
                spawn_installer(
                    temp_path,
                    &self.release.package.install_args,
                    self.release.package.require_elevation,
                )?;
                callback(UpdateEvent::ReadyToRestart);
            }
        }

        Ok(())
    }

    fn record_state_if_possible(&self) {
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
                &self.release.version.to_string(),
                &backup_path,
            );
        }
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
