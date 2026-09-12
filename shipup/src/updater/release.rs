//! 已确认更新实体的下载、验签与安装模块。
//!
//! # 模块职责
//! 定义两阶段更新生命周期的核心载体：
//! - [`Update`]：一个已被通道与平台路由鉴权确认「确实可用」的新版本，负责网络下载与密码学校验；
//! - [`DownloadedUpdate`]：一个已通过 SHA-256 与 Ed25519 校验的本地暂存包，负责物理安装与显式清理。
//!
//! # 设计原理
//! - **实现初衷**：把更新流程严格切分为「网络下载与验签」和「物理文件替换」两个阶段，
//!   使宿主可以先在后台静默预载更新包，再于用户空闲或显式确认时执行安装。
//! - **核心优势**：`Update` 只能由 [`crate::Updater`] 在真正发现新版本时构造，
//!   从类型系统层面排除了「对最新版本执行下载」的非法调用；`DownloadedUpdate` 则强制携带
//!   已验签的物理路径，杜绝「未校验即安装」的路径。
//! - **代价与局限**：更新包在安装前暂存于操作系统临时目录，需调用方在放弃安装时主动
//!   [`DownloadedUpdate::cleanup`]，以避免磁盘残留。
//!
//! # 特性门控
//! 下载相关方法按 `blocking` / `async` 特性分别提供同步与异步两套入口；
//! 安装与清理方法与特性无关，始终保持可用。

#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

use crate::config::is_insecure_http_url;
use crate::download::{self, DownloadOptions};
use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use crate::manifest::{PackageType, ResolvedRelease};
use crate::platform::{get_resumable_download_path, get_temp_download_path};
use crate::restart::{RestartContext, restart_with};
use crate::signature::{verify_ed25519_file_threshold, verify_sha256_file};
use crate::updater::config::NetworkSecurityConfig;
use crate::updater::install::PayloadApplyContext;
use semver::Version;
use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[cfg(any(feature = "blocking", feature = "async"))]
use crate::updater::http::HttpClientOptions;
#[cfg(feature = "async")]
use crate::updater::http::build_async_http_client;
#[cfg(feature = "blocking")]
use crate::updater::http::build_blocking_http_client;

/// 表示已确认可用的新版本更新对象
///
/// # 设计原理
/// - **实现初衷**：代表已通过通道与平台路由鉴权确认可用的新版本，封装后续的下载校验、归档解压与部署替换。
/// - **核心优势**：保证只有在真正存在新版本时才能持有该对象，从类型系统上排除对“最新版本”执行下载的非法调用。
#[derive(Debug, Clone)]
pub struct Update {
    pub(super) current_version: Version,
    pub(super) release: ResolvedRelease,
    pub(super) config: Arc<NetworkSecurityConfig>,
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
        self.validate_package_transport()?;

        let client =
            build_blocking_http_client(&HttpClientOptions::from_network_config(&self.config))?;
        let temp_download_path = self.resolve_download_path()?;
        let options = self.build_download_options(&temp_download_path, cancel_flag);
        let mirrors = self.merge_download_mirrors();

        if let Err(e) = self.download_and_verify_blocking(
            &client,
            &options,
            &mirrors,
            &temp_download_path,
            &mut callback,
        ) {
            callback(UpdateEvent::Failed {
                reason: e.to_string(),
            });
            return Err(e);
        }

        Ok(self.build_downloaded_update(temp_download_path))
    }

    /// 校验更新包传输协议是否满足安全策略（禁止明文 HTTP 与未授权 file:// 协议）
    ///
    /// # Errors
    /// 当端点为明文 HTTP 或 file:// 协议且未被显式放行时返回对应错误。
    fn validate_package_transport(&self) -> Result<()> {
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

        Ok(())
    }

    /// 基于网络配置与暂存路径组装下载参数对象
    fn build_download_options<'a>(
        &'a self,
        temp_path: &'a Path,
        cancel_flag: Option<Arc<AtomicBool>>,
    ) -> DownloadOptions<'a> {
        DownloadOptions {
            url: &self.release.package.url,
            target_path: temp_path,
            cancel_flag,
            max_retries: self.config.max_retries,
            retry_delay: self.config.retry_delay,
            expected_checksum: self.release.package.checksum.as_deref(),
            expected_size: self.release.package.size,
            max_bytes_per_sec: self.config.max_bytes_per_sec,
        }
    }

    /// 合并清单自带镜像与全局配置镜像，去重后形成最终镜像列表
    fn merge_download_mirrors(&self) -> Vec<String> {
        let mut mirrors = self.release.package.mirrors.clone();
        for m in &self.config.download_mirrors {
            if !mirrors.contains(m) {
                mirrors.push(m.clone());
            }
        }
        mirrors
    }

    /// 构造已通过校验的待安装更新实体
    fn build_downloaded_update(&self, downloaded_path: PathBuf) -> DownloadedUpdate {
        DownloadedUpdate {
            current_version: self.current_version.clone(),
            release: self.release.clone(),
            downloaded_path,
            max_rollback_entries: self.config.max_rollback_entries,
            allow_reboot_deferred_replace: self.config.allow_reboot_deferred_replace,
        }
    }

    /// 同步执行下载（整包或分片）并对暂存文件完成完整性与签名校验
    ///
    /// # Errors
    /// 下载失败或哈希/签名校验不通过时返回对应错误。
    #[cfg(feature = "blocking")]
    fn download_and_verify_blocking<F>(
        &self,
        client: &reqwest::blocking::Client,
        options: &DownloadOptions<'_>,
        mirrors: &[String],
        temp_path: &Path,
        callback: &mut F,
    ) -> Result<()>
    where
        F: FnMut(UpdateEvent),
    {
        if self.config.chunked_download {
            let chunked_opts = download::ChunkedDownloadOptions {
                base: options.clone(),
                mirrors,
                concurrency: self.config.chunked_concurrency,
                chunk_size: self.config.chunk_size,
            };
            download::download_file_chunked_blocking(client, &chunked_opts, &mut *callback)?;
        } else {
            download::download_file_blocking(client, options, &mut *callback)?;
        }
        self.verify_downloaded_payload(temp_path, callback)
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
        self.validate_package_transport()?;

        let client =
            build_async_http_client(&HttpClientOptions::from_network_config(&self.config))?;
        let temp_download_path = self.resolve_download_path()?;
        let options = self.build_download_options(&temp_download_path, cancel_flag);
        let mirrors = self.merge_download_mirrors();

        let download_and_verify_result = self
            .download_and_verify_async(
                &client,
                &options,
                &mirrors,
                &temp_download_path,
                &mut callback,
            )
            .await;

        if let Err(e) = download_and_verify_result {
            callback(UpdateEvent::Failed {
                reason: e.to_string(),
            });
            return Err(e);
        }

        Ok(self.build_downloaded_update(temp_download_path))
    }

    /// 异步执行下载（整包或分片），并将阻塞型验签调度至专用线程池
    ///
    /// # Errors
    /// 下载失败、哈希/签名校验不通过或验签任务异常中止时返回对应错误。
    #[cfg(feature = "async")]
    async fn download_and_verify_async<F>(
        &self,
        client: &reqwest::Client,
        options: &DownloadOptions<'_>,
        mirrors: &[String],
        temp_path: &Path,
        callback: &mut F,
    ) -> Result<()>
    where
        F: FnMut(UpdateEvent) + Send,
    {
        if self.config.chunked_download {
            let chunked_opts = download::ChunkedDownloadOptions {
                base: options.clone(),
                mirrors,
                concurrency: self.config.chunked_concurrency,
                chunk_size: self.config.chunk_size,
            };
            download::download_file_chunked_async(client, &chunked_opts, &mut *callback).await?;
        } else {
            download::download_file_async(client, options, &mut *callback).await?;
        }

        self.verify_payload_on_blocking_pool(temp_path, callback)
            .await
    }

    /// 将阻塞型哈希与签名校验调度至阻塞线程池，并把事件经通道桥接回异步回调
    ///
    /// # Errors
    /// 校验失败时返回对应错误；验签任务异常中止时返回 [`UpdateError::SelfReplace`]。
    #[cfg(feature = "async")]
    async fn verify_payload_on_blocking_pool<F>(
        &self,
        temp_path: &Path,
        callback: &mut F,
    ) -> Result<()>
    where
        F: FnMut(UpdateEvent) + Send,
    {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let this = self.clone();
        let target_temp_path = temp_path.to_path_buf();

        let blocking_handle = tokio::task::spawn_blocking(move || {
            this.verify_downloaded_payload(&target_temp_path, &mut |event| {
                let _ = tx.send(event);
            })
        });

        while let Some(event) = rx.recv().await {
            callback(event);
        }

        match blocking_handle.await {
            Ok(res) => res,
            Err(join_err) => Err(UpdateError::SelfReplace(format!(
                "后台签名校验任务异常中止: {}",
                join_err
            ))),
        }
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

    /// 对已下载到本地暂存路径的更新包执行完整性哈希与数字签名双重校验。
    ///
    /// 校验策略为「从严」：只要开启了 `require_signature` **或** 配置了任意验签公钥，
    /// 就必须强制走 Ed25519 校验，绝不会因为显式传入 `require_signature(false)` 而放行未签名包体
    /// （防止调用方误配置导致安全防线被静默关闭）。
    /// 任一步校验失败都会立即删除本地暂存文件，避免损坏包体被后续流程复用。
    ///
    /// # Errors
    /// - 哈希不匹配：[`UpdateError::ChecksumMismatch`]；
    /// - 强制验签但未配置公钥：[`UpdateError::MissingPublicKey`]；
    /// - 强制验签但包体无签名：[`UpdateError::MissingSignature`]；
    /// - 签名验证不通过：[`UpdateError::InvalidSignature`]。
    pub(super) fn verify_downloaded_payload<F>(
        &self,
        temp_path: &Path,
        callback: &mut F,
    ) -> Result<()>
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
    pub(super) current_version: Version,
    pub(super) release: ResolvedRelease,
    pub(super) downloaded_path: PathBuf,
    pub(super) max_rollback_entries: usize,
    pub(super) allow_reboot_deferred_replace: bool,
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
        // 使用独立作用域承载参数对象，使回调的可变借用在此处确定性结束，
        // 便于下方在成功/失败分支中再次使用同一个回调派发终态事件。
        let apply_result = {
            let mut ctx = PayloadApplyContext {
                current_version: &self.current_version,
                release: &self.release,
                temp_path: &self.downloaded_path,
                max_rollback_entries: self.max_rollback_entries,
                allow_reboot_deferred_replace: self.allow_reboot_deferred_replace,
                callback: &mut callback,
            };
            ctx.apply()
        };

        match apply_result {
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
