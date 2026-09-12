//! 更新检查与版本评估模块。
//!
//! # 模块职责
//! 承载 [`crate::Updater`] 的「发现」阶段：多端点故障转移、Happy Eyeballs 并发竞速、
//! Manifest 时效与真伪校验、版本裁决、灰度放量分桶以及后台轮询任务派生。
//!
//! # 设计原理
//! - **实现初衷**：检查阶段的决策维度很多（端点可用性、清单时效、版本单调性、用户偏好、灰度比例），
//!   若与下载安装逻辑混在一起会形成「上帝方法」。本模块把评估链路拆为
//!   `check`（取回原始文本）→ `evaluate_manifest`（解析）→ `evaluate_manifest_struct`（裁决）三层，
//!   使每一层都可被单独测试与替换。
//! - **核心优势**：同步与异步两条链路复用完全相同的裁决逻辑（`evaluate_manifest`），
//!   杜绝「同步修复了、异步忘了改」的双份维护陷阱。
//! - **代价与局限**：竞速模式在端点全部可达时会产生少量冗余探测流量。
//!
//! # 安全契约
//! 评估顺序对安全至关重要，不可随意调整：先校验清单时效（防重放），再校验清单自身门限签名（防伪造），
//! 然后校验版本序号单调性（防版本逆向回滚），最后才进入版本比较与灰度裁决。
//!
//! # 特性门控
//! `check` / `check_endpoints_racing_blocking` 依赖 `blocking`；
//! `check_async` / `check_endpoints_racing_async` 依赖 `async`。
//!
//! [`crate::Updater`]: super::Updater

#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

use crate::download;
use crate::error::{Result, UpdateError};
use crate::manifest::{Manifest, ResolveOptions, ResolvedRelease};
use crate::template::{TemplateContext, resolve_url_template};
use crate::updater::{Update, Updater};
use semver::Version;
use std::sync::Arc;

#[cfg(feature = "blocking")]
use std::fs;

#[cfg(feature = "async")]
use crate::updater::http::{build_async_http_client, fetch_manifest_async};
#[cfg(feature = "blocking")]
use crate::updater::http::{build_blocking_http_client, fetch_manifest_blocking};

impl Updater {
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

            let fetch_result = self.fetch_endpoint_blocking(&client, &endpoint);

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

            let fetch_result = self.fetch_endpoint_async(&client, &endpoint).await;

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

                let eval_res = updater
                    .fetch_endpoint_blocking(&client_cloned, &endpoint)
                    .and_then(|body| updater.evaluate_manifest(&body));

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
            let tx_cloned = tx.clone();
            let updater = self.clone();

            let handle = tokio::spawn(async move {
                if !stagger.is_zero() {
                    tokio::time::sleep(stagger).await;
                }

                let eval_res = match updater
                    .fetch_endpoint_async(&client_cloned, &endpoint)
                    .await
                {
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
    pub(super) fn evaluate_manifest(&self, manifest_json: &str) -> Result<Option<Update>> {
        let manifest = Manifest::from_json_str(manifest_json)?;
        self.evaluate_manifest_struct(&manifest)
    }

    #[cfg(feature = "blocking")]
    /// 同步抓取单个端点的 Manifest 原始文本，并统一施加 `file://` 协议安全门禁。
    ///
    /// # 设计原理
    /// - **实现初衷**：`check` 与多端点竞速两条链路都需要「按端点协议选择抓取方式」这一决策，
    ///   若各自实现一份，极易出现「竞速路径漏做了 `file://` 门禁校验」这类安全缺口。
    /// - **核心优势**：协议判定、门禁校验与抓取动作收敛为单一入口，
    ///   同步与异步版本只差运行时，语义完全对齐。
    ///
    /// # Errors
    /// - 端点使用 `file://` 但未开启 `allow_file_protocol`：[`UpdateError::FileProtocolNotAllowed`]；
    /// - `file://` 端点解析为本地路径失败：[`UpdateError`]；
    /// - 网络抓取或本地读取失败：[`UpdateError::Network`] / [`UpdateError::Io`]。
    fn fetch_endpoint_blocking(
        &self,
        client: &reqwest::blocking::Client,
        endpoint: &str,
    ) -> Result<String> {
        if !download::is_file_url(endpoint) {
            return fetch_manifest_blocking(client, endpoint);
        }
        if !self.inner.config.allow_file_protocol {
            return Err(UpdateError::FileProtocolNotAllowed(endpoint.to_string()));
        }
        let path = download::parse_file_url_to_path(endpoint)?;
        fs::read_to_string(&path).map_err(UpdateError::Io)
    }

    #[cfg(feature = "async")]
    /// 异步抓取单个端点的 Manifest 原始文本，语义与 [`Self::fetch_endpoint_blocking`] 完全一致。
    ///
    /// # Errors
    /// 与同步版本相同，仅底层 I/O 由阻塞调用改为异步等待。
    async fn fetch_endpoint_async(
        &self,
        client: &reqwest::Client,
        endpoint: &str,
    ) -> Result<String> {
        if !download::is_file_url(endpoint) {
            return fetch_manifest_async(client, endpoint).await;
        }
        if !self.inner.config.allow_file_protocol {
            return Err(UpdateError::FileProtocolNotAllowed(endpoint.to_string()));
        }
        let path = download::parse_file_url_to_path(endpoint)?;
        tokio::fs::read_to_string(&path)
            .await
            .map_err(UpdateError::Io)
    }

    /// 针对 Manifest 实体结构执行验签与版本评估。
    ///
    /// # 设计原理
    /// - **实现初衷**：检查阶段需要串联「时效校验 → 真伪校验 → 版本单调性 → 版本裁决 →
    ///   用户偏好过滤 → 灰度放量」六个判定环节，若全部平铺在一个方法体内，
    ///   任意环节的顺序调整都难以被审查发现，而顺序恰恰是安全性的关键。
    /// - **核心优势**：把每个环节提取为语义明确的独立判定方法，
    ///   主流程退化为一条可读的「安全流水线」，顺序即文档。
    /// - **代价与局限**：判定方法较多，跨方法阅读时需要在文件内跳转。
    ///
    /// # 判定顺序契约（不可调整）
    /// 1. [`Self::verify_manifest_authenticity`]：先确认清单未过期且来源可信；
    /// 2. [`Self::enforce_version_seq_monotonicity`]：确认清单序号未倒退；
    /// 3. 版本裁决与偏好过滤：仅在清单已被信任后才有意义。
    fn evaluate_manifest_struct(&self, manifest: &Manifest) -> Result<Option<Update>> {
        self.verify_manifest_authenticity(manifest)?;
        self.enforce_version_seq_monotonicity(manifest)?;

        let options = ResolveOptions {
            channel: self.inner.channel.as_deref(),
            target: &self.inner.target,
            current_version: &self.inner.current_version,
        };
        let mut release = manifest.resolve(&options)?;
        self.expand_relative_offline_package_url(&mut release);

        if !self.is_release_available(&release.version) {
            log::info!(
                "根据版本策略评估，远端版本 ({}) 无需更新（本地当前版本: {}）",
                release.version,
                self.inner.current_version
            );
            return Ok(None);
        }

        if self.is_suppressed_by_preference(&release) {
            return Ok(None);
        }

        if !self.is_release_within_rollout(&release) {
            return Ok(None);
        }

        log::info!("发现可用更新版本: {}", release.version);
        Ok(Some(Update {
            current_version: self.inner.current_version.clone(),
            release,
            config: Arc::clone(&self.inner.config),
        }))
    }

    /// 校验清单时效性与清单自身的门限数字签名，抵御过期重放与伪造清单。
    ///
    /// # Errors
    /// - 清单已过期：[`UpdateError::ManifestExpired`]；
    /// - 清单门限签名不足或校验失败：[`UpdateError::InvalidSignature`]。
    fn verify_manifest_authenticity(&self, manifest: &Manifest) -> Result<()> {
        // 1. 校验 Manifest 有效期限，防范过期清单重放攻击
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        manifest.verify_freshness(now_unix)?;

        // 2. 校验 Manifest 清单自身数字签名
        if self.inner.config.public_keys.is_empty() {
            return Ok(());
        }
        if manifest.all_signatures().is_empty() {
            if self.inner.config.require_signature {
                log::debug!("当前 Manifest 未附带根级数字签名，将严格依赖后续安装包体级数字签名");
            }
            return Ok(());
        }
        manifest.verify_signatures_threshold(
            &self.inner.config.public_keys,
            self.inner.config.signature_threshold,
        )?;
        log::info!(
            "更新源 Manifest 清单自身 TUF 门限数字签名防伪验证通过 (门限: {})",
            self.inner.config.signature_threshold
        );
        Ok(())
    }

    /// 校验清单版本序号单调递增，并把新的高水位序号持久化到用户偏好。
    ///
    /// # Errors
    /// 当远端序号小于本地已记录的高水位时返回 [`UpdateError::StaleManifestVersion`]，
    /// 用于抵御攻击者重放旧清单诱导版本逆向回滚。
    fn enforce_version_seq_monotonicity(&self, manifest: &Manifest) -> Result<()> {
        let Some(remote_seq) = manifest.version_seq else {
            return Ok(());
        };
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
        if pref.last_version_seq().is_none_or(|curr| remote_seq > curr) {
            pref.record_version_seq(remote_seq);
            if let Some(ref path) = self.inner.preference_path {
                let _ = pref.save_to_file(path);
            }
        }
        Ok(())
    }

    /// 当包体地址为相对路径、且当前清单来自本地 `file://` 端点时，把其展开为绝对 `file://` URL。
    ///
    /// # 设计原理
    /// - **实现初衷**：离线仓库的清单通常以相对路径引用同目录下的安装包，便于整个目录整体搬迁，
    ///   但下载引擎只接受可直接访问的绝对地址。
    /// - **容错策略**：展开失败时保留原始相对路径不做处理，
    ///   交由后续下载阶段给出更贴切的错误，避免在此处提前中断整条检查流程。
    fn expand_relative_offline_package_url(&self, release: &mut ResolvedRelease) {
        if release.package.url.contains("://") {
            return;
        }
        let Some(endpoint) = self.inner.endpoints.first() else {
            return;
        };
        if !crate::offline::is_file_protocol(endpoint) {
            return;
        }
        if let Ok(resolved_url) =
            crate::offline::resolve_relative_file_url(endpoint, &release.package.url)
        {
            release.package.url = resolved_url;
        }
    }

    /// 依据版本比较策略判定远端版本是否构成「可用更新」。
    ///
    /// 策略优先级为：自定义比较器 > 允许降级（任意不同即视为可用）> 默认严格升序。
    fn is_release_available(&self, remote: &Version) -> bool {
        if let Some(ref comparator) = self.inner.version_comparator {
            comparator(&self.inner.current_version, remote)
        } else if self.inner.allow_downgrade {
            *remote != self.inner.current_version
        } else {
            *remote > self.inner.current_version
        }
    }

    /// 判定该版本是否被用户偏好（跳过版本 / 稍后提醒）压制而应放弃提示。
    ///
    /// 强制更新（`force_update`）不受任何偏好限制，必须始终放行。
    fn is_suppressed_by_preference(&self, release: &ResolvedRelease) -> bool {
        if release.is_mandatory {
            return false;
        }
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
            return true;
        }
        if pref.is_skipped(&release.version) {
            log::info!("用户已设置跳过版本 {}，忽略本次更新提醒", release.version);
            return true;
        }
        false
    }

    /// 判定该版本是否命中当前客户端的灰度放量分桶（未配置灰度比例或强制更新时恒为命中）。
    ///
    /// # 设计原理
    /// - **实现初衷**：灰度放量必须在「同一客户端 + 同一版本」上给出稳定且不可预测的结果，
    ///   否则用户会遇到「刷新一次能更新、再刷新又不能」的诡异现象。
    /// - **核心优势**：分桶值由 `SHA-256(client_id:version) % 100` 派生，
    ///   既保证确定性，又使不同版本间的分桶分布互不相关，
    ///   避免某台客户端长期被固定分到同一桶而始终无法参与灰度。
    fn is_release_within_rollout(&self, release: &ResolvedRelease) -> bool {
        if release.is_mandatory {
            return true;
        }
        let Some(percentage) = release.rollout_percentage else {
            return true;
        };
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
            return false;
        }
        log::info!(
            "新版本 {} 处于灰度放量中（灰度比例: {}%，客户端分桶: {}），已命中灰度放量",
            release.version,
            percentage,
            bucket
        );
        true
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
