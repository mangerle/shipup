//! 发布源提供者抽象与 GitHub Releases 适配模块。
//!
//! # 模块职责
//! 定义动态发布源扩展点 [`ReleaseProvider`] 及其配置 [`ProviderClientOptions`]，
//! 并内置 GitHub Releases 的静态清单直链实现 [`GitHubProvider`]。
//!
//! # 设计原理
//! - **实现初衷**：不同制品平台（GitHub、GitLab、自建制品库）获取清单的方式差异很大，
//!   若把这些差异硬编码进更新器，将无法支持平台扩展与测试替身。
//! - **核心优势**：
//!   - 提供者只负责「产出 Manifest」，清单的时效、签名与版本裁决仍由更新器统一把关，
//!     因此替换发布源不会削弱任何一层安全防线；
//!   - GitHub 适配器直接请求 Release 附件中的静态清单，完全绕开 REST API 的匿名限流配额，
//!     在 CI 高频发布场景下依然稳定。
//! - **代价与局限**：动态发布源受对应平台的鉴权策略与网络可达性约束；
//!   GitHub 方案要求发布流水线必须把签名清单作为 Release 附件上传。
//!
//! # 特性门控
//! 网络请求相关的实现依赖 `blocking` 或 `async` 特性；两者均关闭时本模块仅保留 trait 定义。

#[cfg(any(feature = "blocking", feature = "async", test))]
use crate::error::{Result, UpdateError};
#[cfg(any(feature = "blocking", feature = "async", test))]
use crate::manifest::Manifest;
use std::fmt;
use std::time::Duration;

#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};

/// 发布源提供者通用接口抽象
///
/// # 设计原理
/// - **实现初衷**：将版本清单（Manifest）的拉取逻辑抽象为通用特型，解耦更新器对常规 HTTP URL 探测通道的直接依赖，支持接入多种自定义或平台化发布源（如 GitHub Releases、GitLab、私有制品库）。
/// - **核心优势**：调用方可自由扩展清单获取策略（例如注入平台专有鉴权、动态计算直链路径或适配私有协议），统一更新元数据加载契约。
/// - **代价与局限**：相比直接配置 `manifest_url`，自定义 Provider 需同时实现同步阻塞与异步原生两套获取逻辑。
pub trait ReleaseProvider: Send + Sync {
    /// 以同步阻塞方式获取 Manifest 元数据
    #[cfg(feature = "blocking")]
    fn fetch_manifest_blocking(&self) -> Result<Manifest>;

    /// 以异步非阻塞方式获取 Manifest 元数据
    #[cfg(feature = "async")]
    fn fetch_manifest_async<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Manifest>> + Send + 'a>>;
}

/// 提供者底层 HTTP 客户端参数配置
#[derive(Debug, Clone)]
pub struct ProviderClientOptions {
    /// 请求超时时长（默认 15 秒）
    pub timeout: Duration,
    /// 自定义 User-Agent 字符串
    pub user_agent: Option<String>,
    /// 自定义受信任根证书 PEM 字节数据列表
    pub root_certificates_pem: Vec<Vec<u8>>,
}

impl Default for ProviderClientOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            user_agent: None,
            root_certificates_pem: Vec::new(),
        }
    }
}

/// GitHub Releases 静态清单发布源提供者
///
/// # 设计原理
/// - **实现初衷**：为托管在 GitHub Releases 的软件提供无服务器运维的静态更新发布源。
/// - **核心优势**：
///   - 直接向 GitHub Release 静态资产（默认固定为 `latest.json`）发起下载请求，走静态存储 CDN；
///   - 彻底摆脱 GitHub REST API（`api.github.com`）未鉴权 60 次/小时 的 Rate Limit 频次配额限制；
///   - 响应极快，并且天然支持接入国内镜像反代加速。
/// - **代价与局限**：发布端必须在发布 Release 时通过 CI/CD 或 shipup-cli 将签名后的清单文件（如 `latest.json`）作为附件一同上传。
#[derive(Clone)]
pub struct GitHubProvider {
    owner: String,
    repo: String,
    token: Option<String>,
    manifest_asset_name: String,
    options: ProviderClientOptions,
}

impl fmt::Debug for GitHubProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubProvider")
            .field("owner", &self.owner)
            .field("repo", &self.repo)
            .field("has_token", &self.token.is_some())
            .field("manifest_asset_name", &self.manifest_asset_name)
            .field("options", &self.options)
            .finish()
    }
}

impl GitHubProvider {
    /// 创建一个新的 GitHub Releases 发布源提供者
    ///
    /// # 参数
    /// * `owner`: GitHub 仓库所属组织或用户名
    /// * `repo`: GitHub 仓库名称
    pub fn new(owner: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            repo: repo.into(),
            token: None,
            manifest_asset_name: "latest.json".to_string(),
            options: ProviderClientOptions::default(),
        }
    }

    /// 设置 GitHub 访问令牌（用于私有仓库访问鉴权）
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// 指定 Release 附件中作为更新清单的文件名（默认为确定的 `latest.json`）
    pub fn with_manifest_asset_name(mut self, name: impl Into<String>) -> Self {
        self.manifest_asset_name = name.into();
        self
    }

    /// 设置网络请求超时时长
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    /// 设置自定义 User-Agent 标识
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.options.user_agent = Some(ua.into());
        self
    }

    /// 注入自定义受信任根证书 PEM 字节数据
    pub fn with_root_certificate_pem(mut self, pem_bytes: &[u8]) -> Self {
        self.options.root_certificates_pem.push(pem_bytes.to_vec());
        self
    }

    /// 获取 GitHub Releases API 请求地址（保留供诊断或特定用途使用）
    pub fn release_api_url(&self) -> String {
        format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            self.owner, self.repo
        )
    }

    /// 获取 GitHub Releases 静态资产直链（默认固定为 latest.json）
    ///
    /// # 设计原理
    /// - **实现初衷**：在 GitHub Releases 体系中，shipup-cli 默认规范输出清单文件为 `latest.json`。
    /// - **核心优势**：直接请求静态资产下载地址（`/releases/latest/download/{asset}`），完全免受 GitHub REST API 60次/小时 Rate Limit 限流，毫秒级响应。
    /// - **代价与局限**：必须依赖发布端通过 CI/CD 或 shipup-cli release 将清单上传至 Release 附件。
    pub fn manifest_download_url(&self) -> String {
        format!(
            "https://github.com/{}/{}/releases/latest/download/{}",
            self.owner, self.repo, self.manifest_asset_name
        )
    }

    #[cfg(any(feature = "blocking", feature = "async"))]
    fn build_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );

        let ua_str = self
            .options
            .user_agent
            .as_deref()
            .unwrap_or(concat!("shipup/", env!("CARGO_PKG_VERSION")));

        let ua_val = HeaderValue::from_str(ua_str)
            .map_err(|e| UpdateError::Network(format!("User-Agent 请求头格式非法: {}", e)))?;
        headers.insert(USER_AGENT, ua_val);

        if let Some(ref token) = self.token {
            let auth_str = format!("Bearer {}", token.trim());
            let auth_val = HeaderValue::from_str(&auth_str)
                .map_err(|e| UpdateError::Network(format!("Authorization 令牌格式非法: {}", e)))?;
            headers.insert(AUTHORIZATION, auth_val);
        }

        Ok(headers)
    }
}

impl ReleaseProvider for GitHubProvider {
    #[cfg(feature = "blocking")]
    fn fetch_manifest_blocking(&self) -> Result<Manifest> {
        let headers = self.build_headers()?;
        let client = reqwest::blocking::Client::builder()
            .timeout(self.options.timeout)
            .default_headers(headers)
            .build()
            .map_err(|e| UpdateError::Network(format!("创建 GitHub HTTP 客户端失败: {}", e)))?;

        let url = self.manifest_download_url();
        log::info!("正在从 GitHub 静态 Release 资产拉取发布清单: {}", url);

        let response = client.get(&url).send().map_err(|e| {
            UpdateError::Network(format!(
                "请求 GitHub 静态清单直链失败: {}, 原因: {}",
                url, e
            ))
        })?;

        let status = response.status();
        if !status.is_success() {
            let msg = response
                .text()
                .unwrap_or_else(|_| "无法读取错误响应体".to_string());
            if status.as_u16() == 404 {
                return Err(UpdateError::HttpStatus {
                    status_code: 404,
                    message: format!(
                        "GitHub Release 附件中未找到静态清单文件（地址: {}）。请确保版本已发布且包含该清单文件",
                        url
                    ),
                });
            }
            return Err(UpdateError::HttpStatus {
                status_code: status.as_u16(),
                message: format!(
                    "下载 GitHub 静态清单响应异常 (HTTP {}): {}",
                    status.as_u16(),
                    msg
                ),
            });
        }

        let text = response
            .text()
            .map_err(|e| UpdateError::Network(format!("读取 GitHub 清单文件内容失败: {}", e)))?;

        Manifest::from_json_str(&text)
    }

    #[cfg(feature = "async")]
    fn fetch_manifest_async<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Manifest>> + Send + 'a>> {
        Box::pin(async move {
            let headers = self.build_headers()?;
            let client = reqwest::Client::builder()
                .timeout(self.options.timeout)
                .default_headers(headers)
                .build()
                .map_err(|e| {
                    UpdateError::Network(format!("创建 GitHub 异步 HTTP 客户端失败: {}", e))
                })?;

            let url = self.manifest_download_url();
            log::info!("正在异步从 GitHub 静态 Release 资产拉取发布清单: {}", url);

            let response = client.get(&url).send().await.map_err(|e| {
                UpdateError::Network(format!(
                    "请求 GitHub 静态清单直链失败: {}, 原因: {}",
                    url, e
                ))
            })?;

            let status = response.status();
            if !status.is_success() {
                let msg = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "无法读取错误响应体".to_string());
                if status.as_u16() == 404 {
                    return Err(UpdateError::HttpStatus {
                        status_code: 404,
                        message: format!(
                            "GitHub Release 附件中未找到静态清单文件（地址: {}）。请确保版本已发布且包含该清单文件",
                            url
                        ),
                    });
                }
                return Err(UpdateError::HttpStatus {
                    status_code: status.as_u16(),
                    message: format!(
                        "下载 GitHub 静态清单响应异常 (HTTP {}): {}",
                        status.as_u16(),
                        msg
                    ),
                });
            }

            let text = response.text().await.map_err(|e| {
                UpdateError::Network(format!("读取 GitHub 清单文件内容失败: {}", e))
            })?;

            Manifest::from_json_str(&text)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_provider_manifest_download_url_default() {
        let provider = GitHubProvider::new("mangerle", "rddns");
        assert_eq!(
            provider.manifest_download_url(),
            "https://github.com/mangerle/rddns/releases/latest/download/latest.json"
        );
    }

    #[test]
    fn test_github_provider_manifest_download_url_custom() {
        let provider =
            GitHubProvider::new("mangerle", "rddns").with_manifest_asset_name("custom.json");
        assert_eq!(
            provider.manifest_download_url(),
            "https://github.com/mangerle/rddns/releases/latest/download/custom.json"
        );
    }

    #[test]
    fn test_github_provider_debug_and_options() {
        let provider = GitHubProvider::new("mangerle", "rddns")
            .with_token("test-token")
            .with_timeout(Duration::from_secs(30))
            .with_user_agent("test-agent/1.0");

        let debug_str = format!("{:?}", provider);
        assert!(debug_str.contains("mangerle"));
        assert!(debug_str.contains("rddns"));
        assert!(debug_str.contains("has_token: true"));
        assert_eq!(
            provider.release_api_url(),
            "https://api.github.com/repos/mangerle/rddns/releases/latest"
        );
    }
}
