// shipup 跨平台自更新系统 - 发布源提供者抽象与 GitHub Releases 适配器

#[cfg(any(feature = "blocking", feature = "async", test))]
use crate::error::{Result, UpdateError};
#[cfg(any(feature = "blocking", feature = "async", test))]
use crate::manifest::{Manifest, PackageInfo, PackageType};
#[cfg(any(feature = "blocking", feature = "async", test))]
use semver::Version;
#[cfg(any(feature = "blocking", feature = "async", test))]
use serde::Deserialize;
#[cfg(any(feature = "blocking", feature = "async", test))]
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};

/// 发布源提供者通用接口抽象
///
/// # 设计原理
/// - **实现初衷**：解耦更新器对单一静态 `manifest.json` 下载端点的依赖，支持接入多种外部发布平台（如 GitHub Releases、GitLab、私有制品库）。
/// - **核心优势**：在无需运维自建更新元数据服务器的前提下，直接从平台 API 推导或拉取版本清单。
/// - **代价与局限**：受平台接口鉴权策略与调用频次配额（Rate Limit）约束。
pub trait ReleaseProvider: Send + Sync {
    /// 以同步阻塞方式获取或推导 Manifest 元数据
    #[cfg(feature = "blocking")]
    fn fetch_manifest_blocking(&self) -> Result<Manifest>;

    /// 以异步非阻塞方式获取或推导 Manifest 元数据
    #[cfg(feature = "async")]
    fn fetch_manifest_async<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Manifest>> + Send + 'a>>;
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

/// GitHub Releases 原生发布源提供者
///
/// # 设计原理
/// - **实现初衷**：直接对接 GitHub 官方 Releases API，实现零服务器运维的自动化软件发布与更新。
/// - **核心优势**：
///   - 自动优先检测附件中的 `manifest.json` 或 `latest.json`，若存在则直接作为权威清单载入；
///   - 若未上传专用清单文件，则自动解析 Release Tag、Release Notes 与附件名称，推导合成符合规范的最小 Manifest；
///   - 支持配置 GitHub Personal Access Token (PAT) 提高接口配额并支持私有仓库拉取。
/// - **代价与局限**：未提供 Token 时，GitHub 匿名 API 请求受 60 次/小时限制。
#[derive(Clone)]
pub struct GitHubProvider {
    owner: String,
    repo: String,
    token: Option<String>,
    manifest_asset_name: Option<String>,
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
            manifest_asset_name: None,
            options: ProviderClientOptions::default(),
        }
    }

    /// 设置 GitHub 访问令牌（用于提高 Rate Limit 配额或访问私有仓库）
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// 指定附件中作为更新清单的文件名（默认为优先检测 `manifest.json` 或 `latest.json`）
    pub fn with_manifest_asset_name(mut self, name: impl Into<String>) -> Self {
        self.manifest_asset_name = Some(name.into());
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

    /// 获取 GitHub Releases API 请求地址
    pub fn release_api_url(&self) -> String {
        format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            self.owner, self.repo
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

/// GitHub Releases 原始响应数据模型
#[cfg(any(feature = "blocking", feature = "async", test))]
#[derive(Debug, Deserialize)]
pub(crate) struct RawGitHubRelease {
    pub tag_name: String,
    pub name: Option<String>,
    pub body: Option<String>,
    pub published_at: Option<String>,
    #[serde(default)]
    pub assets: Vec<RawGitHubAsset>,
}

/// GitHub Releases 附件数据模型
#[cfg(any(feature = "blocking", feature = "async", test))]
#[derive(Debug, Deserialize)]
pub(crate) struct RawGitHubAsset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
}

/// GitHub Release 解析结果形态
#[cfg(any(feature = "blocking", feature = "async", test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReleaseParseOutcome {
    /// 附件中包含独立清单文件，提供其下载直链
    ManifestUrl(String),
    /// 根据附件与元数据动态推导合成的最小清单实体（Box 消除变体体积差异）
    DerivedManifest(Box<Manifest>),
}

/// 解析 GitHub Release API JSON 响应并推导或提取 Manifest
#[cfg(any(feature = "blocking", feature = "async", test))]
pub(crate) fn parse_github_release_response(
    json_text: &str,
    preferred_manifest_name: Option<&str>,
) -> Result<ReleaseParseOutcome> {
    let raw: RawGitHubRelease = serde_json::from_str(json_text).map_err(|e| {
        UpdateError::ManifestParse(format!("解析 GitHub Releases API 响应失败: {}", e))
    })?;

    // 1. 优先查找是否存在显式指定的清单文件名
    if let Some(pref) = preferred_manifest_name
        && let Some(asset) = raw
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(pref))
    {
        return Ok(ReleaseParseOutcome::ManifestUrl(
            asset.browser_download_url.clone(),
        ));
    }

    // 2. 查找默认通用清单文件（manifest.json 或 latest.json）
    for candidate_name in &["manifest.json", "latest.json"] {
        if let Some(asset) = raw
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(candidate_name))
        {
            return Ok(ReleaseParseOutcome::ManifestUrl(
                asset.browser_download_url.clone(),
            ));
        }
    }

    // 3. 若无独立清单文件，从 Release Tag 与附件列表动态推导合成 Manifest
    let clean_tag = raw
        .tag_name
        .trim()
        .strip_prefix('v')
        .or_else(|| raw.tag_name.trim().strip_prefix('V'))
        .unwrap_or(raw.tag_name.trim());

    let version = Version::parse(clean_tag)?;

    let mut packages = BTreeMap::new();
    for asset in &raw.assets {
        if let Some(target) = detect_target_from_filename(&asset.name) {
            let package_type = detect_package_type_from_filename(&asset.name);
            let pkg = PackageInfo {
                url: asset.browser_download_url.clone(),
                mirrors: Vec::new(),
                signature: None,
                signatures: Vec::new(),
                checksum: None,
                package_type,
                install_mode: None,
                install_args: Vec::new(),
                executable_path: None,
                require_elevation: false,
                wait_for_exit: false,
                payload_checksums: Default::default(),
                size: Some(asset.size),
            };
            packages.insert(target.to_string(), pkg);
        }
    }

    let manifest = Manifest {
        version,
        min_supported_version: None,
        force_update: false,
        pub_date: raw.published_at,
        notes: raw.body.or(raw.name),
        packages,
        channels: BTreeMap::new(),
        signature: None,
        signatures: Vec::new(),
        rollout_percentage: None,
        expires_at: None,
        version_seq: None,
    };

    Ok(ReleaseParseOutcome::DerivedManifest(Box::new(manifest)))
}

/// 根据附件文件名猜测适配的目标平台 Target Triple
#[cfg(any(feature = "blocking", feature = "async", test))]
fn detect_target_from_filename(filename: &str) -> Option<&'static str> {
    let lower = filename.to_ascii_lowercase();

    // 常见标准完整 Rust Target 标识匹配
    if lower.contains("x86_64-pc-windows-msvc") {
        return Some("x86_64-pc-windows-msvc");
    }
    if lower.contains("x86_64-pc-windows-gnu") {
        return Some("x86_64-pc-windows-gnu");
    }
    if lower.contains("aarch64-pc-windows-msvc") {
        return Some("aarch64-pc-windows-msvc");
    }
    if lower.contains("x86_64-apple-darwin") {
        return Some("x86_64-apple-darwin");
    }
    if lower.contains("aarch64-apple-darwin") {
        return Some("aarch64-apple-darwin");
    }
    if lower.contains("x86_64-unknown-linux-musl") {
        return Some("x86_64-unknown-linux-musl");
    }
    if lower.contains("x86_64-unknown-linux-gnu") {
        return Some("x86_64-unknown-linux-gnu");
    }
    if lower.contains("aarch64-unknown-linux-musl") {
        return Some("aarch64-unknown-linux-musl");
    }
    if lower.contains("aarch64-unknown-linux-gnu") {
        return Some("aarch64-unknown-linux-gnu");
    }

    // 启发式架构与操作系统关键字匹配
    let is_arm64 = lower.contains("arm64") || lower.contains("aarch64");
    let is_x64 = lower.contains("x86_64") || lower.contains("x64") || lower.contains("amd64");

    if lower.contains("win") || lower.ends_with(".exe") || lower.ends_with(".msi") {
        if is_arm64 {
            return Some("aarch64-pc-windows-msvc");
        }
        if is_x64 {
            return Some("x86_64-pc-windows-msvc");
        }
    }

    if lower.contains("mac")
        || lower.contains("darwin")
        || lower.ends_with(".dmg")
        || lower.ends_with(".pkg")
    {
        if is_arm64 {
            return Some("aarch64-apple-darwin");
        }
        if is_x64 {
            return Some("x86_64-apple-darwin");
        }
    }

    if lower.contains("linux")
        || lower.ends_with(".deb")
        || lower.ends_with(".rpm")
        || lower.ends_with(".appimage")
    {
        let is_musl = lower.contains("musl");
        if is_arm64 {
            return if is_musl {
                Some("aarch64-unknown-linux-musl")
            } else {
                Some("aarch64-unknown-linux-gnu")
            };
        }
        if is_x64 {
            return if is_musl {
                Some("x86_64-unknown-linux-musl")
            } else {
                Some("x86_64-unknown-linux-gnu")
            };
        }
    }

    None
}

/// 根据文件名后缀启发式判断更新包类型
#[cfg(any(feature = "blocking", feature = "async", test))]
fn detect_package_type_from_filename(filename: &str) -> PackageType {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".zip")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
        || lower.ends_with(".tar.xz")
        || lower.ends_with(".tar.zst")
    {
        PackageType::Archive
    } else if lower.ends_with(".msi")
        || lower.ends_with(".exe")
        || lower.ends_with(".pkg")
        || lower.ends_with(".dmg")
        || lower.ends_with(".deb")
        || lower.ends_with(".rpm")
    {
        PackageType::Installer
    } else {
        PackageType::Binary
    }
}

impl ReleaseProvider for GitHubProvider {
    #[cfg(feature = "blocking")]
    fn fetch_manifest_blocking(&self) -> Result<Manifest> {
        let headers = self.build_headers()?;
        let client_builder = reqwest::blocking::Client::builder()
            .timeout(self.options.timeout)
            .default_headers(headers);

        let client = client_builder
            .build()
            .map_err(|e| UpdateError::Network(format!("创建 GitHub HTTP 客户端失败: {}", e)))?;

        let api_url = self.release_api_url();
        log::info!("正在向 GitHub API 请求最新发布元数据: {}", api_url);

        let response = client
            .get(&api_url)
            .send()
            .map_err(|e| UpdateError::Network(format!("请求 GitHub Releases API 失败: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let msg = response
                .text()
                .unwrap_or_else(|_| "无法获取错误响应体".to_string());
            if status.as_u16() == 403 && msg.contains("rate limit") {
                return Err(UpdateError::HttpStatus {
                    status_code: 403,
                    message: "GitHub API 请求频次超限 (Rate Limit Exceeded)，建议配置 Personal Access Token".to_string(),
                });
            }
            return Err(UpdateError::HttpStatus {
                status_code: status.as_u16(),
                message: format!("GitHub API 响应异常: {}", msg),
            });
        }

        let body = response
            .text()
            .map_err(|e| UpdateError::Network(format!("读取 GitHub API 响应体失败: {}", e)))?;

        match parse_github_release_response(&body, self.manifest_asset_name.as_deref())? {
            ReleaseParseOutcome::ManifestUrl(url) => {
                log::info!("在 GitHub Release 附件中发现清单文件，正在拉取: {}", url);
                let manifest_resp = client.get(&url).send().map_err(|e| {
                    UpdateError::Network(format!("下载 GitHub 清单文件失败: {}", e))
                })?;
                let manifest_json = manifest_resp.text().map_err(|e| {
                    UpdateError::Network(format!("读取 GitHub 清单文本失败: {}", e))
                })?;
                Manifest::from_json_str(&manifest_json)
            }
            ReleaseParseOutcome::DerivedManifest(manifest) => {
                log::info!(
                    "根据 GitHub Release 附件动态推导清单完成 (版本: {}, 适配平台数: {})",
                    manifest.version,
                    manifest.packages.len()
                );
                Ok(*manifest)
            }
        }
    }

    #[cfg(feature = "async")]
    fn fetch_manifest_async<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Manifest>> + Send + 'a>> {
        Box::pin(async move {
            let headers = self.build_headers()?;
            let client_builder = reqwest::Client::builder()
                .timeout(self.options.timeout)
                .default_headers(headers);

            let client = client_builder.build().map_err(|e| {
                UpdateError::Network(format!("创建 GitHub 异步 HTTP 客户端失败: {}", e))
            })?;

            let api_url = self.release_api_url();
            log::info!("正在异步向 GitHub API 请求最新发布元数据: {}", api_url);

            let response = client.get(&api_url).send().await.map_err(|e| {
                UpdateError::Network(format!("请求 GitHub Releases API 失败: {}", e))
            })?;

            let status = response.status();
            if !status.is_success() {
                let msg = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "无法获取错误响应体".to_string());
                if status.as_u16() == 403 && msg.contains("rate limit") {
                    return Err(UpdateError::HttpStatus {
                        status_code: 403,
                        message: "GitHub API 请求频次超限 (Rate Limit Exceeded)，建议配置 Personal Access Token".to_string(),
                    });
                }
                return Err(UpdateError::HttpStatus {
                    status_code: status.as_u16(),
                    message: format!("GitHub API 响应异常: {}", msg),
                });
            }

            let body = response
                .text()
                .await
                .map_err(|e| UpdateError::Network(format!("读取 GitHub API 响应体失败: {}", e)))?;

            match parse_github_release_response(&body, self.manifest_asset_name.as_deref())? {
                ReleaseParseOutcome::ManifestUrl(url) => {
                    log::info!(
                        "在 GitHub Release 附件中发现清单文件，正在异步拉取: {}",
                        url
                    );
                    let manifest_resp = client.get(&url).send().await.map_err(|e| {
                        UpdateError::Network(format!("下载 GitHub 清单文件失败: {}", e))
                    })?;
                    let manifest_json = manifest_resp.text().await.map_err(|e| {
                        UpdateError::Network(format!("读取 GitHub 清单文本失败: {}", e))
                    })?;
                    Manifest::from_json_str(&manifest_json)
                }
                ReleaseParseOutcome::DerivedManifest(manifest) => {
                    log::info!(
                        "根据 GitHub Release 附件动态推导清单完成 (版本: {}, 适配平台数: {})",
                        manifest.version,
                        manifest.packages.len()
                    );
                    Ok(*manifest)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_release_with_manifest_asset() {
        let json = r#"{
            "tag_name": "v2.5.0",
            "name": "Release 2.5.0",
            "body": "Bug fixes and improvements",
            "published_at": "2026-09-09T10:00:00Z",
            "assets": [
                {
                    "name": "myapp-windows.zip",
                    "size": 10240,
                    "browser_download_url": "https://github.com/example/repo/releases/download/v2.5.0/myapp-windows.zip"
                },
                {
                    "name": "latest.json",
                    "size": 512,
                    "browser_download_url": "https://github.com/example/repo/releases/download/v2.5.0/latest.json"
                }
            ]
        }"#;

        let res = parse_github_release_response(json, None).unwrap();
        assert_eq!(
            res,
            ReleaseParseOutcome::ManifestUrl(
                "https://github.com/example/repo/releases/download/v2.5.0/latest.json".to_string()
            )
        );
    }

    #[test]
    fn test_parse_github_release_derive_manifest() {
        let json = r#"{
            "tag_name": "v3.1.0",
            "name": "Major Upgrade",
            "body": "Exciting new features",
            "published_at": "2026-09-10T08:00:00Z",
            "assets": [
                {
                    "name": "myapp-x86_64-pc-windows-msvc.exe",
                    "size": 20480,
                    "browser_download_url": "https://github.com/example/repo/releases/download/v3.1.0/myapp-win.exe"
                },
                {
                    "name": "myapp-aarch64-apple-darwin.tar.gz",
                    "size": 15360,
                    "browser_download_url": "https://github.com/example/repo/releases/download/v3.1.0/myapp-mac.tar.gz"
                },
                {
                    "name": "myapp-x86_64-unknown-linux-gnu.tar.gz",
                    "size": 18432,
                    "browser_download_url": "https://github.com/example/repo/releases/download/v3.1.0/myapp-linux.tar.gz"
                }
            ]
        }"#;

        let res = parse_github_release_response(json, None).unwrap();
        match res {
            ReleaseParseOutcome::DerivedManifest(m) => {
                assert_eq!(m.version, Version::parse("3.1.0").unwrap());
                assert_eq!(m.notes.as_deref(), Some("Exciting new features"));
                assert_eq!(m.pub_date.as_deref(), Some("2026-09-10T08:00:00Z"));
                assert_eq!(m.packages.len(), 3);
                assert!(m.packages.contains_key("x86_64-pc-windows-msvc"));
                assert!(m.packages.contains_key("aarch64-apple-darwin"));
                assert!(m.packages.contains_key("x86_64-unknown-linux-gnu"));

                let win_pkg = m.packages.get("x86_64-pc-windows-msvc").unwrap();
                assert_eq!(win_pkg.package_type, PackageType::Installer);
                assert_eq!(win_pkg.size, Some(20480));

                let mac_pkg = m.packages.get("aarch64-apple-darwin").unwrap();
                assert_eq!(mac_pkg.package_type, PackageType::Archive);
            }
            other => panic!("预期解析为 DerivedManifest，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_parse_github_release_invalid_tag_error() {
        let json = r#"{
            "tag_name": "not-a-semver",
            "assets": []
        }"#;

        let res = parse_github_release_response(json, None);
        assert!(matches!(res, Err(UpdateError::SemVer(_))));
    }
}
