//! 更新器 HTTP 传输客户端构建与清单拉取模块。
//!
//! # 模块职责
//! 收敛同步（blocking）与异步（async）两套 HTTP 客户端的构建逻辑，以及远端 Manifest 文本的拉取。
//!
//! # 设计原理
//! - **实现初衷**：`Updater::check` 与 `Update::download` 都需要一个遵守统一安全基线
//!   （最低 TLS 1.2、自定义根证书、代理、默认请求头）的 HTTP 客户端，
//!   若在调用点各自拼装必然产生策略分叉。
//! - **核心优势**：所有出网客户端共享同一套构造路径，安全策略只需维护一处；
//!   `Proxy::all` 与 `Certificate::from_pem` 的失败均被转换为带中文上下文的 [`UpdateError::Network`]。
//! - **代价与局限**：每次调用都会重新构建客户端实例，未做连接池级缓存；
//!   对于高频轮询场景，构造开销由 `reqwest` 内部连接池复用所摊薄。
//!
//! # 特性门控
//! 本模块整体依赖 `blocking` 或 `async` 特性；单独关闭两者时本模块不参与编译。

#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

use crate::error::{Result, UpdateError};
use std::collections::HashMap;
use std::time::Duration;

#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::Proxy;
#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

#[cfg(any(feature = "blocking", feature = "async"))]
/// 把字符串字典形式的自定义请求头解析为 `reqwest` 的 [`HeaderMap`]。
///
/// # Errors
/// 当键名或键值不符合 HTTP 头语法规范时，返回携带非法内容的 [`UpdateError::Network`]。
pub(super) fn parse_header_map(headers: &HashMap<String, String>) -> Result<Option<HeaderMap>> {
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
/// 把可选的代理地址字符串解析为 `reqwest` 的 [`Proxy`] 配置。
///
/// `None` 表示不使用代理；使用代理时统一走 `Proxy::all`，
/// 使 HTTP 与 HTTPS 请求共用同一出口，避免仅代理部分流量造成的行为不一致。
///
/// # Errors
/// 当代理地址格式非法时，返回携带原始地址的 [`UpdateError::Network`]。
pub(super) fn parse_proxy(proxy: Option<&str>) -> Result<Option<Proxy>> {
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
/// 构建同步阻塞 HTTP 客户端，并施加统一的安全基线。
///
/// # 安全基线
/// - 强制最低 TLS 版本为 1.2，拦截历史上的弱协议协商；
/// - 支持注入私有根证书（自建 PKI 或证书固定场景）；
/// - 默认请求头与代理在此一次性注入，避免调用点各自拼装造成策略分叉。
///
/// # Errors
/// - 自定义根证书 PEM 解析失败：[`UpdateError::Network`]；
/// - 请求头或代理配置非法：[`UpdateError::Network`]；
/// - 客户端初始化失败：[`UpdateError::Network`]。
pub(super) fn build_blocking_http_client(
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
/// 构建异步 HTTP 客户端，并施加与同步版本完全一致的安全基线。
///
/// 两个版本共用同一套安全策略（最低 TLS 1.2、自定义根证书、默认请求头、代理），
/// 唯一的差异是底层运行时与错误描述文案，从而杜绝「同步加固了、异步漏改」的双份维护陷阱。
///
/// # Errors
/// - 自定义根证书 PEM 解析失败：[`UpdateError::Network`]；
/// - 请求头或代理配置非法：[`UpdateError::Network`]；
/// - 客户端初始化失败：[`UpdateError::Network`]。
pub(super) fn build_async_http_client(
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
/// 同步拉取远端 Manifest 原始文本。
///
/// 仅负责「取回文本」，不解析、不校验：时效性、签名与版本裁决全部由调用方的评估链路负责，
/// 从而保证「解析失败」与「下载失败」在日志中可被清楚区分。
///
/// # Errors
/// - 连接失败：[`UpdateError::Network`]；
/// - 响应状态码非 2xx：[`UpdateError::HttpStatus`]；
/// - 读取响应体失败：[`UpdateError::Network`]。
pub(super) fn fetch_manifest_blocking(
    client: &reqwest::blocking::Client,
    endpoint: &str,
) -> Result<String> {
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
/// 异步拉取远端 Manifest 原始文本。
///
/// 与 [`fetch_manifest_blocking`] 保持完全一致的职责边界与错误语义，
/// 仅底层 I/O 由阻塞调用改为异步等待。
///
/// # Errors
/// - 连接失败：[`UpdateError::Network`]；
/// - 响应状态码非 2xx：[`UpdateError::HttpStatus`]；
/// - 读取响应体失败：[`UpdateError::Network`]。
pub(super) async fn fetch_manifest_async(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<String> {
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
