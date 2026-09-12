//! 更新器网络传输与数字签名安全配置模块。
//!
//! # 模块职责
//! 定义 [`NetworkSecurityConfig`]，将网络请求策略（超时、代理、重试、请求头、限速、镜像）
//! 与密码学安全策略（多公钥、门限签名、强制验签、TLS 协议约束）内聚为一个不可变配置实体。
//!
//! # 设计原理
//! - **实现初衷**：`Updater`、`Update`、`DownloadedUpdate` 三层实体都需要读取同一份网络与安全策略，
//!   若各自持有散装字段会引发配置漂移与多处克隆开销。
//! - **核心优势**：配置以 `Arc<NetworkSecurityConfig>` 共享，构建完成后不可篡改，
//!   杜绝运行期被意外改写导致的「安全降级」（例如验签开关被并发的日志逻辑覆盖）。
//! - **代价与局限**：配置一经构建即固定，运行期无法动态热重载连接参数。
//!
//! # 安全契约
//! 本模块的 [`std::fmt::Debug`] 实现会对 `Authorization`、`Cookie`、`Proxy-Authorization`、
//! `Set-Cookie` 等敏感请求头执行掩码脱敏，确保配置实体被日志或错误上下文打印时不会泄漏明文凭证。

use std::collections::HashMap;
use std::time::Duration;

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
