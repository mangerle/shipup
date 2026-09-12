//! 更新器网络传输与数字签名安全配置模块。
//!
//! # 模块职责
//! 定义 [`NetworkSecurityConfig`]，将网络请求策略（超时、代理、重试、请求头、限速、镜像）
//! 与密码学安全策略（多公钥、门限签名、强制验签、TLS 协议约束）内聚为一个不可变配置实体。
//!
//! 本实体由 [`crate::config::UpdaterConfig`] 在 [`crate::updater::Updater::new`] 阶段拆分派生，
//! 只承载运行期真正被下载与验签链路消费的安全字段，与业务调度字段（端点、通道、版本基准）分离。
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
    /// Ed25519 验签公钥列表（Base64 编码，任意一枚通过即视为合法）
    pub public_keys: Vec<String>,
    /// 单次网络请求超时时长（默认 15 秒）
    pub timeout: Duration,
    /// 自定义 HTTP User-Agent（若为 None 则使用库内置标识）
    pub user_agent: Option<String>,
    /// 自定义 HTTP 请求头字典（鉴权凭证在 Debug 输出中自动脱敏）
    pub headers: HashMap<String, String>,
    /// HTTP / HTTPS / SOCKS 代理服务器地址（若为 None 则直连）
    pub proxy: Option<String>,
    /// 网络请求失败后的最大重试次数（默认 3 次）
    pub max_retries: u32,
    /// 重试初始退避延迟（默认 1 秒，后续按指数退避）
    pub retry_delay: Duration,
    /// 是否放行明文 HTTP 传输（默认 false；开启即放弃 TLS 保护，仅限受控调试）
    pub dangerous_insecure_transport_protocol: bool,
    /// 是否强制要求更新包携带数字签名（默认 true，关闭将仅依赖哈希完整性）
    pub require_signature: bool,
    /// 后台下载带宽限速（字节/秒，None 表示不限速）
    pub max_bytes_per_sec: Option<u64>,
    /// 是否允许 file:// 本地协议端点（默认 false，防止未授权本地文件读取）
    pub allow_file_protocol: bool,
    /// 是否允许 Windows 重启延迟替换降级路径（MoveFileEx，默认 false）
    pub allow_reboot_deferred_replace: bool,
    /// 最大保留的历史版本回滚备份数量（默认 3）
    pub max_rollback_entries: usize,
    /// 自定义受信任根证书 PEM 字节列表（私有 CA 或证书固定场景）
    pub root_certificates_pem: Vec<Vec<u8>>,
    /// TUF 门限多签最低独立公钥签名法定数量（默认 1）
    pub signature_threshold: usize,
    /// 是否开启多端点并发竞速探测（Happy Eyeballs，默认 false）
    pub endpoint_racing: bool,
    /// 并发竞速时各端点错峰启动延迟（默认 250 毫秒）
    pub stagger_delay: Duration,
    /// 是否开启大文件分片并行下载加速（默认 false）
    pub chunked_download: bool,
    /// 分片并行下载并发 Worker 数量（默认 4，内部截断于 1..=16）
    pub chunked_concurrency: usize,
    /// 单个分片切片字节大小（默认 4MB，内部下限 64KB）
    pub chunk_size: usize,
    /// 备用镜像下载直链列表（用于分片流量分摊与故障转移）
    pub download_mirrors: Vec<String>,
    /// 是否开启跨进程断点续传（默认 false；开启后使用确定性临时路径）
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
