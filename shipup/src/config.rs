//! 更新器对外配置模型模块。
//!
//! # 模块职责
//! 承载更新器构建完成后的不可变配置快照与共享类型别名：
//! - [`UpdaterConfig`]：构建完成的不可变配置快照，字段全部为公开只读，供上层检视与复用；
//! - [`VersionComparator`]：可插拔的版本裁决函数类型；
//! - 端点协议安全判定辅助函数 [`is_insecure_http_url`]。
//!
//! # 设计原理
//! - **实现初衷**：原先 [`UpdaterConfig`] 定义于 `builder` 模块，而 `updater` 又依赖该配置类型，
//!   形成 `builder ↔ updater` 双向引用。将配置模型下沉到本独立模块后，
//!   `builder` 与 `updater` 均单向依赖 `config`，依赖图变为有向无环（DAG）。
//! - **核心优势**：
//!   - 消除模块循环依赖，降低编译单元耦合度与后续重构风险；
//!   - 配置类型与构建器、更新引擎解耦，便于独立演进与文档组织。
//! - **代价与局限**：对外 rustdoc 中类型的定义路径由 `builder` 变为 `config`，
//!   但 crate 根的重导出路径（`shipup::UpdaterConfig`）保持不变，调用端无感知。

use crate::manifest::Manifest;
use crate::provider::ReleaseProvider;
use semver::Version;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// 自定义版本比较器函数指针/闭包类型（输入当前版本与远端版本，返回 true 表示需要更新）
pub type VersionComparator = Arc<dyn Fn(&Version, &Version) -> bool + Send + Sync>;

/// 更新器核心配置结构体
///
/// # 设计原理
/// - **实现初衷**：收敛更新器实例化所需的版本号、目标通道、验签公钥与超时参数，彻底消除多参数平铺。
#[derive(Clone)]
pub struct UpdaterConfig {
    /// 宿主应用当前运行版本号
    pub current_version: Version,
    /// Manifest 元数据远端下载端点列表（支持多源容灾与自动故障转移）
    pub endpoints: Vec<String>,
    /// 动态发布源提供者（如 GitHub Releases 平台）
    pub provider: Option<Arc<dyn ReleaseProvider>>,
    /// 目标发布通道
    pub channel: Option<String>,
    /// Ed25519 验签公钥列表（Base64 编码，支持多公钥共存与平滑轮换）
    pub public_keys: Vec<String>,
    /// 网络超时时长
    pub timeout: Duration,
    /// 自定义 HTTP User-Agent
    pub user_agent: Option<String>,
    /// 自定义 HTTP 请求头字典（用于 Token 鉴权、Cookie 注入等）
    pub headers: HashMap<String, String>,
    /// HTTP / HTTPS / SOCKS 代理服务器地址
    pub proxy: Option<String>,
    /// 网络请求重试最大次数（默认 3 次）
    pub max_retries: u32,
    /// 网络重试初始退避延迟（默认 1 秒）
    pub retry_delay: Duration,
    /// 目标架构 Target Triple 标识
    pub target: String,
    /// 是否允许降级升级
    pub allow_downgrade: bool,
    /// 是否在构造 Updater 时自动执行启动自愈检查（默认为 false）
    pub auto_recover_on_init: bool,
    /// 是否允许不安全的明文 HTTP 传输协议（默认为 false）
    pub dangerous_insecure_transport_protocol: bool,
    /// 是否强制要求更新包携带数字签名（默认恒为 true，与构建 Profile 无关）
    pub require_signature: bool,
    /// 自定义版本比较器闭包（若未设置则按 SemVer 大于判断）
    pub version_comparator: Option<VersionComparator>,
    /// 用户更新偏好持久化文件路径（若为 None 则使用默认同级目录）
    pub preference_path: Option<PathBuf>,
    /// 后台下载最大带宽限速（字节/秒，若为 None 则不限速）
    pub max_bytes_per_sec: Option<u64>,
    /// 是否允许本地及共享协议（file://，默认为 false）
    pub allow_file_protocol: bool,
    /// 是否允许在 Windows 原地替换受阻时自动降级为系统重启延迟替换 (MoveFileEx)
    pub allow_reboot_deferred_replace: bool,
    /// 内嵌 Fallback Manifest 离线容灾兜底元数据
    pub fallback_manifest: Option<Manifest>,
    /// 客户端设备稳定唯一标识（用于灰度放量哈希分桶）
    pub client_id: Option<String>,
    /// 最大保留的历史版本回滚备份数量（默认 3）
    pub max_rollback_entries: usize,
    /// 自定义受信任根证书 PEM 字节数据列表（用于自建私有 PKI 或证书固定）
    pub root_certificates_pem: Vec<Vec<u8>>,
    /// TUF 门限多签要求的最低独立公钥签名法定数量（Threshold，默认 1）
    pub signature_threshold: usize,
    /// 是否开启多更新源端点并发竞速 (Happy Eyeballs) 探测机制
    pub endpoint_racing: bool,
    /// 并发竞速模式下的端点错峰阶梯启动延迟
    pub stagger_delay: Duration,
    /// 是否开启大文件多镜像源分片并行下载与拼装加速（默认为 false）
    pub chunked_download: bool,
    /// 分片并行下载并发 Worker 数量（默认为 4）
    pub chunked_concurrency: usize,
    /// 单个分片切片字节大小（默认为 4MB）
    pub chunk_size: usize,
    /// 全局配置的备用镜像下载直链列表
    pub download_mirrors: Vec<String>,
    /// 是否开启跨进程断点续传（使用确定性临时路径，进程重启后可继续未完成下载）
    pub resumable_download: bool,
}

impl std::fmt::Debug for UpdaterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdaterConfig")
            .field("current_version", &self.current_version)
            .field("endpoints", &self.endpoints)
            .field("has_provider", &self.provider.is_some())
            .field("channel", &self.channel)
            .field("public_keys", &self.public_keys)
            .field("timeout", &self.timeout)
            .field("user_agent", &self.user_agent)
            .field("headers", &redact_sensitive_headers(&self.headers))
            .field("proxy", &self.proxy)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .field("target", &self.target)
            .field("allow_downgrade", &self.allow_downgrade)
            .field("auto_recover_on_init", &self.auto_recover_on_init)
            .field(
                "dangerous_insecure_transport_protocol",
                &self.dangerous_insecure_transport_protocol,
            )
            .field("require_signature", &self.require_signature)
            .field(
                "has_custom_version_comparator",
                &self.version_comparator.is_some(),
            )
            .field("preference_path", &self.preference_path)
            .field("max_rollback_entries", &self.max_rollback_entries)
            .field("root_certificates_count", &self.root_certificates_pem.len())
            .field("signature_threshold", &self.signature_threshold)
            .field("endpoint_racing", &self.endpoint_racing)
            .field("stagger_delay", &self.stagger_delay)
            .field("chunked_download", &self.chunked_download)
            .field("chunked_concurrency", &self.chunked_concurrency)
            .field("chunk_size", &self.chunk_size)
            .field("download_mirrors_count", &self.download_mirrors.len())
            .field("resumable_download", &self.resumable_download)
            .finish()
    }
}

impl UpdaterConfig {
    /// 获取首选主验签公钥（向后兼容接口）
    pub fn public_key(&self) -> Option<&str> {
        self.public_keys.first().map(|s| s.as_str())
    }

    /// 获取首选主端点下载地址（向后兼容接口）
    pub fn manifest_url(&self) -> Option<&str> {
        self.endpoints.first().map(|s| s.as_str())
    }
}

/// 检查指定 URL 是否为不安全的明文 HTTP 协议传输（忽略协议 Scheme 大小写）
///
/// # 设计原理
/// - **实现初衷**：根据 RFC 3986 规范，URL Scheme 大小写不敏感。防范利用大写 `HTTP://` 或混合大小写绕过明文拦截。
/// - **核心优势**：在栈上提取前 7 字节执行 ASCII 大小写无关比对，零堆内存分配。
pub(crate) fn is_insecure_http_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.len() >= 7 {
        trimmed[..7].eq_ignore_ascii_case("http://")
    } else {
        false
    }
}

/// 对敏感请求头（Authorization / Cookie 等）执行 Debug 脱敏
///
/// # 设计原理
/// - **实现初衷**：配置结构体常被日志或错误上下文打印，若明文输出 Basic/Bearer 凭据将造成凭证泄漏。
/// - **核心优势**：仅在格式化视图中替换为掩码，不修改真实运行时配置。
pub(crate) fn redact_sensitive_headers(headers: &HashMap<String, String>) -> HashMap<&str, String> {
    headers
        .iter()
        .map(|(k, v)| {
            let key_lower = k.to_ascii_lowercase();
            let display = if key_lower == "authorization"
                || key_lower == "cookie"
                || key_lower == "proxy-authorization"
                || key_lower == "set-cookie"
            {
                "***".to_string()
            } else {
                v.clone()
            };
            (k.as_str(), display)
        })
        .collect()
}
