// shipup 跨平台自更新系统 - UpdaterBuilder 构建器

use crate::download::is_file_url;
use crate::error::{Result, UpdateError};
use crate::manifest::{Manifest, current_target_triple};
use crate::provider::{GitHubProvider, ReleaseProvider};
use crate::updater::Updater;
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
            .field("headers", &self.headers)
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

/// 更新器链式构建器
///
/// # 设计原理
/// - **实现初衷**：采用标准建造者模式（Builder Pattern）渐进式配置自更新策略，提供兼具易用性与类型安全的配置入口。
/// - **核心优势**：默认提供合理的防降级策略（`false`）、默认超时（15s）及自动平台 Target 探测。
/// - **代价与局限**：终结方法 `build()` 需校验必选参数（`current_version` 与 `endpoints`）是否已正确提供。
#[derive(Clone)]
pub struct UpdaterBuilder {
    pub(crate) current_version: Option<Version>,
    pub(crate) endpoints: Vec<String>,
    pub(crate) provider: Option<Arc<dyn ReleaseProvider>>,
    pub(crate) channel: Option<String>,
    pub(crate) public_keys: Vec<String>,
    pub(crate) timeout: Duration,
    pub(crate) user_agent: Option<String>,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) proxy: Option<String>,
    pub(crate) max_retries: u32,
    pub(crate) retry_delay: Duration,
    pub(crate) target: String,
    pub(crate) allow_downgrade: bool,
    pub(crate) auto_recover_on_init: bool,
    pub(crate) dangerous_insecure_transport_protocol: bool,
    pub(crate) require_signature: bool,
    pub(crate) version_comparator: Option<VersionComparator>,
    pub(crate) preference_path: Option<PathBuf>,
    pub(crate) max_bytes_per_sec: Option<u64>,
    pub(crate) allow_file_protocol: bool,
    pub(crate) allow_reboot_deferred_replace: bool,
    pub(crate) fallback_manifest: Option<Manifest>,
    pub(crate) client_id: Option<String>,
    pub(crate) max_rollback_entries: usize,
    pub(crate) root_certificates_pem: Vec<Vec<u8>>,
    pub(crate) signature_threshold: usize,
    pub(crate) endpoint_racing: bool,
    pub(crate) stagger_delay: Duration,
    pub(crate) chunked_download: bool,
    pub(crate) chunked_concurrency: usize,
    pub(crate) chunk_size: usize,
    pub(crate) download_mirrors: Vec<String>,
}

impl std::fmt::Debug for UpdaterBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdaterBuilder")
            .field("current_version", &self.current_version)
            .field("endpoints", &self.endpoints)
            .field("has_provider", &self.provider.is_some())
            .field("channel", &self.channel)
            .field("public_keys", &self.public_keys)
            .field("timeout", &self.timeout)
            .field("user_agent", &self.user_agent)
            .field("headers", &self.headers)
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
            .field("max_bytes_per_sec", &self.max_bytes_per_sec)
            .field("allow_file_protocol", &self.allow_file_protocol)
            .field("has_fallback_manifest", &self.fallback_manifest.is_some())
            .field("client_id", &self.client_id)
            .field("max_rollback_entries", &self.max_rollback_entries)
            .field("root_certificates_count", &self.root_certificates_pem.len())
            .field("signature_threshold", &self.signature_threshold)
            .field("endpoint_racing", &self.endpoint_racing)
            .field("stagger_delay", &self.stagger_delay)
            .field("chunked_download", &self.chunked_download)
            .field("chunked_concurrency", &self.chunked_concurrency)
            .field("chunk_size", &self.chunk_size)
            .field("download_mirrors_count", &self.download_mirrors.len())
            .finish()
    }
}

impl Default for UpdaterBuilder {
    fn default() -> Self {
        Self {
            current_version: None,
            endpoints: Vec::new(),
            provider: None,
            channel: None,
            public_keys: Vec::new(),
            timeout: Duration::from_secs(15),
            user_agent: None,
            headers: HashMap::new(),
            proxy: None,
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            target: current_target_triple().to_string(),
            allow_downgrade: false,
            auto_recover_on_init: false,
            dangerous_insecure_transport_protocol: false,
            require_signature: true,
            version_comparator: None,
            preference_path: None,
            max_bytes_per_sec: None,
            allow_file_protocol: false,
            allow_reboot_deferred_replace: false,
            fallback_manifest: None,
            client_id: None,
            max_rollback_entries: crate::recovery::DEFAULT_MAX_ROLLBACK_ENTRIES,
            root_certificates_pem: Vec::new(),
            signature_threshold: 1,
            endpoint_racing: false,
            stagger_delay: Duration::from_millis(250),
            chunked_download: false,
            chunked_concurrency: crate::download::DEFAULT_CHUNKED_CONCURRENCY,
            chunk_size: crate::download::DEFAULT_CHUNK_SIZE,
            download_mirrors: Vec::new(),
        }
    }
}

impl UpdaterBuilder {
    /// 创建一个新的构建器实例
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置本地宿主程序当前运行版本号（SemVer 2.0 字符串或已解析的 Version）
    ///
    /// # 设计原理
    /// - **实现初衷**：以严格的语义化版本（SemVer 2.0）作为客户端基准，用于后续与远端 Manifest 中的新版本进行比较。
    ///
    /// # Errors
    /// 当版本号字符串不符合 SemVer 2.0 规范（例如缺失主/次版本号或含有非法字符）时，返回 [`UpdateError::SemVer`]。
    pub fn current_version(mut self, version: impl AsRef<str>) -> Result<Self> {
        let parsed = Version::parse(version.as_ref())?;
        self.current_version = Some(parsed);
        Ok(self)
    }

    /// 设置 Manifest 元数据 JSON 的主下载地址（向后兼容的便捷单端点方法）
    ///
    /// 等价于调用 [`Self::endpoint`]。支持在 URL 中使用模板占位符（如 `{{target}}`、`{{channel}}`）。
    pub fn manifest_url(mut self, url: impl Into<String>) -> Self {
        self.endpoints.push(url.into());
        self
    }

    /// 添加单个更新检查端点（可多次调用以配置多端点冗余与故障转移）
    ///
    /// # 设计原理
    /// - **实现初衷**：支持跨 CDN、主备机房配置多个清单下载端点，按配置顺序依序尝试。
    /// - **核心优势**：在检查更新时若首选端点网络超时或遭遇 HTTP 5xx 异常，自动降级至备选端点。
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoints.push(url.into());
        self
    }

    /// 批量添加更新检查端点列表（按顺序尝试，支持主备容灾与自动故障转移）
    ///
    /// # 设计原理
    /// - **实现初衷**：支持从配置文件或外部服务动态载入多个可用 CDN 源列表。
    pub fn endpoints(mut self, urls: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.endpoints.extend(urls.into_iter().map(Into::into));
        self
    }

    /// 设置目标发布通道（如 "beta", "alpha", "stable"）
    ///
    /// # 设计原理
    /// - **实现初衷**：支持多环境（正式版、预览版）复用单份 Manifest 配置文件，客户端根据通道名称精准路由至对应的软件包。
    /// - **代价与局限**：若指定了通道但 Manifest 中未声明该通道，将直接报告错误，杜绝非预期的静默回退。
    pub fn channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    /// 添加单个 Ed25519 验证公钥（Base64 编码，可多次调用以配置多枚公钥实现平滑轮换）
    ///
    /// # 设计原理
    /// - **实现初衷**：支持配置多个合法发布者公钥，当旧私钥泄漏或证书周期性轮换时，新旧客户端均能无感平滑迁移。
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.public_keys.push(public_key.into());
        self
    }

    /// 批量设置或追加 Ed25519 验证公钥列表（Base64 编码）
    ///
    /// # 设计原理
    /// - **实现初衷**：支持一次性导入备用公钥环，任何一枚公钥签名校验通过即视为合法更新。
    pub fn public_keys(mut self, public_keys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.public_keys
            .extend(public_keys.into_iter().map(Into::into));
        self
    }

    /// 设置 TUF 门限多签要求的最低独立有效公钥签名数量（Threshold，默认 1）
    ///
    /// # 设计原理
    /// - **实现初衷**：在企业级高安全场景下推行 M-of-N 联合签署治理策略，杜绝单一私钥失窃导致恶意固件分发。
    /// - **核心优势**：强制约束验证通过的签名必须来自不同互斥的受信任公钥，杜绝重放伪造。
    /// - **代价与局限**：发布端必须组织至少相应数量的受信任密钥持有人联合签署。
    pub fn signature_threshold(mut self, threshold: usize) -> Self {
        self.signature_threshold = threshold.max(1);
        self
    }

    /// 设置网络请求超时时长（默认 15 秒）
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置 HTTP 请求的自定义 User-Agent 标识
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// 手动指定目标 Target Triple 标识（缺省时自动探测宿主平台架构与 libc）
    ///
    /// # 设计原理
    /// - **实现初衷**：在自动化测试、交叉编译模拟运行或特殊嵌入式架构中，允许上层手动覆写目标平台标识。
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = target.into();
        self
    }

    /// 是否允许降级安装（默认为 false，防降级攻击）
    ///
    /// # 设计原理
    /// - **实现初衷**：默认开启防降级攻击保护，杜绝中间人或恶意配置诱导客户端安装含有已知漏洞的历史旧版本。
    pub fn allow_downgrade(mut self, allow: bool) -> Self {
        self.allow_downgrade = allow;
        self
    }

    /// 设置是否在构造 Updater 实例时自动执行崩溃自愈检查（默认为 false）
    ///
    /// # 设计原理
    /// - **实现初衷**：避免在多实例构建或多次触发更新检查时隐式自增崩溃计数造成误回滚。
    /// - **最佳实践**：推荐在宿主应用入口（如 `main` 函数首行）显式调用 [`crate::check_and_recover_current`]。
    pub fn auto_recover_on_init(mut self, auto_recover: bool) -> Self {
        self.auto_recover_on_init = auto_recover;
        self
    }

    /// 设置是否允许使用不安全的明文传输协议（HTTP）（默认为 false）
    ///
    /// # 设计原理
    /// - **实现初衷**：生产环境中强制执行 HTTPS 传输校验，防范中间人攻击者篡改更新清单或重定向安装包下载。
    /// - **安全警示**：非调试或局域网受控测试场景严禁开启此选项。
    pub fn dangerous_insecure_transport_protocol(mut self, allow: bool) -> Self {
        self.dangerous_insecure_transport_protocol = allow;
        self
    }

    /// 设置是否强制要求更新包携带数字签名（默认恒为 true，消除 Profile 环境漂移）
    ///
    /// # 设计原理
    /// - **实现初衷**：统一安全基线，无论 Debug 还是 Release 模式下均默认开启强制签名校验，杜绝环境漂移引入安全漏洞。
    /// - **安全警示**：若显式设置为 `false`，当更新包缺少签名时将放弃数字身份防伪校验，仅依赖 SHA-256 完整性。
    ///   除受控本地调试场景外，严禁在生产环境关闭该保护。
    pub fn require_signature(mut self, require: bool) -> Self {
        self.require_signature = require;
        self
    }

    /// 设置自定义版本比较器（接收当前版本与远端版本引用，返回 true 表示应触发升级）
    ///
    /// # 设计原理
    /// - **实现初衷**：满足自定义版本策略需求（如按语义化版本标签、灰度构建号、日期版本或忽略特定补丁升级）。
    /// - **核心优势**：允许上层业务深度介入更新裁决，打破默认仅以 SemVer 大于判断的单一死板规则。
    pub fn version_comparator(
        mut self,
        comparator: impl Fn(&Version, &Version) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.version_comparator = Some(Arc::new(comparator));
        self
    }

    /// 添加单个自定义 HTTP 请求头（可多次调用以添加多个，如 Authorization 凭证）
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// 批量设置自定义 HTTP 请求头字典
    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// 设置 HTTP / HTTPS / SOCKS 代理服务器地址（例如 "http://127.0.0.1:7890"）
    pub fn proxy(mut self, proxy_url: impl Into<String>) -> Self {
        self.proxy = Some(proxy_url.into());
        self
    }

    /// 设置网络请求重试最大次数（默认 3 次）
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// 设置网络请求重试初始退避延迟（默认 1 秒）
    pub fn retry_delay(mut self, retry_delay: Duration) -> Self {
        self.retry_delay = retry_delay;
        self
    }

    /// 设置用户更新偏好持久化文件路径（若不指定则默认存储在可执行文件同级目录）
    ///
    /// # 设计原理
    /// - **实现初衷**：支持调用端将跳过版本与稍后提醒记录存储于自定义数据目录或沙箱数据卷。
    pub fn preference_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.preference_path = Some(path.into());
        self
    }

    /// 设置后台更新下载最大带宽速率限制（字节/秒，若不设置则不限速）
    ///
    /// # 设计原理
    /// - **实现初衷**：允许客户端根据业务场景对更新流量实施 QoS 调控，避免后台更新占满网络。
    pub fn max_bytes_per_sec(mut self, limit: u64) -> Self {
        self.max_bytes_per_sec = Some(limit);
        self
    }

    /// 设置是否允许使用本地及共享协议（file://）（默认为 false）
    ///
    /// # 设计原理
    /// - **实现初衷**：满足企业内网、离线隔离网络或本地介质部署环境的更新诉求。
    /// - **安全契约**：默认禁用以避免恶意相对路径注入或未授权本地文件读取，需显式声明开启。
    pub fn allow_file_protocol(mut self, allow: bool) -> Self {
        self.allow_file_protocol = allow;
        self
    }

    /// 配置本地或内网离线镜像更新源目录
    ///
    /// # 设计原理
    /// - **实现初衷**：在单机隔离内网或移动存储设备更新场景下，调用方通常仅持有离线仓库根目录。
    /// - **核心优势**：一键自动将 `allow_file_protocol` 设为 `true`，并将 `manifest_url` 指向该目录下规范化 `file://` 端点，免除手动路径转义。
    /// - **代价与局限**：默认假定目录内存在 `manifest.json` 清单文件。
    ///
    /// # Errors
    /// 当本地路径无法转换为合法 `file://` 端点时返回错误。
    pub fn offline_dir<P: AsRef<std::path::Path>>(mut self, dir_path: P) -> Result<Self> {
        let manifest_path = dir_path.as_ref().join("manifest.json");
        let manifest_url = crate::offline::path_to_file_url(&manifest_path)?;
        self.allow_file_protocol = true;
        self = self.manifest_url(manifest_url);
        Ok(self)
    }

    /// 设置当 Windows 目标可执行程序被占用锁定导致原地替换失败时，是否允许自动降级为系统重启延迟替换 (MoveFileEx)
    ///
    /// # 设计原理
    /// - **实现初衷**：针对 Windows 下常驻后台服务、托盘守护程序或防病毒软件排他锁定导致无法重命名的场景。
    /// - **核心优势**：利用 Windows 原生 `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)` 向系统注册替换任务，
    ///   避免更新主流程直接报错退出，提升常驻服务或被占用进程的更新自愈成功率。
    /// - **代价与局限**：替换在下一次操作系统重启时生效，需妥善向用户派发提示。
    pub fn allow_reboot_deferred_replace(mut self, allow: bool) -> Self {
        self.allow_reboot_deferred_replace = allow;
        self
    }

    /// 设置内嵌 Fallback Manifest 离线容灾兜底元数据
    ///
    /// # 设计原理
    /// - **实现初衷**：在所有网络端点均无法连通时，提供离线保底更新清单进行版本裁决。
    /// - **核心优势**：提升客户端在极端网络中断或无外网单机场景下的可用性。
    pub fn fallback_manifest(mut self, manifest: Manifest) -> Self {
        self.fallback_manifest = Some(manifest);
        self
    }

    /// 通过 JSON 字符串设置内嵌 Fallback Manifest 离线容灾兜底元数据
    ///
    /// # Errors
    /// 当 JSON 字符串无法反序列化为合法 Manifest 时返回 [`UpdateError::ManifestParse`]。
    pub fn fallback_manifest_json(mut self, json_str: &str) -> Result<Self> {
        let manifest = Manifest::from_json_str(json_str)?;
        self.fallback_manifest = Some(manifest);
        Ok(self)
    }

    /// 设置客户端设备稳定唯一标识（用于灰度放量哈希分桶）
    ///
    /// # 设计原理
    /// - **实现初衷**：允许调用方将自定义的设备 ID、用户唯一标识或硬件指纹传入更新器。
    /// - **兜底策略**：若未显式调用此方法设置，更新器将自动从偏好文件读取或生成随机稳定 ID 并持久化。
    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = Some(id.into());
        self
    }

    /// 设置最大保留的历史版本回滚备份数量（默认 3 个）
    ///
    /// # 设计原理
    /// - **实现初衷**：允许调用方根据磁盘存储空间与历史可追溯性灵活配置旧版本保留条目数。
    pub fn max_rollback_entries(mut self, max: usize) -> Self {
        self.max_rollback_entries = max;
        self
    }

    /// 设置自定义动态发布源提供者（如 GitHub Releases、GitLab 等）
    ///
    /// # 设计原理
    /// - **实现初衷**：解耦更新器对单一固定 Manifest URL 文件的强绑定，支持外部制品平台动态发现。
    /// - **核心优势**：自动对接平台 API，极大简化发布运维负担。
    /// - **代价与局限**：受对应平台的鉴权和网络配额限制。
    pub fn provider(mut self, provider: impl ReleaseProvider + 'static) -> Self {
        self.provider = Some(Arc::new(provider));
        self
    }

    /// 便捷配置 GitHub Releases 作为更新发布源
    ///
    /// # 设计原理
    /// - **实现初衷**：为开源及商业项目托管在 GitHub 的软件提供开箱即用的零配置发布源。
    /// - **核心优势**：自动探测附件中的 `manifest.json` 或根据 Release 资产名称自动推导平台安装包。
    ///
    /// # 参数
    /// * `owner`: GitHub 仓库所有者或组织名
    /// * `repo`: GitHub 仓库名称
    pub fn github_releases(self, owner: impl Into<String>, repo: impl Into<String>) -> Self {
        self.provider(GitHubProvider::new(owner, repo))
    }

    /// 设置是否开启多更新源端点并发竞速 (Happy Eyeballs) 探测机制（默认为 false）
    ///
    /// # 设计原理
    /// - **实现初衷**：在配置多个更新端点（主 CDN、备用 CDN、海外镜像）时，避免前序端点偶发超时阻塞整体更新检测。
    /// - **核心优势**：以错峰阶梯并发向所有端点发起请求，最快成功返回并校验通过的端点直接采纳，有效降低长尾延迟。
    /// - **代价与局限**：在多端点全部可达时会产生少量的额外冗余探测流量。
    pub fn endpoint_racing(mut self, enabled: bool) -> Self {
        self.endpoint_racing = enabled;
        self
    }

    /// 设置并发竞速模式下的端点错峰阶梯启动延迟（默认 250 毫秒）
    ///
    /// # 设计原理
    /// - **实现初衷**：参考 RFC 8305 Happy Eyeballs 算法规范，避免瞬间向所有镜像源发起突发流量风暴。
    /// - **核心优势**：给予优先级最高的首选端点充分的优先响应时间窗口，仅在主端点迟钝时平滑唤醒后备源。
    pub fn stagger_delay(mut self, delay: Duration) -> Self {
        self.stagger_delay = delay;
        self
    }

    /// 添加自定义受信任根证书 PEM 格式数据（支持私有 CA 或证书固定 Certificate Pinning）
    ///
    /// # 设计原理
    /// - **实现初衷**：满足企业内网自建 CA 或高安全金融场景下证书固定需求，仅信任特定的私有根证书。
    /// - **核心优势**：在构造底层 TLS 客户端时直接将 PEM 证书注入上下文，无需修改操作系统全局受信任根证书库。
    /// - **代价与局限**：若远端服务器证书更换导致公钥不匹配，网络请求将触发安全中断。
    pub fn add_root_certificate_pem(mut self, pem_bytes: &[u8]) -> Self {
        self.root_certificates_pem.push(pem_bytes.to_vec());
        self
    }

    /// 设置是否开启大文件多镜像源分片并行下载与拼装加速（默认为 false）
    ///
    /// # 设计原理
    /// - **实现初衷**：针对数十至数百兆大型更新包，突破单 TCP 连接吞吐上限并跨镜像分摊网络流量。
    /// - **核心优势**：基于 HTTP Range 原地预分配切片写入，若服务端不支持则平滑降级为常规流式下载。
    /// - **代价与局限**：在开启时会创建多个并发 HTTP 连接和 worker 线程。
    pub fn chunked_download(mut self, enabled: bool) -> Self {
        self.chunked_download = enabled;
        self
    }

    /// 设置分片并行下载时的并发 Worker 数量（默认 4）
    ///
    /// # 设计原理
    /// - **实现初衷**：允许调用方根据网络带宽与设备资源配置合适的并发工作线程数。
    /// - **代价与局限**：过高并发度可能导致服务端触发频率限制或本地文件句柄抖动，内部自动截断于 1..=16 范围。
    pub fn chunked_concurrency(mut self, concurrency: usize) -> Self {
        self.chunked_concurrency = concurrency.clamp(1, 16);
        self
    }

    /// 设置单个分片切片的字节大小（默认 4MB，即 4,194,304 字节）
    ///
    /// # 设计原理
    /// - **实现初衷**：平衡切片请求开销与断点恢复成本。切片过小会导致 HTTP 头与握手开销增大，切片过大则退化为粗粒度下载。
    pub fn chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size.max(64 * 1024);
        self
    }

    /// 添加单个备用镜像下载直链（用于大文件分片并发流量分摊与故障转移）
    ///
    /// # 设计原理
    /// - **实现初衷**：为客户端提供额外的 CDN 或镜像节点，分片下载引擎将自动在主下载直链与镜像直链间轮询分流。
    pub fn download_mirror(mut self, mirror: impl Into<String>) -> Self {
        self.download_mirrors.push(mirror.into());
        self
    }

    /// 批量添加备用镜像下载直链列表
    ///
    /// # 设计原理
    /// - **实现初衷**：便于一次性载入多个镜像节点列表。
    pub fn download_mirrors(
        mut self,
        mirrors: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.download_mirrors
            .extend(mirrors.into_iter().map(Into::into));
        self
    }

    /// 构建 Updater 实例并完成前置安全门禁与合法性校验
    ///
    /// # 校验内容
    /// 1. 验证 `current_version` 已提供。
    /// 2. 验证至少提供了一个有效的更新源端点（`manifest_url` 或 `endpoints`）或配置了 `provider`。
    /// 3. 在未显式开启 `dangerous_insecure_transport_protocol` 时，拦截任何明文 HTTP 端点。
    /// 4. 在未显式开启 `allow_file_protocol` 时，拦截任何 `file://` 协议端点。
    /// 5. 在 `require_signature` 为 true 时，强制要求至少配置一枚验签公钥。
    ///
    /// # Errors
    /// - 当缺少必填字段时返回 [`UpdateError::ManifestParse`]。
    /// - 当端点使用明文 HTTP 且未显式允许时返回 [`UpdateError::InsecureTransportProtocol`]。
    /// - 当端点使用 file:// 且未显式允许时返回 [`UpdateError::FileProtocolNotAllowed`]。
    /// - 当强制验签模式下缺少公钥时返回 [`UpdateError::MissingPublicKey`]。
    pub fn build(self) -> Result<Updater> {
        let current_version = self.current_version.ok_or_else(|| {
            UpdateError::ManifestParse("构建 Updater 必须提供 current_version".to_string())
        })?;

        if self.endpoints.is_empty() && self.provider.is_none() {
            return Err(UpdateError::ManifestParse(
                "构建 Updater 必须提供至少一个更新端点 (manifest_url 或 endpoints) 或配置 provider"
                    .to_string(),
            ));
        }

        for ep in &self.endpoints {
            if !self.dangerous_insecure_transport_protocol && is_insecure_http_url(ep) {
                return Err(UpdateError::InsecureTransportProtocol(ep.clone()));
            }
            if !self.allow_file_protocol && is_file_url(ep) {
                return Err(UpdateError::FileProtocolNotAllowed(ep.clone()));
            }
        }

        if self.require_signature && self.public_keys.is_empty() {
            return Err(UpdateError::MissingPublicKey);
        }

        if self.require_signature && self.public_keys.len() < self.signature_threshold {
            return Err(UpdateError::ManifestParse(format!(
                "受信任公钥数量 ({}) 少于要求的门限法定人数 ({})",
                self.public_keys.len(),
                self.signature_threshold
            )));
        }

        let config = UpdaterConfig {
            current_version,
            endpoints: self.endpoints,
            provider: self.provider,
            channel: self.channel,
            public_keys: self.public_keys,
            timeout: self.timeout,
            user_agent: self.user_agent,
            headers: self.headers,
            proxy: self.proxy,
            max_retries: self.max_retries,
            retry_delay: self.retry_delay,
            target: self.target,
            allow_downgrade: self.allow_downgrade,
            auto_recover_on_init: self.auto_recover_on_init,
            dangerous_insecure_transport_protocol: self.dangerous_insecure_transport_protocol,
            require_signature: self.require_signature,
            version_comparator: self.version_comparator,
            preference_path: self.preference_path,
            max_bytes_per_sec: self.max_bytes_per_sec,
            allow_file_protocol: self.allow_file_protocol,
            allow_reboot_deferred_replace: self.allow_reboot_deferred_replace,
            fallback_manifest: self.fallback_manifest,
            client_id: self.client_id,
            max_rollback_entries: self.max_rollback_entries,
            root_certificates_pem: self.root_certificates_pem,
            signature_threshold: self.signature_threshold,
            endpoint_racing: self.endpoint_racing,
            stagger_delay: self.stagger_delay,
            chunked_download: self.chunked_download,
            chunked_concurrency: self.chunked_concurrency,
            chunk_size: self.chunk_size,
            download_mirrors: self.download_mirrors,
        };

        Ok(Updater::new(config))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_missing_required_fields() {
        // 缺少版本与 URL
        let empty_builder = UpdaterBuilder::new();
        assert!(matches!(
            empty_builder.build(),
            Err(UpdateError::ManifestParse(_))
        ));

        // 仅提供版本缺少 URL
        let only_version = UpdaterBuilder::new().current_version("1.0.0").unwrap();
        assert!(matches!(
            only_version.build(),
            Err(UpdateError::ManifestParse(_))
        ));

        // 仅提供 URL 缺少版本
        let only_url = UpdaterBuilder::new().manifest_url("https://example.com/latest.json");
        assert!(matches!(
            only_url.build(),
            Err(UpdateError::ManifestParse(_))
        ));

        // 无效版本字符串
        assert!(
            UpdaterBuilder::new()
                .current_version("invalid-semver")
                .is_err()
        );
    }

    #[test]
    fn test_builder_full_configuration() {
        let updater = UpdaterBuilder::new()
            .current_version("1.0.5")
            .unwrap()
            .manifest_url("https://updates.example.com/latest.json")
            .channel("canary")
            .public_key("dGVzdC1wdWJsaWMta2V5")
            .timeout(Duration::from_secs(30))
            .user_agent("CustomUpdater/1.0")
            .header("Authorization", "Bearer secret-token-123")
            .header("X-Custom-Header", "shipup-test")
            .proxy("http://127.0.0.1:8080")
            .max_retries(5)
            .retry_delay(Duration::from_millis(500))
            .target("x86_64-pc-windows-msvc")
            .allow_downgrade(true)
            .build();

        assert!(updater.is_ok());
    }

    #[test]
    fn test_updater_new_does_not_mutate_recovery_state() {
        // 多次构造 Updater 实例，确保默认情况下不产生隐式崩溃自愈累加副作用
        for _ in 0..5 {
            let res = UpdaterBuilder::new()
                .current_version("1.0.0")
                .unwrap()
                .manifest_url("https://example.com/manifest.json")
                .require_signature(false)
                .build();
            assert!(res.is_ok());
        }
    }

    #[test]
    fn test_insecure_transport_protocol_rejection_and_override() {
        // 1. 默认情况下，明文 HTTP 地址必须被严格拦截拒绝
        let insecure_err = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("http://insecure.example.com/manifest.json")
            .require_signature(false)
            .build();
        assert!(matches!(
            insecure_err,
            Err(UpdateError::InsecureTransportProtocol(_))
        ));

        // 验证大写 HTTP:// 协议头亦被严格拦截拒绝，防止大小写绕过
        let upper_err = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("HTTP://insecure.example.com/manifest.json")
            .require_signature(false)
            .build();
        assert!(matches!(
            upper_err,
            Err(UpdateError::InsecureTransportProtocol(_))
        ));

        // 2. 显式开启危险明文协议开关后放行
        let insecure_allowed = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("http://insecure.example.com/manifest.json")
            .dangerous_insecure_transport_protocol(true)
            .require_signature(false)
            .build();
        assert!(insecure_allowed.is_ok());
    }

    #[test]
    fn test_require_signature_validation() {
        // 1. 默认即为强制验签模式，未配置公钥直接返回 MissingPublicKey（无需手动调用 require_signature）
        let missing_key_err = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("https://example.com/manifest.json")
            .build();
        assert!(matches!(
            missing_key_err,
            Err(UpdateError::MissingPublicKey)
        ));

        // 2. 显式关闭 require_signature(false) 后，允许无公钥构建
        let disabled_sig_builder = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("https://example.com/manifest.json")
            .require_signature(false)
            .build();
        assert!(disabled_sig_builder.is_ok());

        // 3. 传入公钥后默认通过校验构建成功
        let valid_builder = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("https://example.com/manifest.json")
            .public_key("dGVzdC1wdWJsaWMta2V5")
            .build();
        assert!(valid_builder.is_ok());
    }

    #[test]
    fn test_multi_endpoints_configuration() {
        // 1. 未提供任何端点时构建报错
        let no_endpoints = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .build();
        assert!(matches!(no_endpoints, Err(UpdateError::ManifestParse(_))));

        // 2. 配置主端点与备用端点成功
        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .endpoint("https://primary-cdn.example.com/manifest.json")
            .endpoint("https://backup-cdn.example.com/manifest.json")
            .require_signature(false)
            .build()
            .unwrap();

        assert_eq!(updater.endpoints().len(), 2);
        assert_eq!(
            updater.endpoints()[0],
            "https://primary-cdn.example.com/manifest.json"
        );
        assert_eq!(
            updater.endpoints()[1],
            "https://backup-cdn.example.com/manifest.json"
        );
    }

    #[test]
    fn test_builder_file_protocol_security_gate() {
        // 1. 默认未开启 allow_file_protocol 时拦截 file:// 协议
        let err = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("file:///tmp/manifest.json")
            .require_signature(false)
            .build();
        assert!(matches!(err, Err(UpdateError::FileProtocolNotAllowed(_))));

        // 2. 显式开启 allow_file_protocol 后允许通过
        let ok = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("file:///tmp/manifest.json")
            .allow_file_protocol(true)
            .require_signature(false)
            .build();
        assert!(ok.is_ok());
    }

    #[test]
    fn test_builder_fallback_manifest_config() {
        let manifest_json = r#"{
            "version": "1.1.0",
            "notes": "离线兜底版本",
            "pub_date": "2026-09-09T00:00:00Z",
            "platforms": {}
        }"#;

        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("https://example.com/manifest.json")
            .fallback_manifest_json(manifest_json)
            .unwrap()
            .require_signature(false)
            .build()
            .unwrap();

        assert!(updater.fallback_manifest().is_some());
    }

    #[test]
    fn test_builder_add_root_certificate_pem() {
        let pem_sample = b"-----BEGIN CERTIFICATE-----\nfake_pem_bytes\n-----END CERTIFICATE-----";
        let builder = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("https://example.com/manifest.json")
            .require_signature(false)
            .add_root_certificate_pem(pem_sample);

        assert_eq!(builder.root_certificates_pem.len(), 1);
        assert_eq!(builder.root_certificates_pem[0], pem_sample);

        let updater = builder.build().unwrap();
        // 验证构建后配置被安全共享
        drop(updater);
    }

    #[test]
    fn test_builder_offline_dir_configuration() {
        let temp_dir =
            std::env::temp_dir().join(format!("test_builder_offline_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let builder = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .offline_dir(&temp_dir)
            .unwrap()
            .require_signature(false);

        assert!(builder.allow_file_protocol);
        assert!(!builder.endpoints.is_empty());
        let url = &builder.endpoints[0];
        assert!(url.starts_with("file://"));
        assert!(url.ends_with("manifest.json"));
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_builder_with_provider_without_endpoints() {
        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .github_releases("example-org", "example-repo")
            .require_signature(false)
            .build()
            .unwrap();

        assert!(updater.endpoints().is_empty());
        assert!(updater.provider().is_some());
    }

    #[test]
    fn test_builder_chunked_download_options() {
        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("https://example.com/manifest.json")
            .require_signature(false)
            .chunked_download(true)
            .chunked_concurrency(8)
            .chunk_size(2 * 1024 * 1024)
            .download_mirror("https://mirror1.example.com/payload.tar.gz")
            .download_mirrors(vec![
                "https://mirror2.example.com/payload.tar.gz".to_string(),
                "https://mirror3.example.com/payload.tar.gz".to_string(),
            ])
            .build()
            .unwrap();

        // 验证 Debug 格式中包含分片配置与镜像
        let debug_str = format!("{:?}", updater);
        assert!(debug_str.contains("chunked_download: true"));
        assert!(debug_str.contains("chunked_concurrency: 8"));
        assert!(debug_str.contains("chunk_size: 2097152"));
        assert!(debug_str.contains("mirror1.example.com"));
        assert!(debug_str.contains("mirror2.example.com"));
        assert!(debug_str.contains("mirror3.example.com"));
    }
}
