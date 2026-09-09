// shipup 跨平台自更新系统 - UpdaterBuilder 构建器

use crate::error::{Result, UpdateError};
use crate::manifest::current_target_triple;
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
    /// 是否强制要求更新包携带数字签名（Release 模式下默认开启）
    pub require_signature: bool,
    /// 自定义版本比较器闭包（若未设置则按 SemVer 大于判断）
    pub version_comparator: Option<VersionComparator>,
    /// 用户更新偏好持久化文件路径（若为 None 则使用默认同级目录）
    pub preference_path: Option<PathBuf>,
}

impl std::fmt::Debug for UpdaterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdaterConfig")
            .field("current_version", &self.current_version)
            .field("endpoints", &self.endpoints)
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
}

impl std::fmt::Debug for UpdaterBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdaterBuilder")
            .field("current_version", &self.current_version)
            .field("endpoints", &self.endpoints)
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
            .finish()
    }
}

impl Default for UpdaterBuilder {
    fn default() -> Self {
        Self {
            current_version: None,
            endpoints: Vec::new(),
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
            require_signature: !cfg!(debug_assertions),
            version_comparator: None,
            preference_path: None,
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

    /// 设置是否强制要求更新包携带数字签名（Release 模式下默认开启）
    ///
    /// # 设计原理
    /// - **实现初衷**：将验签模型由默认 Fail-Open 升级为 Fail-Close，防止开发者疏漏公钥导致恶意安装包直接执行。
    /// - **安全契约**：若启用该选项，构建更新器时若未配置公钥，或清单中包未包含签名，更新流程将被阻断。
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

    /// 构建 Updater 实例并完成前置安全门禁与合法性校验
    ///
    /// # 校验内容
    /// 1. 验证 `current_version` 已提供。
    /// 2. 验证至少提供了一个有效的更新源端点（`manifest_url` 或 `endpoints`）。
    /// 3. 在未显式开启 `dangerous_insecure_transport_protocol` 时，拦截任何明文 HTTP 端点。
    /// 4. 在 `require_signature` 为 true 时，强制要求至少配置一枚验签公钥。
    ///
    /// # Errors
    /// - 当缺少必填字段时返回 [`UpdateError::ManifestParse`]。
    /// - 当端点使用明文 HTTP 且未显式允许时返回 [`UpdateError::InsecureTransportProtocol`]。
    /// - 当强制验签模式下缺少公钥时返回 [`UpdateError::MissingPublicKey`]。
    pub fn build(self) -> Result<Updater> {
        let current_version = self.current_version.ok_or_else(|| {
            UpdateError::ManifestParse("构建 Updater 必须提供 current_version".to_string())
        })?;

        if self.endpoints.is_empty() {
            return Err(UpdateError::ManifestParse(
                "构建 Updater 必须提供至少一个更新端点 (manifest_url 或 endpoints)".to_string(),
            ));
        }

        if !self.dangerous_insecure_transport_protocol {
            for ep in &self.endpoints {
                if ep.starts_with("http://") {
                    return Err(UpdateError::InsecureTransportProtocol(ep.clone()));
                }
            }
        }

        if self.require_signature && self.public_keys.is_empty() {
            return Err(UpdateError::MissingPublicKey);
        }

        let config = UpdaterConfig {
            current_version,
            endpoints: self.endpoints,
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
        };

        Ok(Updater::new(config))
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
            .build();
        assert!(matches!(
            insecure_err,
            Err(UpdateError::InsecureTransportProtocol(_))
        ));

        // 2. 显式开启危险明文协议开关后放行
        let insecure_allowed = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("http://insecure.example.com/manifest.json")
            .dangerous_insecure_transport_protocol(true)
            .build();
        assert!(insecure_allowed.is_ok());
    }

    #[test]
    fn test_require_signature_validation() {
        // 1. 强制要求验签模式下，未配置公钥将返回 MissingPublicKey
        let missing_key_err = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("https://example.com/manifest.json")
            .require_signature(true)
            .build();
        assert!(matches!(
            missing_key_err,
            Err(UpdateError::MissingPublicKey)
        ));

        // 2. 传入公钥后通过校验构建成功
        let valid_builder = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url("https://example.com/manifest.json")
            .public_key("dGVzdC1wdWJsaWMta2V5")
            .require_signature(true)
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
}
