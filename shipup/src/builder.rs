// shipup 跨平台自更新系统 - UpdaterBuilder 构建器

use crate::error::{Result, UpdateError};
use crate::manifest::current_target_triple;
use crate::updater::Updater;
use semver::Version;
use std::collections::HashMap;
use std::time::Duration;

/// 更新器核心配置结构体
///
/// # 设计原理
/// - **实现初衷**：收敛更新器实例化所需的版本号、目标通道、验签公钥与超时参数，彻底消除多参数平铺。
#[derive(Debug, Clone)]
pub struct UpdaterConfig {
    /// 宿主应用当前运行版本号
    pub current_version: Version,
    /// Manifest 元数据远端下载地址
    pub manifest_url: String,
    /// 目标发布通道
    pub channel: Option<String>,
    /// Ed25519 验签公钥（Base64 编码）
    pub public_key: Option<String>,
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
}

/// 更新器链式构建器
///
/// # 设计原理
/// - **实现初衷**：采用标准建造者模式（Builder Pattern）渐进式配置自更新策略，提供兼具易用性与类型安全的配置入口。
/// - **核心优势**：默认提供合理的防降级策略（`false`）、默认超时（15s）及自动平台 Target 探测。
/// - **代价与局限**：终结方法 `build()` 需校验必选参数（`current_version` 与 `manifest_url`）是否已正确提供。
#[derive(Debug, Clone)]
pub struct UpdaterBuilder {
    pub(crate) current_version: Option<Version>,
    pub(crate) manifest_url: Option<String>,
    pub(crate) channel: Option<String>,
    pub(crate) public_key: Option<String>,
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
}

impl Default for UpdaterBuilder {
    fn default() -> Self {
        Self {
            current_version: None,
            manifest_url: None,
            channel: None,
            public_key: None,
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
        }
    }
}

impl UpdaterBuilder {
    /// 创建一个新的构建器实例
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置本地当前运行版本号（SemVer 2.0 字符串或已解析的 Version）
    pub fn current_version(mut self, version: impl AsRef<str>) -> Result<Self> {
        let parsed = Version::parse(version.as_ref())?;
        self.current_version = Some(parsed);
        Ok(self)
    }

    /// 设置 Manifest 元数据 JSON 的下载地址
    pub fn manifest_url(mut self, url: impl Into<String>) -> Self {
        self.manifest_url = Some(url.into());
        self
    }

    /// 设置更新通道（如 "beta", "alpha", "stable"）
    pub fn channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    /// 设置 Ed25519 公钥（Base64 编码，若不配置则关闭公钥验签）
    pub fn public_key(mut self, public_key: impl Into<String>) -> Self {
        self.public_key = Some(public_key.into());
        self
    }

    /// 设置网络请求超时时长（默认 15 秒）
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 设置 HTTP 请求的 User-Agent 标识
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// 手动指定目标 Target Triple 标识（缺省自动探测宿主平台）
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = target.into();
        self
    }

    /// 是否允许降级安装（默认为 false，防降级攻击）
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

    /// 构建 Updater 实例
    ///
    /// # Errors
    /// 当未提供 `current_version` 或 `manifest_url` 等必填配置时，返回 [`UpdateError::ManifestParse`]。
    pub fn build(self) -> Result<Updater> {
        let current_version = self.current_version.ok_or_else(|| {
            UpdateError::ManifestParse("构建 Updater 必须提供 current_version".to_string())
        })?;

        let manifest_url = self.manifest_url.ok_or_else(|| {
            UpdateError::ManifestParse("构建 Updater 必须提供 manifest_url".to_string())
        })?;

        if !self.dangerous_insecure_transport_protocol && manifest_url.starts_with("http://") {
            return Err(UpdateError::InsecureTransportProtocol(manifest_url));
        }

        let config = UpdaterConfig {
            current_version,
            manifest_url,
            channel: self.channel,
            public_key: self.public_key,
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
}
