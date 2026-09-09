// shipup 跨平台自更新系统 - URL 动态模板占位符解析引擎

use semver::Version;

/// URL 模板变量上下文参数对象
///
/// # 设计原理
/// - **实现初衷**：收敛 URL 动态渲染所需的 Target Triple、当前版本与通道参数，消除多参数平铺。
#[derive(Debug, Clone)]
pub struct TemplateContext<'a> {
    /// 目标 Target Triple（如 "x86_64-pc-windows-msvc"）
    pub target: &'a str,
    /// 宿主应用当前运行版本号
    pub current_version: &'a Version,
    /// 目标发布通道（如 "beta", "stable"）
    pub channel: Option<&'a str>,
}

/// 根据上下文解析替换 URL 模板中的动态占位符
///
/// # 支持的占位符
/// - `{{target}}`: 完整目标平台 Target Triple（例如 "x86_64-pc-windows-msvc"）
/// - `{{arch}}`: CPU 架构简写（例如 "x86_64", "aarch64", "x86", "arm"）
/// - `{{os}}`: 操作系统简写（例如 "windows", "macos", "linux"）
/// - `{{current_version}}`: 宿主当前 SemVer 2.0 版本号
/// - `{{channel}}`: 当前匹配通道名称（未配置时默认解析为 "stable"）
///
/// # 设计原理
/// - **实现初衷**：使服务端能够根据客户端请求动态下发特定平台包，并依据版本号实施服务端灰度放量。
/// - **核心优势**：免除外部重量级模板引擎依赖，基于字符串简单替换，性能极高。
pub fn resolve_url_template(template: &str, ctx: &TemplateContext<'_>) -> String {
    if !template.contains("{{") {
        return template.to_string();
    }

    let (arch, os) = parse_arch_and_os(ctx.target);
    let channel_str = ctx.channel.unwrap_or("stable");
    let version_str = ctx.current_version.to_string();

    template
        .replace("{{target}}", ctx.target)
        .replace("{{arch}}", arch)
        .replace("{{os}}", os)
        .replace("{{current_version}}", &version_str)
        .replace("{{channel}}", channel_str)
}

fn parse_arch_and_os(target: &str) -> (&str, &str) {
    let lower = target.to_ascii_lowercase();
    let arch = if lower.starts_with("x86_64") {
        "x86_64"
    } else if lower.starts_with("aarch64") || lower.starts_with("arm64") {
        "aarch64"
    } else if lower.starts_with("i686") || lower.starts_with("x86") {
        "x86"
    } else if lower.starts_with("arm") {
        "arm"
    } else {
        "unknown"
    };

    let os = if lower.contains("windows") {
        "windows"
    } else if lower.contains("darwin") || lower.contains("apple") || lower.contains("macos") {
        "macos"
    } else if lower.contains("linux") {
        "linux"
    } else {
        "unknown"
    };

    (arch, os)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_url_template_all_variables() {
        let version = Version::parse("1.2.3-beta.1").unwrap();
        let ctx = TemplateContext {
            target: "x86_64-pc-windows-msvc",
            current_version: &version,
            channel: Some("beta"),
        };

        let template = "https://api.example.com/updates/{{channel}}/{{target}}/{{current_version}}?arch={{arch}}&os={{os}}";
        let resolved = resolve_url_template(template, &ctx);

        assert_eq!(
            resolved,
            "https://api.example.com/updates/beta/x86_64-pc-windows-msvc/1.2.3-beta.1?arch=x86_64&os=windows"
        );
    }

    #[test]
    fn test_resolve_url_template_defaults_and_no_placeholders() {
        let version = Version::parse("2.0.0").unwrap();
        let ctx = TemplateContext {
            target: "aarch64-apple-darwin",
            current_version: &version,
            channel: None,
        };

        let template = "https://cdn.example.com/{{channel}}/manifest.json";
        let resolved = resolve_url_template(template, &ctx);
        assert_eq!(resolved, "https://cdn.example.com/stable/manifest.json");

        let static_url = "https://cdn.example.com/static/manifest.json";
        assert_eq!(resolve_url_template(static_url, &ctx), static_url);
    }
}
