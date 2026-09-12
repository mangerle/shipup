//! 配置脚手架子模块：`init` 命令的完整实现。
//!
//! # 模块职责
//! 生成标准 `shipup.toml` 配置模板文件，为新接入项目提供开箱即用的批量发布配置骨架。
//!
//! # 设计原理
//! - **实现初衷**：新项目首次接入 shipup 发布体系时，手工排版 TOML 配置容易遗漏字段或写错格式。
//!   提供一份带详尽注释的全平台预设模板，可大幅降低接入门槛。
//! - **核心优势**：默认提供 Windows / macOS / Linux 三平台预设结构与字段说明注释，
//!   兼具规范性与指引价值。
//! - **代价与局限**：若目标文件已存在默认拒绝覆写，需显式声明 `--force`，
//!   防止误操作覆盖既有配置。
//!
//! # 兄弟导航
//! - [`super::batch`]：消费本模块生成的配置文件执行批量发布；
//! - [`super::keygen`]：生成配置中引用的 Ed25519 密钥对。

use crate::cli::InitArgs;
use anyhow::{Context, Result, anyhow};
use std::fs;

/// 默认的 `shipup.toml` 配置模板内容。
const DEFAULT_TEMPLATE: &str = r#"# shipup 跨平台自更新发布配置文件
version = "1.0.0"
notes = "版本更新说明：常规性能优化与缺陷修复"
pub_date = "" # 留空将在发布时自动注入当前 UTC 时间
min_supported_version = "0.9.0"
force_update = false
channel = "stable"
rollout_percentage = 100
key = "./keys/ed25519.key"
manifest = "latest.json"

[[packages]]
target = "x86_64-pc-windows-msvc"
package = "./dist/myapp-1.0.0-windows-x64.zip"
package_type = "archive"
url = "https://download.example.com/myapp-1.0.0-windows-x64.zip"
executable_path = "myapp.exe"

[[packages]]
target = "aarch64-apple-darwin"
package = "./dist/myapp-1.0.0-macos-arm64.tar.gz"
package_type = "archive"
url = "https://download.example.com/myapp-1.0.0-macos-arm64.tar.gz"
executable_path = "myapp"

[[packages]]
target = "x86_64-unknown-linux-gnu"
package = "./dist/myapp-1.0.0-linux-x64.tar.gz"
package_type = "archive"
url = "https://download.example.com/myapp-1.0.0-linux-x64.tar.gz"
executable_path = "myapp"
"#;

/// 执行初始化命令生成发布配置脚手架。
///
/// # 设计原理
/// - **实现初衷**：为新接入的项目提供开箱即用的标准 `shipup.toml` 配置脚手架，
///   减少手工排版与参数遗漏。
/// - **核心优势**：默认提供全平台预设结构与详尽注释，兼具规范性与指引价值。
/// - **代价与局限**：若目标文件已存在默认拒绝覆写，需显式声明 `--force`。
///
/// # Errors
/// 目标文件已存在且未指定 `--force`、父目录创建失败或文件写入失败时返回中文错误。
pub(crate) fn handle_init(args: &InitArgs) -> Result<()> {
    if args.output.exists() && !args.force {
        return Err(anyhow!(
            "目标配置文件已存在: {}，若需覆盖请追加 --force 参数",
            args.output.display()
        ));
    }

    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建配置输出父目录失败: {}", parent.display()))?;
    }

    fs::write(&args.output, DEFAULT_TEMPLATE)
        .with_context(|| format!("写入配置文件失败: {}", args.output.display()))?;

    log::info!("成功生成发布配置模板: {}", args.output.display());
    println!("成功生成发布配置模板: {}", args.output.display());
    Ok(())
}
