//! 离线仓库示例。
//!
//! 演示如何从本地目录读取 `manifest.json` 并完成更新检查，
//! 适用于企业内网、隔离网络与移动介质（U 盘）分发场景。
//!
//! # 运行前准备
//! 在当前目录放置 `offline_repo/manifest.json` 与对应安装包，
//! 然后执行 `cargo run --example offline_repo`。

use std::path::PathBuf;

use shipup::Updater;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/offline_repo");

    // 离线目录会自动开启 file:// 协议并将 manifest_url 指向该目录
    let updater = Updater::builder()
        .current_version("1.0.0")?
        .offline_dir(&repo_dir)?
        // 本地联调通常尚未配置签名公钥，显式关闭强制验签
        .require_signature(false)
        .build()?;

    match updater.check()? {
        Some(update) => {
            println!(
                "离线源发现新版本: {}，包类型: {}",
                update.version(),
                update.package_type()
            );
            if let Some(notes) = update.notes() {
                println!("更新说明: {notes}");
            }
        }
        None => println!("离线源无可用更新"),
    }

    Ok(())
}
