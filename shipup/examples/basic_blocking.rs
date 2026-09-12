//! 基础同步阻塞模式示例。
//!
//! 演示更新器构建、检查更新与两阶段安装（下载验签 → 物理替换）的完整骨架，
//! 适合不引入异步运行时的传统桌面与命令行程序参考。
//!
//! # 运行前准备
//! 请替换 `PUBLIC_KEY` 与 `MANIFEST_URL` 为真实值；
//! 本地联调可临时开启 `require_signature(false)` 与 `dangerous_insecure_transport_protocol(true)`，
//! 但生产环境严禁保留这两项放宽配置。

use std::time::Duration;

use shipup::{UpdateEvent, Updater};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 入口健康检查：新版本连续崩溃超阈值时自动回滚
    shipup::check_and_recover_current(2)?;

    // 2. 构建更新器（生产环境务必配置公钥并保持 require_signature 默认开启）
    let updater = Updater::builder()
        .current_version(env!("CARGO_PKG_VERSION"))?
        .manifest_url("https://updates.example.com/latest.json")
        .channel("stable")
        .public_key("YOUR_BASE64_ED25519_PUBLIC_KEY")
        .timeout(Duration::from_secs(15))
        .build()?;

    // 3. 检查是否有可用更新
    if let Some(update) = updater.check()? {
        println!("发现新版本: {}", update.version());

        // 4. 阶段一：下载并验签（不修改正在运行的二进制）
        let downloaded = update.download(|event| match event {
            UpdateEvent::DownloadStarted { total_bytes } => {
                println!("开始下载，总大小: {total_bytes:?}");
            }
            UpdateEvent::DownloadProgress {
                percent: Some(p), ..
            } => {
                println!("下载进度: {p:.1}%");
            }
            UpdateEvent::VerifyingSignature => println!("正在校验数字签名..."),
            _ => {}
        })?;

        // 5. 阶段二：在合适时机执行物理替换
        downloaded.install(|event| {
            if event == UpdateEvent::ReadyToRestart {
                println!("安装完成，准备重启");
            }
        })?;

        // 6. 优雅自重启
        update.restart_with(|ctx| {
            ctx.before_exit(|| {
                println!("退出前释放单实例锁并清理运行状态...");
            });
        })?;
    } else {
        println!("当前已是最新版本");
    }

    // 7. 应用平稳运行后确认升级成功，退出健康观察期
    shipup::confirm_update_success()?;
    Ok(())
}
