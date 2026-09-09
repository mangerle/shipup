# shipup

通用、轻量级、无 UI 绑定的跨平台软件自更新（Self-Updater）系统。

[English](README.md) | 简体中文

---

## 核心特性

- **纯粹独立，零 UI 绑定**：不假设任何上层 GUI 框架或异步事件循环，可无缝嵌入 GPUI、Slint、Egui、Iced 以及命令行与服务端应用。
- **复合更新策略**：支持轻量单二进制原地原子替换、压缩包（.zip / .tar.gz）解压沙箱替换与大型桌面应用外部安装器接管。
- **原生同步与异步双模式**：基于 `reqwest`，开箱即用支持同步阻塞（`blocking`）与异步原生（`async`）双套 API，亦可通过特性灵活裁剪依赖。
- **工业级安全防线**：
  - 第一层：SHA-256 流式哈希校验传输损坏。
  - 第二层：Ed25519 纯 Rust 高性能非对称公钥数字签名验证。
  - 第三层：Zip Slip 路径逃逸防御与解压体积熔断防护。
- **跨平台鲁棒性**：
  - 同卷原子写入策略，彻底杜绝跨文件系统 `EXDEV: Cross-device link` 错误。
  - 深度适配 Windows 文件锁重命名绕过与新进程启动自清理闭环。
  - 自动修复 Linux 可执行权限（0o755）与清理 macOS Gatekeeper 隔离属性。
- **发布生态闭环**：提供开箱即用的发布端命令行工具 `shipup-cli`，支持密钥生成（`keygen`）与发布包签名合并（`release`）。

---

## 快速入门

### 1. 添加依赖

在应用的 `Cargo.toml` 中添加：

```toml
[dependencies]
shipup = "0.1.0"
```

### 2. 客户端更新检查与安装

```rust
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use shipup::{Updater, UpdateEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 构建更新器实例
    let updater = Updater::builder()
        .current_version("1.0.0")?
        .manifest_url("https://updates.example.com/latest.json")
        .channel("stable")
        .public_key("your_base64_ed25519_public_key...")
        .timeout(Duration::from_secs(15))
        .build()?;

    // 检查更新
    if let Some(update) = updater.check()? {
        println!("发现新版本: {}", update.version());

        // 下载并安装
        let cancel_flag = Arc::new(AtomicBool::new(false));
        update.download_and_install_with_cancellation(
            Some(cancel_flag),
            |event| match event {
                UpdateEvent::DownloadStarted { total_bytes } => {
                    println!("开始下载，文件大小: {:?}", total_bytes);
                }
                UpdateEvent::DownloadProgress { percent, .. } => {
                    if let Some(p) = percent {
                        println!("下载进度: {:.1}%", p);
                    }
                }
                UpdateEvent::Installing => println!("正在替换安装..."),
                UpdateEvent::ReadyToRestart => println!("安装就绪，准备重启。"),
                _ => {}
            },
        )?;

        // 优雅自重启
        update.restart_with(|ctx| {
            ctx.before_exit(|| {
                println!("正在释放单实例锁并清理运行状态...");
            });
        })?;
    }

    Ok(())
}
```

---

## 发布端命令行工具 (shipup-cli)

`shipup` 提供了独立的发布端辅助命令行工具 `shipup-cli`，用于快速生成 Ed25519 密钥对以及构建并签署版本清单（Manifest）。

### 1. 安装发布工具
```powershell
cargo install shipup-cli
```

### 2. 生成签名密钥对
```powershell
shipup-cli keygen -o ./keys
```
将在 `./keys` 目录下生成 `ed25519.key`（私钥，请妥善保密）与 `ed25519.pub`（公钥，配置于客户端应用）。

### 3. 生成并签署发布清单
```powershell
shipup-cli release \
  --version 1.1.0 \
  --target x86_64-pc-windows-msvc \
  --package ./target/release/app.exe \
  --url https://updates.example.com/downloads/app-1.1.0.exe \
  --key ./keys/ed25519.key \
  --package-type binary \
  --manifest ./dist/latest.json
```

---

## 许可证
本项目采用 MIT 许可证授权。详情参见 [LICENSE](LICENSE) 文件。
