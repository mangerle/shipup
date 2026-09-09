# shipup

通用、轻量级、无 UI 绑定的跨平台软件自更新（Self-Updater）系统。

[English](README.md) | 简体中文 | [详细使用说明文档 (docs/USAGE.md)](docs/USAGE.md)

---

## 核心特性

- **纯粹独立，零 UI 绑定**：不假设任何上层 GUI 框架或异步事件循环，可无缝嵌入 GPUI、Slint、Egui、Iced 以及命令行与服务端应用。
- **复合更新策略**：支持轻量单二进制原地原子替换、压缩包（.zip / .tar.gz）解压沙箱替换与大型桌面应用外部安装器接管。
- **两阶段生命周期解耦**：将更新流程严格拆分为“网络下载与密码学验签（`download()`）”和“物理文件替换（`install()`）”，支持后台静默预载与用户空闲时无感部署。
- **原生同步与异步双模式**：基于 `reqwest`，开箱即用支持同步阻塞（`blocking`）与异步原生（`async`）双套 API，亦可通过特性灵活裁剪依赖。
- **工业级高可用与安全防线**：
  - 第一层：SHA-256 流式哈希校验传输损坏。
  - 第二层：Ed25519 纯 Rust 高性能非对称公钥数字签名验证，支持多公钥配置与无感平滑轮换。
  - 第三层：强制生产环境 TLS 协议强校验，拦截任何非受控的明文 HTTP 传输。
  - 第四层：Zip Slip 路径逃逸防御与解压体积熔断防护。
- **多端点自动故障转移 (Failover)**：支持配置主备多源清单端点，首选 CDN 异常时自动降级尝试下一备用端点。
- **动态 URL 模板与多通道路由**：支持端点 URL 占位符展开（`{{target}}`, `{{current_version}}`, `{{channel}}`），原生适配灰度放量与多通道发行。
- **用户更新偏好持久化**：原生内置用户“跳过此版本”与“稍后提醒（静默期）”偏好管理，支持强更（Mandatory）全局逃逸覆盖。
- **跨平台鲁棒性与灾难自愈**：
  - 同卷原子写入策略，彻底杜绝跨文件系统 `EXDEV: Cross-device link` 错误。
  - 深度适配 Windows 运行文件锁重命名绕过与新进程启动自清理闭环。
  - 自动修复 Linux 可执行权限（0o755）与清理 macOS Gatekeeper 隔离属性。
  - 内置启动健康自检与异常连续崩溃自动回滚机制。
- **发布生态闭环**：提供开箱即用的发布端命令行工具 `shipup-cli`，支持密钥生成（`keygen`）与发布包签名合并（`release`）。

---

## 快速入门

> 详细的场景代码范例、高级配置以及 CI/CD 流水线集成，请查阅 [完整使用说明文档](docs/USAGE.md)。

### 1. 添加依赖

在应用的 `Cargo.toml` 中添加：

```toml
[dependencies]
shipup = { version = "0.3.0", features = ["blocking"] }
```

### 2. 客户端更新检查、下载与安装

```rust
use std::time::Duration;
use shipup::{Updater, UpdateEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 启动入口健康检查（若新版本连续崩溃超过 2 次将自动触发回滚）
    shipup::check_and_recover_current(2)?;

    // 2. 构建更新器实例
    let updater = Updater::builder()
        .current_version("1.0.0")?
        .manifest_url("https://updates.example.com/latest.json")
        .channel("stable")
        .public_key("YOUR_BASE64_ED25519_PUBLIC_KEY")
        .timeout(Duration::from_secs(15))
        .build()?;

    // 3. 检查是否有新版本
    if let Some(update) = updater.check()? {
        println!("发现新版本: {}", update.version());

        // 4. 下载并校验（不产生磁盘覆盖破坏）
        let downloaded = update.download(|event| match event {
            UpdateEvent::DownloadProgress { percent, speed_bytes_per_sec, .. } => {
                if let Some(p) = percent {
                    println!("下载进度: {:.1}%, 速率: {:?} B/s", p, speed_bytes_per_sec);
                }
            }
            UpdateEvent::VerifyingSignature => println!("正在校验数字签名..."),
            _ => {}
        })?;

        // 5. 执行物理替换或拉起安装器
        downloaded.install(|event| {
            if event == UpdateEvent::ReadyToRestart {
                println!("安装就绪，准备重启。");
            }
        })?;

        // 6. 优雅自重启
        update.restart_with(|ctx| {
            ctx.before_exit(|| {
                println!("正在释放单实例锁并清理运行状态...");
            });
        })?;
    }

    // 7. 程序平稳运行后确认升级成功闭环
    shipup::confirm_update_success()?;
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

