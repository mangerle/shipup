# shipup 使用说明文档

本文档为 `shipup` 跨平台桌面软件自更新系统的全景使用指南，涵盖核心架构设计、客户端双调用模式集成、十大核心业务场景代码实战、发布端工作流以及常见问题排查。

---

## 目录

- [一、 架构总览与更新生命周期](#一-架构总览与更新生命周期)
- [二、 快速上手](#二-快速上手)
  - [1. 添加依赖与特性选择](#1-添加依赖与特性选择)
  - [2. 同步阻塞模式 (Blocking Mode)](#2-同步阻塞模式-blocking-mode)
  - [3. 异步原生模式 (Async Mode)](#3-异步原生模式-async-mode)
- [三、 核心功能场景实战](#三-核心功能场景实战)
  - [1. 多端点冗余配置与故障转移 (Failover)](#1-多端点冗余配置与故障转移-failover)
  - [2. 动态端点 URL 模板解析](#2-动态端点-url-模板解析)
  - [3. 多公钥配置与平滑密钥轮换](#3-多公钥配置与平滑密钥轮换)
  - [4. 强制传输安全与明文协议防呆](#4-强制传输安全与明文协议防呆)
  - [5. 发布环境强制安全验签模式](#5-发布环境强制安全验签模式)
  - [6. 自定义版本比较器注入](#6-自定义版本比较器注入)
  - [7. Windows 标准安装模式与 UAC 提权](#7-windows-标准安装模式与-uac-提权)
  - [8. 用户更新偏好管理 (跳过版本与稍后提醒)](#8-用户更新偏好管理-跳过版本与稍后提醒)
  - [9. 两阶段解耦更新 (下载与安装分离)](#9-两阶段解耦更新-下载与安装分离)
  - [10. 后台周期性静默轮询调度器 (AutoPoller)](#10-后台周期性静默轮询调度器-autopoller)
  - [11. 优雅重启与 Windows 运行锁绕过](#11-优雅重启与-windows-运行锁绕过)
  - [12. 灾难自愈与异常崩溃自动回滚](#12-灾难自愈与异常崩溃自动回滚)
- [四、 发布端工作流与 CLI 使用指南](#四-发布端工作流与-cli-使用指南)
  - [1. 安装发布工具 shipup-cli](#1-安装发布工具-shipup-cli)
  - [2. 生成 Ed25519 签名密钥对](#2-生成-ed25519-签名密钥对)
  - [3. 签署发布包并生成 Manifest](#3-签署发布包并生成-manifest)
  - [4. CI/CD 自动化多平台合并发布](#4-cicd-自动化多平台合并发布)
- [五、 常见问题排查 (FAQ)](#五-常见问题排查-faq)

---

## 一、 架构总览与更新生命周期

`shipup` 采用纯粹独立的、零 UI 绑定的状态机驱动架构，将自更新生命周期明确拆分为四个确定性的阶段：

1. **元数据检测阶段 (Check)**：
   客户端基于当前架构与版本，向配置的端点发起请求。遇到网络或 5xx 故障自动故障转移（Failover）；结合用户偏好（跳过/静默）与版本比较器判定是否需要升级。
2. **下载校验阶段 (Download)**：
   通过断点续传（HTTP Range）下载安装包至同卷安全临时目录。计算流式 SHA-256 校验传输完整性，并基于公钥环执行 Ed25519 非对称密码学验签。
3. **物理安装阶段 (Install)**：
   根据安装包类型（单二进制 / 压缩归档 / 独立安装器）执行原地原子替换、沙箱解压同步或脱离父进程树派生安装器。
4. **优雅重启与自愈阶段 (Restart & Recovery)**：
   主进程释放单实例锁并退出，拉起新版本进程；新版本在观察期内检测平稳运行后确认升级，若连续启动崩溃则自动原子回滚至稳定旧版本。

```
[检查端点 (多源容灾)]
        |
        v
[解析 Manifest / 通道路由] ----> (无需更新 / 用户跳过 / 稍后提醒中) ----> 流程结束
        |
        v (发现新版本)
[流式下载 (Range 断点续传)]
        |
        v
[SHA-256 完整性哈希校验]
        |
        v
[Ed25519 多公钥数字签名验证]
        |
        v
[产出 DownloadedUpdate 待安装句柄]
        |
   +----+--------------------------------+
   | (用户确认 / 空闲时调度 install())   |
   v                                     v
[单二进制 / 归档沙箱]            [外部安装器 (EXE / MSI / PKG)]
   |                                     |
   v (记录旧备份与自愈标记)              v (注入静默参数 / UAC 提权)
[原地原子替换 (文件锁绕过)]       [派生脱离进程树的独立安装进程]
   |                                     |
   +-----------------+-------------------+
                     |
                     v
       [优雅重启 (清理资源 / 退出)]
                     |
                     v
       [新版本启动自检 / 连续崩溃自动回滚]
```

---

## 二、 快速上手

### 1. 添加依赖与特性选择

在应用项目的 `Cargo.toml` 中引入 `shipup`。根据项目运行模型开启对应特性：

```toml
[dependencies]
# 同步阻塞模式（适用于 Slint、Egui、常规终端 CLI）
shipup = { version = "0.3.0", features = ["blocking"] }

# 或原生异步模式（适用于 GPUI、Tokio 异步运行时）
# shipup = { version = "0.3.0", features = ["async"] }
```

### 2. 同步阻塞模式 (Blocking Mode)

```rust
use shipup::{Updater, UpdateEvent};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 在 main 函数首行前置执行启动健康检查与崩溃自愈
    shipup::check_and_recover_current(2)?;

    // 2. 流式链式构建更新器
    let updater = Updater::builder()
        .current_version("1.0.0")?
        .manifest_url("https://updates.example.com/release/latest.json")
        .public_key("YOUR_BASE64_ED25519_PUBLIC_KEY")
        .timeout(Duration::from_secs(15))
        .build()?;

    // 3. 检查是否有新版本
    if let Some(update) = updater.check()? {
        println!("检测到新版本: {}", update.version());

        // 4. 下载更新包并校验完整性与签名（产出已下载句柄）
        let downloaded = update.download(|event| match event {
            UpdateEvent::DownloadProgress { percent, speed_bytes_per_sec, .. } => {
                if let Some(p) = percent {
                    println!("下载进度: {:.1}%, 速率: {:?} B/s", p, speed_bytes_per_sec);
                }
            }
            UpdateEvent::VerifyingSignature => println!("正在验证数字签名..."),
            _ => {}
        })?;

        // 5. 执行物理替换或拉起外部安装器
        downloaded.install(|event| {
            if event == UpdateEvent::ReadyToRestart {
                println!("更新替换完成，准备重启！");
            }
        })?;

        // 6. 优雅自重启
        update.restart_with(|ctx| {
            ctx.before_exit(|| {
                println!("正在保存文档、注销快捷键与释放单实例互斥锁...");
            });
        })?;
    }

    // 7. 宿主程序主流程平稳运行后，显式确认升级成功闭环
    shipup::confirm_update_success()?;

    Ok(())
}
```

### 3. 异步原生模式 (Async Mode)

```rust
use shipup::{Updater, UpdateEvent};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    shipup::check_and_recover_current(2)?;

    let updater = Updater::builder()
        .current_version(env!("CARGO_PKG_VERSION"))?
        .manifest_url("https://updates.example.com/release/latest.json")
        .public_key("YOUR_BASE64_ED25519_PUBLIC_KEY")
        .timeout(Duration::from_secs(15))
        .build()?;

    if let Some(update) = updater.check_async().await? {
        println!("异步发现新版本: {}", update.version());

        let downloaded = update.download_async(|event| {
            // 异步进度事件通知
        }).await?;

        downloaded.install(|_| {})?;
        update.restart()?;
    }

    shipup::confirm_update_success()?;
    Ok(())
}
```

---

## 三、 核心功能场景实战

### 1. 多端点冗余配置与故障转移 (Failover)

为防范单一 CDN 节点故障或域名遭封禁，可在构建更新器时配置多个端点。检查更新时将按顺序请求，前序端点超时或遭遇非 2xx 响应时自动切换下一备用端点：

```rust
let updater = Updater::builder()
    .current_version("1.0.0")?
    .endpoints(vec![
        "https://primary-cdn.example.com/updates/latest.json",
        "https://backup-cdn.example.com/updates/latest.json",
        "https://origin-server.example.com/api/v1/updates/latest.json",
    ])
    .public_key("YOUR_BASE64_ED25519_PUBLIC_KEY")
    .build()?;
```

### 2. 动态端点 URL 模板解析

更新端点 URL 支持内嵌动态占位符，由 `shipup` 在发起请求前自动根据系统上下文求值展开，方便后端做架构分流、灰度放量或访问统计：

- `{{target}}`：完整 Target Triple，例如 `x86_64-pc-windows-msvc`
- `{{arch}}`：CPU 架构，例如 `x86_64`、`aarch64`
- `{{os}}`：操作系统，例如 `windows`、`macos`、`linux`
- `{{current_version}}`：当前程序版本，例如 `1.2.0`
- `{{channel}}`：发布通道，例如 `stable`、`beta`

```rust
let updater = Updater::builder()
    .current_version("1.2.0")?
    .channel("beta")
    .manifest_url("https://api.example.com/v1/manifest/{{channel}}/{{target}}?from={{current_version}}")
    .public_key("...")
    .build()?;
```

### 3. 多公钥配置与平滑密钥轮换

当旧签名私钥到期或意外泄漏需要迁移时，可在客户端配置多枚公钥。验签时采用宽容机制（任一公钥校验通过即视为合法），保证存量客户端能平滑迁移：

```rust
let updater = Updater::builder()
    .current_version("1.0.0")?
    .manifest_url("https://updates.example.com/latest.json")
    // 配置多枚信任公钥（旧公钥与新公钥共存）
    .public_keys(vec![
        "PRIMARY_OLD_PUBLIC_KEY_BASE64",
        "NEW_ROTATED_PUBLIC_KEY_BASE64",
    ])
    .build()?;
```

### 4. 强制传输安全与明文协议防呆

为了防止中间人劫持重写下载地址或版本号，`shipup` 在生产模式下默认强制校验 HTTPS 协议。若端点或安装包包含明文 `http://`，构建时将直接报错阻断：

```rust
// 尝试使用明文 HTTP 将在 build() 时报错：UpdateError::InsecureTransportProtocol
let result = Updater::builder()
    .current_version("1.0.0")?
    .manifest_url("http://insecure.example.com/latest.json")
    .build();

assert!(result.is_err());

// 仅在受控开发测试环境下可显式覆盖（生产环境严禁开启）
let dev_updater = Updater::builder()
    .current_version("1.0.0")?
    .manifest_url("http://127.0.0.1:8080/latest.json")
    .dangerous_insecure_transport_protocol(true)
    .require_signature(false)
    .build()?;
```

### 5. 发布环境强制安全验签模式

在发布构建（Release Profile）下，`require_signature` 默认为 `true`。若未配置任何公钥或远程发布包缺少数字签名，更新器将拒绝执行并返回错误，彻底杜绝 Fail-Open 漏洞：

```rust
let updater = Updater::builder()
    .current_version("1.0.0")?
    .manifest_url("https://updates.example.com/latest.json")
    .require_signature(true) // 强制必须具备公钥与签名校验
    .public_key("YOUR_BASE64_ED25519_PUBLIC_KEY")
    .build()?;
```

### 6. 自定义版本比较器注入

针对非 SemVer 强递增的升级诉求（例如允许灰度构建、日期版本号、补丁更新或支持受控降级回滚），可注入自定义闭包：

```rust
let updater = Updater::builder()
    .current_version("2.0.0")?
    .manifest_url("https://updates.example.com/latest.json")
    .public_key("...")
    // 自定义比较逻辑：输入当前版本与远端版本引用，返回 true 即代表需要安装更新
    .version_comparator(|current, remote| {
        // 支持安全回滚至特定稳定版本
        if remote.major < current.major {
            return true;
        }
        remote > current
    })
    .build()?;
```

### 7. Windows 标准安装模式与 UAC 提权

对于大型桌面应用（分发 NSIS、Inno Setup 的 `.exe` 或 `.msi`），可配置标准化静默参数，并支持在需要时触发系统 UAC 凭据提权：

```json
{
  "version": "2.0.0",
  "packages": {
    "x86_64-pc-windows-msvc": {
      "url": "https://updates.example.com/MyApp-2.0.0-Setup.exe",
      "package_type": "installer",
      "install_mode": "passive",
      "require_elevation": true,
      "checksum": "sha256:...",
      "signature": "..."
    }
  }
}
```

- `install_mode` 可选：
  - `passive`：被动模式（显示安装进度条，无需用户手动点击下一步）。
  - `quiet`：完全静默模式（MSI 下注入 `/qn /norestart`，EXE 下注入 `/S`）。
  - `basicUi`：基础界面模式。
- `require_elevation`：为 `true` 时自动通过系统权限调用拉起管理员权限对话框。

### 8. 用户更新偏好管理 (跳过版本与稍后提醒)

支持持久化存储用户跳过指定版本的意图及稍后提醒静默期：

```rust
let updater = Updater::builder()
    .current_version("1.0.0")?
    .manifest_url("https://updates.example.com/latest.json")
    .public_key("...")
    .build()?;

// 1. 用户点击“跳过此版本”
updater.skip_version(semver::Version::parse("1.2.0")?)?;

// 2. 用户点击“稍后提醒（24 小时后）”
updater.snooze(Duration::from_secs(24 * 3600))?;

// 3. 用户在设置界面点击“重置更新偏好”
updater.clear_preferences()?;
```

> **注意**：若 Manifest 声明了 `force_update: true` 或版本低于 `min_supported_version`（强制更新），更新器将忽略跳过与稍后提醒设置，确保安全修复覆盖率。

### 9. 两阶段解耦更新 (下载与安装分离)

传统的自更新库往往将下载与替换绑定在一处执行。`shipup` 提供了严格解耦的两阶段 API，支持在后台预先下载好更新包，在用户保存完工作或空闲时再执行安装：

```rust
// 阶段一：纯下载与密码学验签（不修改磁盘任何已有文件）
let downloaded = update.download(|event| {
    // 监听网络下载进度
})?;

println!("更新包下载完毕，暂存于: {}", downloaded.downloaded_path().display());

// 阶段二：在合适的业务时机触发物理安装
downloaded.install(|event| {
    if event == UpdateEvent::ReadyToRestart {
        println!("安装完毕，准备重启生效");
    }
})?;
```

### 10. 后台周期性静默轮询调度器 (AutoPoller)

`shipup` 内置了开箱即用的后台自动巡检工作器，支持线程模型（`blocking`）与异步协程模型（`async`）。开启 `silent_download` 时，后台仅预载更新包并产出 `DownloadedUpdate`，绝对不会在后台物理替换正在运行的应用程序：

```rust
use shipup::{AutoPollOptions, AutoPollEvent};

let poll_options = AutoPollOptions::default()
    .interval(Duration::from_secs(4 * 3600)) // 每 4 小时检查一次
    .check_immediately(true)                // 启动时立即初检
    .silent_download(true);                 // 发现新版本后后台静默预载

let handle = updater.start_polling_thread(poll_options, |event| {
    match event {
        AutoPollEvent::Checking => {
            log::info!("正在后台检查新版本...");
        }
        AutoPollEvent::NewVersionAvailable(update) => {
            log::info!("发现新版本: {}", update.version());
        }
        AutoPollEvent::Downloading(_) => {
            log::info!("正在后台静默下载更新包...");
        }
        AutoPollEvent::UpdateReady(downloaded) => {
            // 更新包已在后台下载校验完毕，已安全暂存就绪！
            // 此时可通知用户弹窗：“新版本已就绪，点击重启即可生效”
            log::info!("新版本已暂存就绪，目标版本: {}", downloaded.version());
        }
        AutoPollEvent::UpToDate => {
            log::debug!("当前已是最新版本");
        }
        AutoPollEvent::Error(err) => {
            log::warn!("后台检查发生可恢复错误: {}", err);
        }
    }
})?;

// 应用程序退出时可显式中止后台轮询
handle.stop();
```

### 11. 优雅重启与 Windows 运行锁绕过

在 Windows 系统下，由于操作系统强制锁定正在运行的可执行文件二进制，常规原地覆写会抛出文件被占用的拒绝访问错误。`shipup` 在底层通过重命名绕过机制将旧程序移至 `.shipup.old`，新版本启动时自动静默清理。

重启时可注入退出前清理回调：

```rust
update.restart_with(|ctx| {
    ctx.before_exit(|| {
        // 在这里释放全局命名互斥锁（Named Mutex）
        // 保存未完成的工作文档
        // 关闭数据库连接池
    });
})?;
```

### 12. 灾难自愈与异常崩溃自动回滚

当新版本因打包遗漏动态链接库、第三方依赖冲突或代码严重缺陷导致应用启动后立即崩溃闪退时，传统的更新器会使客户端陷入无限崩溃死锁。`shipup` 内置了灾难自愈状态机：

1. **入口前置自检**：在 `main` 函数第一行调用 `shipup::check_and_recover_current(2)`。
2. **崩溃计数判定**：如果新版本启动连续崩溃超过容忍上限（`DEFAULT_MAX_CRASH_ATTEMPTS` 默认 2，即第 3 次启动时），自动使用稳定旧版本备份原子覆盖崩溃二进制，完成自愈。
3. **确认升级闭环**：当应用完成启动并平稳运行（如主界面加载完毕）后，调用 `shipup::confirm_update_success()` 销毁旧备份与状态标记，退出观察期。

---

## 四、 发布端工作流与 CLI 使用指南

### 1. 安装发布工具 shipup-cli

```powershell
cargo install shipup-cli
```

### 2. 生成 Ed25519 签名密钥对

```powershell
shipup-cli keygen -o ./keys
```

执行后将在 `./keys` 目录下生成两个文件：
- `ed25519.key`：私钥（Base64 编码，**极高机密**，严禁提交到代码仓库或公开）。
- `ed25519.pub`：公钥（Base64 编码，配置在客户端的 `UpdaterBuilder` 中）。

### 3. 签署发布包并生成 Manifest

```powershell
# 针对 Windows x86_64 发布单文件或安装器
shipup-cli release \
  --version 1.2.0 \
  --target x86_64-pc-windows-msvc \
  --package ./dist/myapp-1.2.0.exe \
  --url https://updates.example.com/downloads/myapp-1.2.0.exe \
  --package-type binary \
  --key ./keys/ed25519.key \
  --notes "1. 新增深色模式支持\n2. 修复数据同步偶发异常" \
  --manifest ./dist/latest.json
```

生成的 `latest.json` 示例：

```json
{
  "version": "1.2.0",
  "min_supported_version": null,
  "force_update": false,
  "pub_date": "2026-09-09T12:00:00Z",
  "notes": "1. 新增深色模式支持\n2. 修复数据同步偶发异常",
  "packages": {
    "x86_64-pc-windows-msvc": {
      "url": "https://updates.example.com/downloads/myapp-1.2.0.exe",
      "signature": "MEYCIQDx...BASE64_ED25519_SIGNATURE...",
      "checksum": "sha256:a1b2c3d4e5...",
      "package_type": "binary"
    }
  }
}
```

### 4. CI/CD 自动化多平台合并发布

`shipup-cli release` 具备**智能增量合并**特性：若目标 `--manifest` 文件已经存在，再次执行时会自动保留已存在的其他平台配置，仅新增或更新当前 `--target` 的配置：

```yaml
# GitHub Actions 示例片段
- name: 签署 Windows 构建成果并更新清单
  run: |
    shipup-cli release \
      --version ${{ github.ref_name }} \
      --target x86_64-pc-windows-msvc \
      --package ./target/release/myapp.exe \
      --url https://cdn.example.com/releases/${{ github.ref_name }}/myapp-windows.exe \
      --package-type binary \
      --key ./keys/ed25519.key \
      --manifest ./dist/latest.json

- name: 签署 macOS aarch64 构建成果并增量合并至清单
  run: |
    shipup-cli release \
      --version ${{ github.ref_name }} \
      --target aarch64-apple-darwin \
      --package ./target/release/myapp-mac.tar.gz \
      --url https://cdn.example.com/releases/${{ github.ref_name }}/myapp-mac.tar.gz \
      --package-type archive \
      --executable-path "MyApp.app/Contents/MacOS/myapp" \
      --key ./keys/ed25519.key \
      --manifest ./dist/latest.json
```

---

## 五、 故障排查手册与安全生产最佳实践 (Troubleshooting & Best Practices)

### 1. 数字签名与验签失败诊断指南

#### (1) 多公钥验签失败 (`MultiKeyVerificationFailed`)
- **错误表现**：`多候选公钥验签全部失败（共尝试 N 个候选公钥）: [公钥 #1: ...; 公钥 #2: ...]`。
- **诊断方法**：`shipup` 在所有候选公钥均验证失败时，会在错误信息中详尽聚合每一个候选公钥的具体失败原因：
  1. 若提示 `Base64 解码错误`：检查客户端配置的公钥字符串是否包含换行符、首尾多余空格或错误截断。
  2. 若提示 `Ed25519 公钥格式非法（必须为 32 字节）`：说明公钥长度不正确，应重新通过 `shipup-cli keygen` 生成并比对。
  3. 若提示 `数字签名无效或文件已被篡改`：说明该候选公钥与签名私钥不配对，或待验签数据被篡改。
- **应对方案**：在公钥平滑轮换期间，确保客户端公钥列表同时包含**当前正在使用的旧公钥**与**计划上线的新公钥**。

#### (2) 签名配置缺失 (`MissingSignature`)
- **错误表现**：`签名配置缺失: 客户端启用了验签但 Manifest 未包含签名`。
- **根本原因**：`shipup` 默认强制开启数字签名验证（`require_signature: true`），若远端 `manifest.json` 未包含顶层 `signature` 字段或目标安装包缺失 `signature`，更新将被阻断以防机会性降级投毒。
- **应对方案**：在发布流水线中必须使用 `shipup-cli release --key <path>` 完成清单与发布包签署。本地测试若明确不需要签名，可通过 `.require_signature(false)` 显式关闭。

#### (3) 重放攻击与过期拒绝 (`ManifestExpired` / `StaleManifestVersion`)
- **错误表现**：`Manifest 已于 ... 过期失效` 或 `清单版本序号滞后`。
- **安全机制**：若 Manifest 声明了 `expires_at` 或 `version_seq`，客户端在验签成功后强制核验时间戳与序号单调递增性。
- **应对方案**：发布新版本时确保系统时间与 UTC 保持同步，且 `version_seq` 严格单调递增；更新 CDN 缓存策略，杜绝长期缓存过期的 `latest.json`。

---

### 2. 企业内网私有 CA 与证书固定 (Certificate Pinning)

在金融、政企或内网私有源环境下，远端服务器往往采用自签名证书或私有企业根 CA。此时系统默认证书库可能抛出 `PKIX path building failed` 或 TLS 握手异常。

#### 配置自定义 PEM 根证书
`shipup` 允许调用方在不修改操作系统全局证书信任库的前提下，为更新器专属注入受信任 PEM 证书：

```rust
let ca_pem = include_bytes!("../certs/company_internal_ca.pem");

let updater = UpdaterBuilder::new()
    .current_version("1.0.0")?
    .manifest_url("https://internal-repo.corp.com/releases/latest.json")
    .add_root_certificate_pem(ca_pem) // 注入企业自建 CA
    .build()?;
```

#### TLS 安全基线保证
- `shipup` 同步与异步 HTTP 客户端均在传输层硬性约束最低 **TLS 1.2+** 协议版本，杜绝 SSL 3.0、TLS 1.0、TLS 1.1 的中间人降级利用。
- 若需要完全脱离平台 OpenSSL 动态依赖，可在 `Cargo.toml` 中切换为纯 Rust 静态编译的 `rustls-tls` 特性：
  ```toml
  shipup = { version = "0.3.0", default-features = false, features = ["blocking", "rustls-tls", "archive"] }
  ```

---

### 3. 企业代理与受限网络穿透指南

针对内网隔离、透明代理或网关鉴权环境：

```rust
let updater = UpdaterBuilder::new()
    .current_version("1.0.0")?
    .manifest_url("https://updates.example.com/manifest.json")
    // 配置 HTTP / SOCKS5 代理网关
    .proxy("http://proxy.corp.com:8080")
    // 注入自定义网关鉴权令牌
    .header("Authorization", "Bearer eyJhbGciOi...")
    // 注入自定义租户与客户端版本标识
    .header("X-Client-Tenant", "finance-dept")
    .timeout(std::time::Duration::from_secs(30))
    .build()?;
```

---

### 4. 本地持久化与回滚目录布局说明

`shipup` 采取严格的防御性与同卷写入设计，各物理文件在磁盘上的分布拓扑如下：

```
[可执行程序同级目录或安全数据目录]
├── myapp.exe                     # 当前运行的主程序二进制
├── myapp.exe.shipup.{version}.old # 物理替换前按版本备份的旧二进制（用于自愈回滚与主动回滚）
├── myapp.exe.{token}.{rnd}.shipup.tmp # 同卷临时写入切片（带高熵随机数防预测与预占投毒）
├── .shipup.state                  # 启动观察期健康状态机标记（崩溃计数与备份路径）
├── .shipup.history                # 历史版本回滚记录（受 max_rollback_entries 限制）
└── .shipup_preference.json        # 用户偏好状态（跳过版本、稍后提醒时间戳与客户端唯一匿名 UUID）

[系统通用临时目录 (如 /tmp 或 %TEMP%)]
└── shipup_installer_{token}_{rnd}/ # 安装器专用隔离目录（Unix 权限严格限制为 0700 私有模式）
    └── installer.exe              # 待拉起的完整物理安装程序
```

- **备份生命周期**：版本化备份 `{exe}.shipup.{version}.old` 由回滚历史管理；`{exe}.shipup.old` 会在下一次应用程序初始化并确认新版本运行稳定后由 `cleanup_old_backups()` 自动销毁。
- **孤儿临时切片防泄露**：Windows、macOS 与 Linux 下若遇到下载断电或进程强退，修改时间超过 24 小时的孤儿临时切片会在下次程序启动时静默回收。
- **回滚历史保护**：`.shipup.history` 记录了最近多次升级的版本号与备份文件路径；`.shipup.state` 记录健康观察期状态。若启动尝试次数超过容忍上限（`DEFAULT_MAX_CRASH_ATTEMPTS` 默认 2，即第 3 次启动时），系统将在无需人工干预的情况下原子恢复至上一版本。

