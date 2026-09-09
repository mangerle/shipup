# shipup

A universal, lightweight, UI-agnostic cross-platform self-updating system for desktop applications.

English | [简体中文](README_ZH.md)

---

## Core Features

- **Pure & UI-Agnostic**: Imposes no assumptions on GUI frameworks or async runtimes. Seamlessly integrates with GPUI, Slint, egui, Iced, as well as CLI and backend daemon services.
- **Multiple Update Strategies**: Supports in-place atomic binary replacement, archive extraction sandbox replacement (.zip / .tar.gz), and external installer takeover for complex installers.
- **Native Dual Modes**: Built on top of `reqwest`, offering out-of-the-box support for both synchronous blocking (`blocking`) and asynchronous native (`async`) APIs, customizable via Cargo feature flags.
- **Enterprise-Grade Security Defense**:
  - Layer 1: Streaming SHA-256 integrity verification against corrupt downloads.
  - Layer 2: High-performance pure-Rust Ed25519 asymmetric cryptographic signature verification.
  - Layer 3: Zip Slip path traversal mitigation and decompression size limit circuit breaking.
- **Cross-Platform Robustness**:
  - Same-volume atomic staging strategy preventing cross-filesystem `EXDEV: Cross-device link` errors.
  - Deep adaptation for Windows executable file locks via atomic rename and self-cleanup helper processes.
  - Automatic permission bit fixing (0o755) on Linux and Gatekeeper quarantine attribute removal on macOS.
- **Release Ecosystem**: Ships with an out-of-the-box CLI tool `shipup-cli` for cryptographic key generation (`keygen`) and manifest building/signing (`release`).

---

## Quick Start

### 1. Add Dependency

Add `shipup` to your application's `Cargo.toml`:

```toml
[dependencies]
shipup = "0.1.0"
```

### 2. Client Update Checking and Installation

```rust
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use shipup::{Updater, UpdateEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build the updater instance
    let updater = Updater::builder()
        .current_version("1.0.0")?
        .manifest_url("https://updates.example.com/latest.json")
        .channel("stable")
        .public_key("your_base64_ed25519_public_key...")
        .timeout(Duration::from_secs(15))
        .build()?;

    // Check for updates
    if let Some(update) = updater.check()? {
        println!("New update found: {}", update.version());

        // Download and apply update
        let cancel_flag = Arc::new(AtomicBool::new(false));
        update.download_and_install_with_cancellation(
            Some(cancel_flag),
            |event| match event {
                UpdateEvent::DownloadStarted { total_bytes } => {
                    println!("Download started, file size: {:?}", total_bytes);
                }
                UpdateEvent::DownloadProgress { percent, .. } => {
                    if let Some(p) = percent {
                        println!("Download progress: {:.1}%", p);
                    }
                }
                UpdateEvent::Installing => println!("Applying update and replacing files..."),
                UpdateEvent::ReadyToRestart => println!("Installation completed. Ready to restart."),
                _ => {}
            },
        )?;

        // Graceful self-restart
        update.restart_with(|ctx| {
            ctx.before_exit(|| {
                println!("Releasing single-instance locks and cleaning up runtime state...");
            });
        })?;
    }

    Ok(())
}
```

---

## Release Tool (shipup-cli)

`shipup` provides a companion CLI tool `shipup-cli` for keypair management and manifest signing.

### 1. Install CLI Tool
```powershell
cargo install shipup-cli
```

### 2. Generate Ed25519 Keypair
```powershell
shipup-cli keygen -o ./keys
```
This generates `ed25519.key` (private key, keep confidential) and `ed25519.pub` (public key, embedded in client applications) in the `./keys` directory.

### 3. Build and Sign Manifest
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

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
