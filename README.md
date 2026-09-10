# shipup

A universal, lightweight, UI-agnostic cross-platform self-updating system for desktop applications.

English | [简体中文](README_ZH.md) | [Documentation (docs/USAGE.md)](docs/USAGE.md)

---

## Core Features

- **Pure & UI-Agnostic**: Imposes no assumptions on GUI frameworks or async runtimes. Seamlessly integrates with GPUI, Slint, egui, Iced, as well as CLI and backend daemon services.
- **Multiple Update Strategies**: Supports in-place atomic binary replacement, archive extraction sandbox replacement (.zip / .tar.gz), and external installer takeover for complex installers.
- **Native Dual Modes**: Built on top of `reqwest`, offering out-of-the-box support for both synchronous blocking (`blocking`) and asynchronous native (`async`) APIs, customizable via Cargo feature flags.
- **Decoupled Lifecycle**: Separates download/verification (`download()`) from local disk installation (`install()`), supporting background pre-fetching without interfering with running binaries.
- **Multi-Endpoint Failover**: Seamlessly handles CDN downtime by cycling through primary and secondary mirror endpoints.
- **Enterprise-Grade Security Defense**:
  - Layer 1: Streaming SHA-256 integrity verification against corrupt downloads.
  - Layer 2: High-performance pure-Rust Ed25519 asymmetric cryptographic signature verification with key rotation support.
  - Layer 3: Enforced TLS certificate transport verification.
  - Layer 4: Zip Slip path traversal mitigation and decompression size limit circuit breaking.
- **Cross-Platform Robustness**:
  - Same-volume atomic staging strategy preventing cross-filesystem `EXDEV: Cross-device link` errors.
  - Deep adaptation for Windows executable file locks via atomic rename and self-cleanup helper processes.
  - Automatic permission bit fixing (0o755) on Linux and Gatekeeper quarantine attribute removal on macOS.
  - Automatic startup health checks and rollback on consecutive crashes.
- **Release Ecosystem**: Ships with an out-of-the-box CLI tool `shipup-cli` for cryptographic key generation (`keygen`) and manifest building/signing (`release`).

---

## Quick Start

> For in-depth tutorials, multi-channel rollout, and CI/CD pipelines, see [Usage Guide](docs/USAGE.md).

### 1. Add Dependency

Add `shipup` to your application's `Cargo.toml`:

```toml
[dependencies]
shipup = { version = "0.3.0", features = ["blocking"] }
```

### 2. Client Update Checking and Installation

```rust
use std::time::Duration;
use shipup::{Updater, UpdateEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Startup health check (auto-rollback after consecutive crashes)
    shipup::check_and_recover_current(2)?;

    // 2. Build the updater instance
    let updater = Updater::builder()
        .current_version("1.0.0")?
        .manifest_url("https://updates.example.com/latest.json")
        .channel("stable")
        .public_key("YOUR_BASE64_ED25519_PUBLIC_KEY")
        .timeout(Duration::from_secs(15))
        .build()?;

    // 3. Check for updates
    if let Some(update) = updater.check()? {
        println!("New update found: {}", update.version());

        // 4. Download and verify (does not overwrite running binaries)
        let downloaded = update.download(|event| match event {
            UpdateEvent::DownloadProgress { percent, speed_bytes_per_sec, .. } => {
                if let Some(p) = percent {
                    println!("Download progress: {:.1}%, speed: {:?} B/s", p, speed_bytes_per_sec);
                }
            }
            UpdateEvent::VerifyingSignature => println!("Verifying digital signature..."),
            _ => {}
        })?;

        // 5. Apply binary replacement or spawn installer
        downloaded.install(|event| {
            if event == UpdateEvent::ReadyToRestart {
                println!("Installation completed. Ready to restart.");
            }
        })?;

        // 6. Graceful self-restart
        update.restart_with(|ctx| {
            ctx.before_exit(|| {
                println!("Releasing single-instance locks and cleaning up runtime state...");
            });
        })?;
    }

    // 7. Confirm the upgrade after the app has started successfully
    shipup::confirm_update_success()?;
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
