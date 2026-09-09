// shipup 跨平台自更新系统 - 门面与核心接口导出
//! # shipup
//!
//! `shipup` 是一个通用、轻量级、无 UI 绑定的跨平台软件自更新（Self-Updater）系统。
//! 支持在桌面程序（GPUI、Slint、Egui、Iced 等）以及服务端和命令行程序中无缝嵌入。
//!
//! ## 核心特性
//! - 零 GUI 框架绑定，架构纯粹独立
//! - 支持二进制原地原子替换、压缩包解压沙箱替换与外部安装器无残留派生
//! - 原生支持同步阻塞（blocking）与异步（async）双调用模式
//! - 内置 SHA-256 传输完整性校验与 Ed25519 数字签名验证
//! - 防范 Zip Slip 路径越界逃逸与同卷原子写入防跨设备链接（EXDEV）错误
//! - 自动绕过 Windows 文件锁并完成启动自清理闭环

pub mod archive;
pub(crate) mod builder;
pub(crate) mod download;
pub mod error;
pub mod event;
pub mod manifest;
pub(crate) mod platform;
pub(crate) mod poller;
pub(crate) mod recovery;
pub(crate) mod restart;
pub mod signature;
pub mod template;
pub(crate) mod updater;

// 常用核心类型直接重导出
pub use builder::{UpdaterBuilder, UpdaterConfig, VersionComparator};
pub use error::{Result, UpdateError};
pub use event::UpdateEvent;
pub use manifest::{
    ChannelInfo, Manifest, PackageInfo, PackageType, ResolveOptions, ResolvedRelease,
    current_target_triple,
};
pub use platform::{cleanup_old_backups, get_same_volume_temp_path, get_temp_download_path};
pub use poller::{AutoPollEvent, AutoPollOptions, AutoPollerHandle};
pub use recovery::{
    HealthCheckStatus, check_and_recover_current, check_and_recover_once, confirm_update_success,
    confirm_update_success_in_dir,
};
pub use restart::{RestartContext, SHIPUP_RESTARTED_ARG, is_restarted_by_shipup, restart_with};
pub use template::{TemplateContext, resolve_url_template};
pub use updater::{Update, Updater};
