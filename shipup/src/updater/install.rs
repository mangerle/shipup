//! 更新包物理安装与应用模块。
//!
//! # 模块职责
//! 承载两阶段生命周期中的第二阶段——把已完成哈希与数字签名校验的本地暂存包
//! 「物理落地」到宿主程序运行位置：二进制原地原子替换、归档包沙箱解压同步、外部安装器派生。
//!
//! # 设计原理
//! - **实现初衷**：把「对本地磁盘的破坏性修改」从下载流程中彻底剥离，
//!   使调用方可以先把三个安装形态的差异（二进制 / 归档 / 安装器）集中在本模块裁决，
//!   而不是散落在下载入口。
//! - **核心优势**：替换前统一建立物理备份并写入回滚状态记录，
//!   使「更新失败」具备可逆性；归档形态在独立沙箱目录内解压与二次校验后再同步，天然隔离 Zip Slip 风险。
//! - **代价与局限**：备份与回滚记录会额外占用一份当前可执行文件体积的磁盘空间。
//!
//! # 关键契约
//! - 安装动作一旦开始便会修改运行中的程序文件，属于不可回退的显式操作；调用方须通过
//!   [`crate::DownloadedUpdate::install`] 主动触发，不得由下载流程隐式发起。
//! - 任何失败路径都必须保留已建立的历史备份，确保 `recovery` 模块仍可完成自愈回滚。

use crate::archive::{extract_archive, sync_extracted_payload};
use crate::error::Result;
use crate::event::UpdateEvent;
use crate::manifest::{PackageType, ResolvedRelease};
use crate::platform::{InstallerOptions, replace_binary, spawn_installer};
use semver::Version;
use std::fs;
use std::path::{Path, PathBuf};

/// 执行二进制替换，若原地替换受阻且配置了允许重启延迟替换则安全降级
fn perform_replace_with_fallback<F>(
    new_binary: &Path,
    version: &str,
    allow_reboot_deferred: bool,
    callback: &mut F,
) -> Result<bool>
where
    F: FnMut(UpdateEvent),
{
    match replace_binary(new_binary) {
        Ok(()) => Ok(false),
        Err(e) => {
            #[cfg(windows)]
            if allow_reboot_deferred {
                log::warn!(
                    "Windows 原地替换可执行程序受阻 ({e})，尝试降级为系统重启延迟替换 (MoveFileEx)..."
                );
                let current_exe = std::env::current_exe()?;
                let parent = current_exe.parent().unwrap_or_else(|| Path::new("."));
                let pending_path =
                    parent.join(format!(".shipup_reboot_pending_{}.exe", std::process::id()));
                fs::copy(new_binary, &pending_path)?;
                crate::platform::schedule_reboot_replace(&pending_path, &current_exe)?;
                callback(UpdateEvent::DeferredToReboot {
                    version: version.to_string(),
                    pending_path,
                });
                return Ok(true);
            }
            #[cfg(not(windows))]
            let _ = (version, allow_reboot_deferred, &mut *callback);

            Err(e)
        }
    }
}

/// 载荷落地所需的上下文与事件回调（参数对象模式）。
///
/// # 设计原理
/// - **实现初衷**：三种安装形态共享同一批入参（当前版本、发布元数据、暂存路径、回滚上限、
///   重启降级开关、事件回调）。若继续以平铺参数在多个处理函数之间传递，既突破参数数量上限，
///   也会在新增参数时留下「只改了一处」的漏改隐患。
/// - **核心优势**：参数集合单点定义，后续扩展只需修改结构体与唯一的构造处。
/// - **代价与局限**：引入一层结构体间接，阅读时需要先确认各字段含义。
pub(super) struct PayloadApplyContext<'a, F> {
    /// 当前正在运行的本地版本
    pub(super) current_version: &'a Version,
    /// 已通过哈希与签名校验的目标发布元数据
    pub(super) release: &'a ResolvedRelease,
    /// 已完成校验的本地暂存包路径
    pub(super) temp_path: &'a Path,
    /// 回滚历史最大保留条目数
    pub(super) max_rollback_entries: usize,
    /// 是否允许在就地替换受阻时降级为系统重启延迟替换
    pub(super) allow_reboot_deferred_replace: bool,
    /// 安装进度事件回调
    pub(super) callback: &'a mut F,
}

impl<F: FnMut(UpdateEvent)> PayloadApplyContext<'_, F> {
    /// 依据包体安装形态分派到对应的落地策略。
    ///
    /// 三种形态的差异全部收敛在此处，调用方无需感知 Binary / Archive / Installer 的区别。
    ///
    /// # Errors
    /// 当备份创建失败、解压或载荷校验失败、原子替换失败、派生安装器失败时，
    /// 返回对应的 [`crate::UpdateError`]。
    pub(super) fn apply(&mut self) -> Result<()> {
        match self.release.package.package_type {
            PackageType::Binary => self.apply_binary(),
            PackageType::Archive => self.apply_archive(),
            PackageType::Installer => self.apply_installer(),
        }
    }

    /// 二进制形态：在当前卷内以原子重命名方式替换正在运行的可执行文件。
    ///
    /// # Errors
    /// 备份创建失败、原子替换失败且不允许重启延迟替换时返回错误。
    fn apply_binary(&mut self) -> Result<()> {
        (self.callback)(UpdateEvent::Installing);
        let backup_path = prepare_backup_before_replace(self.current_version)?;
        let is_deferred = perform_replace_with_fallback(
            self.temp_path,
            &self.release.version.to_string(),
            self.allow_reboot_deferred_replace,
            self.callback,
        )?;
        let _ = fs::remove_file(self.temp_path);
        self.record_outcome(backup_path.as_deref());
        if !is_deferred {
            (self.callback)(UpdateEvent::ReadyToRestart);
        }
        Ok(())
    }

    /// 归档形态：沙箱解压 → 载荷二次校验 → 伴随资源同步 → 主程序替换。
    ///
    /// 沙箱目录与暂存包在成功与失败路径上都会被回收，避免磁盘残留。
    ///
    /// # Errors
    /// 解压失败、载荷校验失败、资源同步失败或主程序替换失败时返回错误。
    fn apply_archive(&mut self) -> Result<()> {
        (self.callback)(UpdateEvent::ExtractingArchive);
        let sandbox_dir = self.create_sandbox_dir();

        let apply_result = self.extract_and_replace_in_sandbox(&sandbox_dir);

        // 无论成功与否都必须回收沙箱与暂存包，避免磁盘残留
        let _ = fs::remove_dir_all(&sandbox_dir);
        let _ = fs::remove_file(self.temp_path);
        let (backup_path, is_deferred) = apply_result?;

        self.record_outcome(backup_path.as_deref());
        if !is_deferred {
            (self.callback)(UpdateEvent::ReadyToRestart);
        }
        Ok(())
    }

    /// 安装器形态：按平台约定展开静默安装参数并脱离父进程树派生。
    ///
    /// # Errors
    /// 派生安装器进程失败时返回错误。
    fn apply_installer(&mut self) -> Result<()> {
        (self.callback)(UpdateEvent::Installing);
        let installer_options = InstallerOptions {
            user_args: &self.release.package.install_args,
            install_mode: self.release.package.install_mode,
            require_elevation: self.release.package.require_elevation,
            wait_for_exit: self.release.package.wait_for_exit,
        };
        spawn_installer(self.temp_path, &installer_options)?;
        (self.callback)(UpdateEvent::ReadyToRestart);
        Ok(())
    }

    /// 创建本次解压专用的隔离沙箱目录。
    ///
    /// 目录名由「进程号 + 毫秒时间戳」组成，确保同一主机上并发或快速连续触发多次更新时，
    /// 各次解压互不干扰。
    fn create_sandbox_dir(&self) -> PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let sandbox_name = format!("shipup_sandbox_{}_{}", std::process::id(), timestamp);
        self.temp_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(sandbox_name)
    }

    /// 在沙箱内完成解压、载荷二次校验、伴随资源同步与主程序替换。
    ///
    /// 返回值为「备份路径」与「是否已降级为重启延迟替换」，供调用方决定是否需要提示重启。
    ///
    /// # Errors
    /// 解压失败、载荷哈希不符、资源同步失败或主程序替换失败时返回错误。
    fn extract_and_replace_in_sandbox(
        &mut self,
        sandbox_dir: &Path,
    ) -> Result<(Option<PathBuf>, bool)> {
        let extracted_binary = extract_archive(
            self.temp_path,
            sandbox_dir,
            self.release.package.executable_path.as_deref(),
        )?;

        // 解压后对 Manifest 声明的关键文件执行二次哈希防伪
        if !self.release.package.payload_checksums.is_empty() {
            let extract_root = extracted_binary
                .parent()
                .unwrap_or(sandbox_dir)
                .to_path_buf();
            crate::archive::verify_extracted_payload_checksums(
                &extract_root,
                &self.release.package.payload_checksums,
            )?;
        }

        (self.callback)(UpdateEvent::Installing);

        // 同步解压目录中除主程序外的全部伴随依赖（动态库、静态资源等）到宿主应用目录
        let current_exe = std::env::current_exe()?;
        if let Some(target_dir) = current_exe.parent() {
            let payload_dir = extracted_binary.parent().unwrap_or(sandbox_dir);
            sync_extracted_payload(payload_dir, target_dir, &extracted_binary)?;
        }

        let backup_path = prepare_backup_before_replace(self.current_version)?;
        let is_deferred = perform_replace_with_fallback(
            &extracted_binary,
            &self.release.version.to_string(),
            self.allow_reboot_deferred_replace,
            self.callback,
        )?;
        Ok((backup_path, is_deferred))
    }

    /// 记录本次安装的回滚状态。
    ///
    /// 仅当物理备份确实存在时才会写入记录；否则会留下指向不存在文件的孤儿条目，
    /// 导致后续主动回滚列出「看似可用但实际无法执行」的版本。
    fn record_outcome(&self, backup_path: Option<&Path>) {
        record_state_if_possible(
            self.current_version,
            &self.release.version,
            backup_path,
            self.max_rollback_entries,
        );
    }
}

fn prepare_backup_before_replace(current_version: &Version) -> Result<Option<PathBuf>> {
    #[cfg(target_os = "macos")]
    {
        if let Some(bundle) = crate::platform::macos::find_current_app_bundle() {
            if let Some(parent) = bundle.parent() {
                let bundle_name = bundle
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("app.app");
                let backup_bundle =
                    parent.join(format!("{}.shipup.{}.old", bundle_name, current_version));
                return Ok(Some(backup_bundle));
            }
        }
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("app");
        let backup_path = parent.join(format!("{}.shipup.{}.old", exe_name, current_version));
        if backup_path.exists() {
            let _ = fs::remove_file(&backup_path);
        }
        if let Err(e) = fs::copy(&current_exe, &backup_path) {
            log::warn!("创建当前可执行文件物理备份失败: {}", e);
            return Ok(None);
        }
        log::info!("已创建历史可执行文件物理备份: {}", backup_path.display());
        return Ok(Some(backup_path));
    }

    Ok(None)
}

fn record_state_if_possible(
    current_version: &Version,
    target_version: &Version,
    backup_path: Option<&Path>,
    max_rollback_entries: usize,
) {
    let target_dir = crate::preference::resolve_safe_data_dir().or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    });

    if let Some(dir) = target_dir
        && let Some(backup) = backup_path
        && backup.exists()
    {
        let _ = crate::recovery::record_update_state(&dir, &target_version.to_string(), backup);
        let _ = crate::recovery::record_rollback_version(
            &dir,
            current_version,
            backup,
            max_rollback_entries,
        );
    }
}
