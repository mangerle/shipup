// shipup 跨平台自更新系统 - 后台周期性静默轮询与暂存调度器

use crate::error::UpdateError;
#[cfg(feature = "async")]
use crate::updater::Updater;
use crate::updater::{DownloadedUpdate, Update};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// 后台轮询事件模型
///
/// # 设计原理
/// - **实现初衷**：将后台工作线程或异步任务的生命周期状态以数据形式派发给宿主，
///   解耦更新器内部调度与宿主 UI（如系统托盘、通知中心）。
#[derive(Debug)]
pub enum AutoPollEvent {
    /// 正在后台检查更新
    Checking,
    /// 发现可用新版本
    NewVersionAvailable(Update),
    /// 正在后台静默下载安装包
    Downloading(Update),
    /// 更新包已在后台下载校验完毕，已暂存就绪，宿主可随时安排安装与重启生效
    UpdateReady(DownloadedUpdate),
    /// 当前已是最新版本
    UpToDate,
    /// 后台轮询发生可恢复网络异常或配置错误
    Error(UpdateError),
}

/// 后台轮询参数配置选项
#[derive(Debug, Clone)]
pub struct AutoPollOptions {
    /// 轮询时间间隔（例如每 4 小时一次）
    pub interval: Duration,
    /// 是否在启动时立即执行一次检查（默认为 true）
    pub check_immediately: bool,
    /// 检测到可用新版本后，是否在后台静默下载并暂存更新包（默认为 true）
    pub silent_download: bool,
}

impl Default for AutoPollOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(4 * 3600), // 默认 4 小时
            check_immediately: true,
            silent_download: true,
        }
    }
}

impl AutoPollOptions {
    /// 设置后台轮询的时间间隔时长（例如 `Duration::from_secs(3600 * 2)`）
    ///
    /// # 设计原理
    /// - **实现初衷**：为不同业务类型提供差异化的轮询频率，高频（如 1 小时）适用于关键内测，低频（如 24 小时）适用于稳定正式版。
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// 设置工作器启动时是否立即执行首次更新检测（默认为 true）
    ///
    /// # 设计原理
    /// - **实现初衷**：true 可让应用在冷启动时立即完成一次更新感知；若应用启动时有繁重初始化网络请求，可设为 false 延后一个周期检查以避免资源争抢。
    pub fn check_immediately(mut self, check: bool) -> Self {
        self.check_immediately = check;
        self
    }

    /// 设置检测到可用新版本后是否在后台静默下载并暂存更新包（默认为 true）
    ///
    /// # 设计原理
    /// - **实现初衷**：为桌面用户提供“无感预载”极致体验。后台仅下载与验签（产出 [`DownloadedUpdate`] 并触发 [`AutoPollEvent::UpdateReady`]），不发生任何正在运行二进制的磁盘覆盖。
    /// - **关闭场景**：当希望仅通知用户有新版本、并在用户显式点击界面“立即下载”时再发起下载时，可将此项设为 false。
    pub fn silent_download(mut self, silent: bool) -> Self {
        self.silent_download = silent;
        self
    }
}

/// 后台轮询控制器句柄
///
/// # 设计原理
/// - **实现初衷**：为宿主提供对常驻后台巡检与单次下载的精准取消控制能力。
/// - **核心优势**：基于独立原子布尔标志位解耦调度器与单次下载生命周期；句柄支持自由传递与丢弃，绝不在句柄析构时误杀常驻任务。
#[derive(Debug, Clone)]
pub struct AutoPollerHandle {
    stop_flag: Arc<AtomicBool>,
    download_cancel_flag: Arc<AtomicBool>,
}

impl AutoPollerHandle {
    #[cfg(feature = "async")]
    pub(crate) fn new(stop_flag: Arc<AtomicBool>, download_cancel_flag: Arc<AtomicBool>) -> Self {
        Self {
            stop_flag,
            download_cancel_flag,
        }
    }

    /// 停止后台轮询任务与所有在途下载
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        self.download_cancel_flag.store(true, Ordering::Relaxed);
        log::info!("已请求中止后台自更新轮询工作器");
    }

    /// 仅取消当前正在执行的单次静默下载，不终止周期性轮询调度
    pub fn cancel_current_download(&self) {
        self.download_cancel_flag.store(true, Ordering::Relaxed);
        log::info!("已请求取消当前正在进行的静默下载任务");
    }

    /// 检查后台任务是否已被请求停止
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Relaxed)
    }
}

#[cfg(feature = "blocking")]
/// 启动基于操作系统独立原生线程的后台周期性轮询工作器
///
/// # 设计原理
/// - **实现初衷**：为基于同步模型或带有 GUI 主事件循环的桌面程序（如 Slint、Egui）提供非阻塞的后台更新巡检机制。
/// - **核心优势**：
///   - 独立线程调度，绝对杜绝耗时网络检查或百兆更新包下载阻塞 GUI 渲染帧率。
///   - 睡眠切片算法：将大跨度长等待拆分为 500ms 检查片，确保调用 [`AutoPollerHandle::stop`] 时可在半秒内快速响应退出。
/// - **代价与局限**：占用一个操作系统原生线程资源。
///
/// # 参数
/// * `updater`: 更新器实例（内部状态 Arc 共享）
/// * `options`: 轮询频率与行为策略
/// * `callback`: 事件通知闭包，负责向宿主派发轮询状态事件
///
/// # Errors
/// 当向底层操作系统申请创建原生线程失败时，返回 [`std::io::Error`]。
pub fn spawn_polling_thread<F>(
    updater: Updater,
    options: AutoPollOptions,
    mut callback: F,
) -> std::io::Result<AutoPollerHandle>
where
    F: FnMut(AutoPollEvent) + Send + 'static,
{
    let stop_flag = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop_flag);
    let download_cancel_flag = Arc::new(AtomicBool::new(false));
    let worker_download_cancel = Arc::clone(&download_cancel_flag);

    std::thread::Builder::new()
        .name("shipup-poller".to_string())
        .spawn(move || {
            log::info!(
                "后台同步轮询工作线程已启动，检测间隔: {:?}",
                options.interval
            );
            let mut first_run = true;

            while !worker_stop.load(Ordering::Relaxed) {
                if first_run && !options.check_immediately {
                    first_run = false;
                } else {
                    first_run = false;
                    callback(AutoPollEvent::Checking);
                    match updater.check() {
                        Ok(Some(update)) => {
                            if options.silent_download {
                                callback(AutoPollEvent::Downloading(update.clone()));
                                worker_download_cancel.store(false, Ordering::Relaxed);
                                let cancel_token = Some(Arc::clone(&worker_download_cancel));
                                match update.download_with_cancellation(cancel_token, |_| {}) {
                                    Ok(downloaded) => {
                                        callback(AutoPollEvent::UpdateReady(downloaded))
                                    }
                                    Err(UpdateError::Cancelled) => {
                                        log::info!("后台静默下载更新包已被取消，保持周期轮询调度");
                                    }
                                    Err(e) => callback(AutoPollEvent::Error(e)),
                                }
                            } else {
                                callback(AutoPollEvent::NewVersionAvailable(update));
                            }
                        }
                        Ok(None) => callback(AutoPollEvent::UpToDate),
                        Err(e) => callback(AutoPollEvent::Error(e)),
                    }
                }

                // 拆分休眠片，响应毫秒级退出请求
                let slice = Duration::from_millis(500);
                let total_slices = (options.interval.as_millis() / slice.as_millis()).max(1);
                for _ in 0..total_slices {
                    if worker_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(slice);
                }
            }

            log::info!("后台自更新轮询工作线程已优雅退出");
        })?;

    Ok(AutoPollerHandle::new(stop_flag, download_cancel_flag))
}

#[cfg(feature = "async")]
/// 启动基于 Tokio 运行时的后台异步轮询协作任务
///
/// # 设计原理
/// - **实现初衷**：在全面异步化的现代客户端（如 GPUI）或高并发服务节点中，以极低开销常驻执行更新感知。
/// - **核心优势**：
///   - 依托 Tokio 定时器与异步 HTTP，零额外操作系统线程开销，内存占用极小。
///   - 优雅取消集成：持有返回的 [`AutoPollerHandle`] 可随时通知任务安全析构，下载中亦支持即时中断。
/// - **代价与局限**：必须运行在有效的 Tokio 异步运行时上下文中。
///
/// # 参数
/// * `updater`: 更新器实例
/// * `options`: 轮询频率与策略
/// * `callback`: 事件通知闭包
pub fn spawn_polling_task<F>(
    updater: Updater,
    options: AutoPollOptions,
    mut callback: F,
) -> AutoPollerHandle
where
    F: FnMut(AutoPollEvent) + Send + 'static,
{
    let stop_flag = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop_flag);
    let download_cancel_flag = Arc::new(AtomicBool::new(false));
    let worker_download_cancel = Arc::clone(&download_cancel_flag);

    tokio::spawn(async move {
        log::info!("后台异步轮询任务已启动，检测间隔: {:?}", options.interval);
        let mut first_run = true;

        while !worker_stop.load(Ordering::Relaxed) {
            if first_run && !options.check_immediately {
                first_run = false;
            } else {
                first_run = false;
                callback(AutoPollEvent::Checking);
                match updater.check_async().await {
                    Ok(Some(update)) => {
                        if options.silent_download {
                            callback(AutoPollEvent::Downloading(update.clone()));
                            worker_download_cancel.store(false, Ordering::Relaxed);
                            let cancel_token = Some(Arc::clone(&worker_download_cancel));
                            match update
                                .download_with_cancellation_async(cancel_token, |_| {})
                                .await
                            {
                                Ok(downloaded) => callback(AutoPollEvent::UpdateReady(downloaded)),
                                Err(UpdateError::Cancelled) => {
                                    log::info!("后台异步静默下载更新包已被取消，保持周期轮询调度");
                                }
                                Err(e) => callback(AutoPollEvent::Error(e)),
                            }
                        } else {
                            callback(AutoPollEvent::NewVersionAvailable(update));
                        }
                    }
                    Ok(None) => callback(AutoPollEvent::UpToDate),
                    Err(e) => callback(AutoPollEvent::Error(e)),
                }
            }

            let slice = Duration::from_millis(500);
            let total_slices = (options.interval.as_millis() / slice.as_millis()).max(1);
            for _ in 0..total_slices {
                if worker_stop.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(slice).await;
            }
        }

        log::info!("后台异步自更新轮询任务已优雅退出");
    });

    AutoPollerHandle::new(stop_flag, download_cancel_flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_poll_options_builder() {
        let options = AutoPollOptions::default()
            .interval(Duration::from_secs(60))
            .check_immediately(false)
            .silent_download(false);

        assert_eq!(options.interval, Duration::from_secs(60));
        assert!(!options.check_immediately);
        assert!(!options.silent_download);
    }

    #[test]
    fn test_poller_handle_stop_flag() {
        let flag = Arc::new(AtomicBool::new(false));
        let cancel_dl = Arc::new(AtomicBool::new(false));
        let handle = AutoPollerHandle::new(Arc::clone(&flag), Arc::clone(&cancel_dl));

        assert!(!handle.is_stopped());
        handle.cancel_current_download();
        assert!(cancel_dl.load(Ordering::Relaxed));
        assert!(!handle.is_stopped()); // 仅取消单次下载不终止整个轮询工作器

        handle.stop();
        assert!(handle.is_stopped());
        assert!(flag.load(Ordering::Relaxed));
    }
}
