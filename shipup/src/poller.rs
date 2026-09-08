// shipup 跨平台自更新系统 - 后台周期性静默轮询与暂存调度器

use crate::error::UpdateError;
use crate::updater::{Update, Updater};
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
    /// 更新包已在后台下载校验完毕，已暂存就绪，宿主可随时安排重启生效
    UpdateReady(Update),
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
    /// 设置轮询时间间隔
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// 设置是否在启动时立即执行首次检查
    pub fn check_immediately(mut self, check: bool) -> Self {
        self.check_immediately = check;
        self
    }

    /// 设置是否在后台静默下载更新包
    pub fn silent_download(mut self, silent: bool) -> Self {
        self.silent_download = silent;
        self
    }
}

/// 后台轮询控制器句柄
///
/// # 设计原理
/// - **实现初衷**：为宿主提供对常驻后台任务的取消控制能力。
/// - **核心优势**：基于原子布尔标志位，具备 `Drop` 自动析构安全；无死锁风险。
#[derive(Debug, Clone)]
pub struct AutoPollerHandle {
    stop_flag: Arc<AtomicBool>,
}

impl AutoPollerHandle {
    pub(crate) fn new(stop_flag: Arc<AtomicBool>) -> Self {
        Self { stop_flag }
    }

    /// 停止后台轮询任务
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        log::info!("已请求中止后台自更新轮询工作器");
    }

    /// 检查后台任务是否已被请求停止
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Relaxed)
    }
}

impl Drop for AutoPollerHandle {
    fn drop(&mut self) {
        // 当持有者释放全部引用且仅剩自身时，保障退出
        if Arc::strong_count(&self.stop_flag) <= 2 {
            self.stop_flag.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "blocking")]
/// 启动基于 OS 独立线程的后台轮询工作器
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
                                let cancel_token = Some(Arc::clone(&worker_stop));
                                match update
                                    .download_and_install_with_cancellation(cancel_token, |_| {})
                                {
                                    Ok(()) => callback(AutoPollEvent::UpdateReady(update)),
                                    Err(UpdateError::Cancelled) => {
                                        log::info!("后台静默下载更新包已被主动取消");
                                        break;
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

    Ok(AutoPollerHandle::new(stop_flag))
}

#[cfg(feature = "async")]
/// 启动基于 Tokio 的后台异步轮询任务
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
                            let cancel_token = Some(Arc::clone(&worker_stop));
                            match update
                                .download_and_install_with_cancellation_async(cancel_token, |_| {})
                                .await
                            {
                                Ok(()) => callback(AutoPollEvent::UpdateReady(update)),
                                Err(UpdateError::Cancelled) => {
                                    log::info!("后台异步静默下载更新包已被主动取消");
                                    break;
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

    AutoPollerHandle::new(stop_flag)
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
        let handle = AutoPollerHandle::new(Arc::clone(&flag));

        assert!(!handle.is_stopped());
        handle.stop();
        assert!(handle.is_stopped());
        assert!(flag.load(Ordering::Relaxed));
    }
}
