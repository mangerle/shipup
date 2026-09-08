#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

// shipup 跨平台自更新系统 - 流式下载引擎（支持进度派发与主动取消）

use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use std::fs::{self, File};
#[cfg(feature = "blocking")]
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "blocking")]
const BUFFER_SIZE: usize = 64 * 1024; // 64KB 缓冲区

/// 更新包流式下载配置选项
///
/// # 设计原理
/// - **实现初衷**：采用参数对象模式（Parameter Object Pattern）收敛下载目标 URL、落盘文件路径及取消令牌，
///   避免方法入参过度平铺膨胀。
/// - **核心优势**：借用切片生命周期，避免 URL 与 Path 的克隆分配开销。
/// - **代价与局限**：生命周期 `'a` 与调用上下文借用绑定。
#[derive(Debug, Clone)]
pub struct DownloadOptions<'a> {
    /// 目标资源公网下载直链
    pub url: &'a str,
    /// 下载落盘保存的目标临时路径
    pub target_path: &'a Path,
    /// 跨线程/异步任务的主动取消信号标记
    pub cancel_flag: Option<Arc<AtomicBool>>,
}

#[cfg(feature = "blocking")]
/// 同步阻塞流式下载更新包到目标文件
///
/// # 设计原理
/// - **实现初衷**：基于固定大小缓冲区（64KB）循环拉取 HTTP 响应流，并实时派发进度通知事件。
/// - **核心优势**：单次内存占用恒定，即便下载数百兆的安装包也不会造成内存暴涨；支持毫秒级轮询响应主动取消。
/// - **代价与局限**：在调用线程中形成阻塞，若需在 GUI 中使用需调度至后台工作线程。
///
/// # Errors
/// - 当网络请求发起失败或 HTTP 响应非 2xx 时返回 [`UpdateError::Network`] 或 [`UpdateError::HttpStatus`]。
/// - 当用户触发取消信号时物理销毁临时文件并返回 [`UpdateError::Cancelled`]。
/// - 当磁盘写入失败时返回 [`UpdateError::Io`]。
pub fn download_file_blocking<F>(
    client: &reqwest::blocking::Client,
    options: &DownloadOptions<'_>,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    log::info!("正在发起同步下载请求，目标地址: {}", options.url);
    let mut response = client
        .get(options.url)
        .send()
        .map_err(|e| UpdateError::Network(format!("发起下载请求失败: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        return Err(UpdateError::HttpStatus {
            status_code: status.as_u16(),
            message: format!("下载响应异常: {}", status),
        });
    }

    let total_bytes = response.content_length();
    event_callback(UpdateEvent::DownloadStarted { total_bytes });

    if let Some(parent) = options.target_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(options.target_path)?;
    pipe_blocking_stream(
        &mut response,
        file,
        total_bytes,
        options,
        &mut event_callback,
    )?;

    log::info!(
        "更新包同步下载完成，临时路径: {}",
        options.target_path.display()
    );
    Ok(())
}

#[cfg(feature = "blocking")]
fn pipe_blocking_stream<F>(
    response: &mut reqwest::blocking::Response,
    mut file: File,
    total_bytes: Option<u64>,
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    let mut downloaded_bytes: u64 = 0;
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        if let Some(ref flag) = options.cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消下载信号，正在清理临时文件");
            drop(file);
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::Cancelled);
        }

        let read_bytes = match response.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                drop(file);
                let _ = fs::remove_file(options.target_path);
                return Err(UpdateError::Io(e));
            }
        };

        if let Err(e) = file.write_all(&buffer[..read_bytes]) {
            drop(file);
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::Io(e));
        }

        downloaded_bytes += read_bytes as u64;
        let percent = total_bytes.map(|total| {
            if total > 0 {
                (downloaded_bytes as f32 / total as f32) * 100.0
            } else {
                0.0
            }
        });

        event_callback(UpdateEvent::DownloadProgress {
            downloaded_bytes,
            total_bytes,
            percent,
        });
    }

    file.flush()?;
    Ok(())
}

#[cfg(feature = "async")]
/// 异步流式下载更新包到目标文件
///
/// # 设计原理
/// - **实现初衷**：利用异步数据流（`bytes_stream`）逐块拉取更新包，契合 Tokio 异步事件驱动架构。
/// - **核心优势**：在单线程或多任务并发上下文中不阻塞 OS 线程，资源开销小。
/// - **代价与局限**：回调函数需满足 `Send` 约束。
///
/// # Errors
/// - 当异步网络请求失败或响应非 2xx 时返回 [`UpdateError::Network`] 或 [`UpdateError::HttpStatus`]。
/// - 当用户触发取消信号时物理销毁临时文件并返回 [`UpdateError::Cancelled`]。
/// - 当文件落盘失败时返回 [`UpdateError::Io`]。
pub async fn download_file_async<F>(
    client: &reqwest::Client,
    options: &DownloadOptions<'_>,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    log::info!("正在发起异步下载请求，目标地址: {}", options.url);
    let response = client
        .get(options.url)
        .send()
        .await
        .map_err(|e| UpdateError::Network(format!("发起异步下载请求失败: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        return Err(UpdateError::HttpStatus {
            status_code: status.as_u16(),
            message: format!("下载响应异常: {}", status),
        });
    }

    let total_bytes = response.content_length();
    event_callback(UpdateEvent::DownloadStarted { total_bytes });

    if let Some(parent) = options.target_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(options.target_path)?;
    pipe_async_stream(response, file, total_bytes, options, &mut event_callback).await?;

    log::info!(
        "更新包异步下载完成，临时路径: {}",
        options.target_path.display()
    );
    Ok(())
}

#[cfg(feature = "async")]
async fn pipe_async_stream<F>(
    response: reqwest::Response,
    mut file: File,
    total_bytes: Option<u64>,
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    use futures_util::StreamExt;
    let mut downloaded_bytes: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk_res) = stream.next().await {
        if let Some(ref flag) = options.cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消异步下载信号，正在清理临时文件");
            drop(file);
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::Cancelled);
        }

        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => {
                drop(file);
                let _ = fs::remove_file(options.target_path);
                return Err(UpdateError::Network(format!("下载数据流中断: {}", e)));
            }
        };

        if let Err(e) = file.write_all(&chunk) {
            drop(file);
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::Io(e));
        }

        downloaded_bytes += chunk.len() as u64;
        let percent = total_bytes.map(|total| {
            if total > 0 {
                (downloaded_bytes as f32 / total as f32) * 100.0
            } else {
                0.0
            }
        });

        event_callback(UpdateEvent::DownloadProgress {
            downloaded_bytes,
            total_bytes,
            percent,
        });
    }

    file.flush()?;
    Ok(())
}
