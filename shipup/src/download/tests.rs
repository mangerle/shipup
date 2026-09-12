//! download 模块单元测试。
//!
//! # 模块职责
//! 覆盖进度采样、退避策略、缓存命中、分片切分、磁盘预检与本地/网络分片下载主路径。

use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::error::UpdateError;
use crate::event::UpdateEvent;

#[cfg(any(feature = "blocking", feature = "async"))]
use std::io::{Read, Write};

#[cfg(feature = "async")]
use crate::download::asynchronous::download_file_chunked_async;
#[cfg(feature = "blocking")]
use crate::download::blocking::{copy_local_file_blocking, download_file_chunked_blocking};

#[test]
fn test_download_progress_tracker_zero_and_percent() {
    let mut tracker = DownloadProgressTracker::new(Some(1000));
    let (percent, _speed, _eta) = tracker.update(0);
    assert_eq!(percent, Some(0.0));

    let (percent, _speed, _eta) = tracker.update(500);
    assert_eq!(percent, Some(50.0));

    let (percent, _speed, _eta) = tracker.update(1000);
    assert_eq!(percent, Some(100.0));
}

#[test]
fn test_download_progress_tracker_unknown_total() {
    let mut tracker = DownloadProgressTracker::new(None);
    let (percent, _speed, eta) = tracker.update(2048);
    assert_eq!(percent, None);
    assert_eq!(eta, None);
}

#[test]
fn test_download_progress_tracker_eta_calculation() {
    let mut tracker = DownloadProgressTracker::new(Some(2_000_000));
    // 手动模拟速率计算
    tracker.current_speed = Some(1_000_000); // 1MB/s
    let (percent, speed, eta) = tracker.update(1_000_000); // 剩余 1MB
    assert_eq!(percent, Some(50.0));
    assert_eq!(speed, Some(1_000_000));
    assert_eq!(eta, Some(Duration::from_secs(1)));
}

#[test]
fn test_calculate_backoff_exponential_growth_and_cap() {
    let base = Duration::from_secs(1);
    // attempt 1: 1 * 2^0 = 1s
    assert_eq!(calculate_backoff(base, 1), Duration::from_secs(1));
    // attempt 2: 1 * 2^1 = 2s
    assert_eq!(calculate_backoff(base, 2), Duration::from_secs(2));
    // attempt 3: 1 * 2^2 = 4s
    assert_eq!(calculate_backoff(base, 3), Duration::from_secs(4));
    // attempt 10: 1 * 2^9 = 512s，但应被 60s 上限截断
    assert_eq!(calculate_backoff(base, 10), Duration::from_secs(60));
}

#[test]
fn test_is_retryable_error_rules() {
    // 用户主动取消不可重试
    assert!(!is_retryable_error(&UpdateError::Cancelled));

    // 404 Not Found 不可重试
    assert!(!is_retryable_error(&UpdateError::HttpStatus {
        status_code: 404,
        message: "Not Found".to_string(),
    }));

    // 408 Timeout 可重试
    assert!(is_retryable_error(&UpdateError::HttpStatus {
        status_code: 408,
        message: "Request Timeout".to_string(),
    }));

    // 429 Too Many Requests 可重试
    assert!(is_retryable_error(&UpdateError::HttpStatus {
        status_code: 429,
        message: "Too Many Requests".to_string(),
    }));

    // 502 Bad Gateway 可重试
    assert!(is_retryable_error(&UpdateError::HttpStatus {
        status_code: 502,
        message: "Bad Gateway".to_string(),
    }));

    // 普通网络连接错误可重试
    assert!(is_retryable_error(&UpdateError::Network(
        "连接超时重置".to_string()
    )));

    // 校验和不匹配不可重试
    assert!(!is_retryable_error(&UpdateError::ChecksumMismatch {
        expected: "sha256:aaa".to_string(),
        actual: "bbb".to_string(),
    }));

    // 签名无效不可重试
    assert!(!is_retryable_error(&UpdateError::InvalidSignature));

    // 权限拒绝 IO 错误不可重试
    assert!(!is_retryable_error(&UpdateError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "拒绝访问"
    ))));
}

#[test]
fn test_try_hit_local_cache() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join(format!("shipup_cache_test_{}.bin", std::process::id()));
    let content = b"hello shipup cached update package";
    fs::write(&test_file, content).unwrap();

    let mut events = Vec::new();

    // 1. 哈希不匹配时不能命中缓存
    let not_hit = try_hit_local_cache(&test_file, Some("wrong_hash"), &mut |ev| events.push(ev));
    assert!(!not_hit);
    assert!(events.is_empty());

    // 2. 哈希匹配时成功命中缓存并派发 100% 进度
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(content);
    let mut expected_hash = String::new();
    for b in hash {
        use std::fmt::Write;
        let _ = write!(expected_hash, "{b:02x}");
    }

    let hit = try_hit_local_cache(&test_file, Some(&expected_hash), &mut |ev| events.push(ev));
    assert!(hit);
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], UpdateEvent::DownloadStarted { .. }));
    if let UpdateEvent::DownloadProgress { percent, .. } = &events[1] {
        assert_eq!(*percent, Some(100.0));
    } else {
        panic!("预期收到 100% DownloadProgress 事件");
    }

    let _ = fs::remove_file(&test_file);
}

#[test]
fn test_update_event_variants_retrying_failed_completed() {
    let retrying_ev = UpdateEvent::Retrying {
        attempt: 1,
        max_retries: 3,
        delay: Duration::from_millis(500),
        error: "连接超时".to_string(),
    };
    let failed_ev = UpdateEvent::Failed {
        reason: "哈希校验失败".to_string(),
    };
    let completed_ev = UpdateEvent::Completed;

    assert_eq!(
        retrying_ev,
        UpdateEvent::Retrying {
            attempt: 1,
            max_retries: 3,
            delay: Duration::from_millis(500),
            error: "连接超时".to_string(),
        }
    );
    assert_eq!(
        failed_ev,
        UpdateEvent::Failed {
            reason: "哈希校验失败".to_string()
        }
    );
    assert_eq!(completed_ev, UpdateEvent::Completed);
}

#[test]
fn test_check_disk_space_available_thresholds() {
    let temp_dir = std::env::temp_dir();
    // 1. 0 字节需求恒成功
    assert!(check_disk_space_available(&temp_dir, 0).is_ok());

    // 2. 10KB 需求在正常操作系统环境下必定满足
    let small_req = 10 * 1024;
    assert!(check_disk_space_available(&temp_dir, small_req).is_ok());

    // 3. 天文数字容量需求应当触发 InsufficientDiskSpace 错误
    let impossible_req = 1_000_000_000_000_000_000u64;
    let err = check_disk_space_available(&temp_dir, impossible_req);
    match err {
        Err(UpdateError::InsufficientDiskSpace {
            required,
            available: _,
        }) => {
            assert_eq!(required, impossible_req);
        }
        other => panic!("预期返回 InsufficientDiskSpace 错误，实际为: {:?}", other),
    }
}

#[cfg(feature = "blocking")]
#[test]
fn test_rate_limiter_record_and_throttle() {
    let mut limiter = RateLimiter::new(1024 * 1024); // 1MB/s
    let start = Instant::now();
    limiter.record_and_throttle_blocking(512);
    assert!(start.elapsed() < Duration::from_millis(100));
}

#[test]
fn test_parse_file_url_to_path() {
    // 非 file:// 报错
    assert!(parse_file_url_to_path("https://example.com/test").is_err());

    // 带 localhost
    let _parsed = parse_file_url_to_path("file://localhost/path/to/file.txt").unwrap();
    #[cfg(not(windows))]
    assert_eq!(_parsed, PathBuf::from("/path/to/file.txt"));

    // 百分号解码
    let decoded = parse_file_url_to_path("file:///path/to/my%20file.txt").unwrap();
    assert!(decoded.to_string_lossy().contains("my file.txt"));

    #[cfg(windows)]
    {
        let win_path = parse_file_url_to_path("file:///C:/Windows/notepad.exe").unwrap();
        assert_eq!(win_path, PathBuf::from("C:/Windows/notepad.exe"));
    }
}

#[cfg(feature = "blocking")]
#[test]
fn test_copy_local_file_blocking_and_events() {
    let temp_dir = std::env::temp_dir();
    let src_file = temp_dir.join(format!("shipup_src_{}.bin", std::process::id()));
    let dst_file = temp_dir.join(format!("shipup_dst_{}.bin", std::process::id()));
    let data = b"offline package payload test content";
    fs::write(&src_file, data).unwrap();

    let src_url = if cfg!(windows) {
        format!(
            "file:///{}",
            src_file.display().to_string().replace('\\', "/")
        )
    } else {
        format!("file://{}", src_file.display())
    };

    let mut events = Vec::new();
    let options = DownloadOptions {
        url: &src_url,
        target_path: &dst_file,
        cancel_flag: None,
        max_retries: 1,
        retry_delay: Duration::from_millis(10),
        expected_checksum: None,
        expected_size: Some(data.len() as u64),
        max_bytes_per_sec: None,
    };

    let res = copy_local_file_blocking(&options, &mut |ev| events.push(ev));
    assert!(res.is_ok());
    assert_eq!(fs::read(&dst_file).unwrap(), data);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, UpdateEvent::DownloadStarted { .. }))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, UpdateEvent::DownloadProgress { .. }))
    );

    let _ = fs::remove_file(&src_file);
    let _ = fs::remove_file(&dst_file);
}

#[test]
fn test_file_chunk_range_methods() {
    let chunk = FileChunkRange {
        index: 0,
        start: 0,
        end: 99,
    };
    assert_eq!(chunk.len(), 100);
    assert!(!chunk.is_empty());

    let empty_chunk = FileChunkRange {
        index: 1,
        start: 10,
        end: 5,
    };
    assert_eq!(empty_chunk.len(), 0);
    assert!(empty_chunk.is_empty());
}

#[test]
fn test_split_file_into_chunks_edge_cases() {
    // 1. 空文件或 0 切片大小
    assert!(split_file_into_chunks(0, 1024).is_empty());
    assert!(split_file_into_chunks(100, 0).is_empty());

    // 2. 恰好整除：100 字节，切片 25 字节 -> 4 个分片
    let chunks = split_file_into_chunks(100, 25);
    assert_eq!(chunks.len(), 4);
    assert_eq!(
        chunks[0],
        FileChunkRange {
            index: 0,
            start: 0,
            end: 24
        }
    );
    assert_eq!(
        chunks[1],
        FileChunkRange {
            index: 1,
            start: 25,
            end: 49
        }
    );
    assert_eq!(
        chunks[2],
        FileChunkRange {
            index: 2,
            start: 50,
            end: 74
        }
    );
    assert_eq!(
        chunks[3],
        FileChunkRange {
            index: 3,
            start: 75,
            end: 99
        }
    );

    // 3. 有余数：105 字节，切片 25 字节 -> 5 个分片，末尾为 5 字节
    let chunks_rem = split_file_into_chunks(105, 25);
    assert_eq!(chunks_rem.len(), 5);
    assert_eq!(
        chunks_rem[4],
        FileChunkRange {
            index: 4,
            start: 100,
            end: 104
        }
    );
    assert_eq!(chunks_rem[4].len(), 5);

    // 4. 单切片大于等于总大小
    let chunks_single = split_file_into_chunks(50, 100);
    assert_eq!(chunks_single.len(), 1);
    assert_eq!(
        chunks_single[0],
        FileChunkRange {
            index: 0,
            start: 0,
            end: 49
        }
    );
}

#[test]
fn test_collect_candidate_urls() {
    let mirrors = vec![
        "https://mirror1.example.com/app.tar.gz".to_string(),
        "   ".to_string(),
        "https://main.example.com/app.tar.gz".to_string(), // 与主 URL 重复
        "https://mirror2.example.com/app.tar.gz".to_string(),
    ];
    let result = collect_candidate_urls("https://main.example.com/app.tar.gz", &mirrors);
    assert_eq!(result.len(), 3);
    assert_eq!(result[0], "https://main.example.com/app.tar.gz");
    assert_eq!(result[1], "https://mirror1.example.com/app.tar.gz");
    assert_eq!(result[2], "https://mirror2.example.com/app.tar.gz");
}

/// 解析 HTTP 请求头中的 Range: bytes=start-end
#[cfg(any(feature = "blocking", feature = "async"))]
fn parse_range_header(req_str: &str, payload_len: usize) -> Option<(usize, usize)> {
    for line in req_str.lines() {
        if line.to_ascii_lowercase().starts_with("range: bytes=") {
            let parts: Vec<&str> = line[13..].trim().split('-').collect();
            if parts.len() == 2 {
                let start = parts[0].parse::<usize>().unwrap_or(0);
                let end = parts[1]
                    .parse::<usize>()
                    .unwrap_or(payload_len.saturating_sub(1));
                return Some((start, end));
            }
        }
    }
    None
}

/// 读取完整 HTTP 请求头（直到空行），避免 TCP 分片导致 Range 头被截断
#[cfg(any(feature = "blocking", feature = "async"))]
fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut req = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") || req.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&req).into_owned()
}

/// 处理单个已接受连接：读请求、按 Range 写出响应体
#[cfg(any(feature = "blocking", feature = "async"))]
fn handle_mock_connection(
    mut stream: std::net::TcpStream,
    payload: &Arc<Vec<u8>>,
    support_range: bool,
) {
    let _ = stream.set_nodelay(true);
    let req_str = read_http_request(&mut stream);
    let range = if support_range {
        parse_range_header(&req_str, payload.len())
    } else {
        None
    };

    let write_result = if let Some((start, end)) = range {
        let end = end.min(payload.len().saturating_sub(1));
        let chunk = if start <= end && start < payload.len() {
            &payload[start..=end]
        } else {
            &[]
        };
        let header = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
            chunk.len(),
            start,
            end,
            payload.len()
        );
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(chunk))
    } else {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(payload))
    };
    let _ = write_result;
    let _ = stream.flush();
}

/// 启动本地 Range 模拟服务；每连接独立线程，消除并发分片串行处理竞态
#[cfg(any(feature = "blocking", feature = "async"))]
fn run_mock_range_server(payload: Arc<Vec<u8>>, support_range: bool) -> (String, Arc<AtomicBool>) {
    use std::sync::mpsc;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    let url = format!("http://127.0.0.1:{}", port);
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    std::thread::spawn(move || {
        let _ = ready_tx.send(());
        while running_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let payload = payload.clone();
                    std::thread::spawn(move || {
                        handle_mock_connection(stream, &payload, support_range);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    let _ = ready_rx.recv_timeout(Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(5));

    (url, running)
}

#[cfg(feature = "blocking")]
#[test]
fn test_download_file_chunked_blocking_full_flow() {
    let payload = Arc::new(vec![42u8; 128]);
    let (server_url, server_guard) = run_mock_range_server(payload.clone(), true);

    let temp_dir = std::env::temp_dir();
    let target_file = temp_dir.join(format!("shipup_chunked_test_{}.bin", std::process::id()));
    let _ = fs::remove_file(&target_file);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let mut events = Vec::new();
    let options = ChunkedDownloadOptions {
        base: DownloadOptions {
            url: &server_url,
            target_path: &target_file,
            cancel_flag: None,
            max_retries: 2,
            retry_delay: Duration::from_millis(10),
            expected_checksum: None,
            expected_size: Some(128),
            max_bytes_per_sec: None,
        },
        mirrors: &[],
        concurrency: 2,
        chunk_size: 32,
    };

    let result = download_file_chunked_blocking(&client, &options, |ev| events.push(ev));
    assert!(
        result.is_ok(),
        "blocking chunked download error: {:?}",
        result
    );
    assert!(target_file.exists());
    assert_eq!(fs::read(&target_file).unwrap(), *payload);

    assert!(
        events
            .iter()
            .any(|e| matches!(e, UpdateEvent::DownloadStarted { .. }))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, UpdateEvent::DownloadProgress { .. }))
    );

    server_guard.store(false, Ordering::Relaxed);
    let _ = fs::remove_file(&target_file);
}

#[cfg(feature = "blocking")]
#[test]
fn test_download_file_chunked_blocking_fallback_on_unsupported_range() {
    let payload = Arc::new(vec![99u8; 128]);
    let (server_url, server_guard) = run_mock_range_server(payload.clone(), false);

    let temp_dir = std::env::temp_dir();
    let target_file = temp_dir.join(format!("shipup_chunked_fb_{}.bin", std::process::id()));
    let _ = fs::remove_file(&target_file);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let mut events = Vec::new();
    let options = ChunkedDownloadOptions {
        base: DownloadOptions {
            url: &server_url,
            target_path: &target_file,
            cancel_flag: None,
            max_retries: 1,
            retry_delay: Duration::from_millis(10),
            expected_checksum: None,
            expected_size: Some(128),
            max_bytes_per_sec: None,
        },
        mirrors: &[],
        concurrency: 2,
        chunk_size: 32,
    };

    let result = download_file_chunked_blocking(&client, &options, |ev| events.push(ev));
    assert!(result.is_ok());
    assert!(target_file.exists());
    assert_eq!(fs::read(&target_file).unwrap(), *payload);

    server_guard.store(false, Ordering::Relaxed);
    let _ = fs::remove_file(&target_file);
}

#[cfg(feature = "blocking")]
#[test]
fn test_download_file_chunked_cancellation() {
    let payload = Arc::new(vec![7u8; 128]);
    let (server_url, server_guard) = run_mock_range_server(payload, true);

    let temp_dir = std::env::temp_dir();
    let target_file = temp_dir.join(format!("shipup_chunked_cancel_{}.bin", std::process::id()));
    let _ = fs::remove_file(&target_file);

    let cancel_flag = Arc::new(AtomicBool::new(true));

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let options = ChunkedDownloadOptions {
        base: DownloadOptions {
            url: &server_url,
            target_path: &target_file,
            cancel_flag: Some(cancel_flag),
            max_retries: 1,
            retry_delay: Duration::from_millis(10),
            expected_checksum: None,
            expected_size: Some(128),
            max_bytes_per_sec: None,
        },
        mirrors: &[],
        concurrency: 2,
        chunk_size: 32,
    };

    let result = download_file_chunked_blocking(&client, &options, |_| {});
    assert!(matches!(result, Err(UpdateError::Cancelled)));

    server_guard.store(false, Ordering::Relaxed);
    let _ = fs::remove_file(&target_file);
}

#[cfg(feature = "async")]
#[test]
fn test_download_file_chunked_async_full_flow() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let payload = Arc::new(vec![88u8; 128]);
        let (server_url, server_guard) = run_mock_range_server(payload.clone(), true);

        let temp_dir = std::env::temp_dir();
        let target_file = temp_dir.join(format!("shipup_chunked_async_{}.bin", std::process::id()));
        let _ = fs::remove_file(&target_file);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut events = Vec::new();
        let options = ChunkedDownloadOptions {
            base: DownloadOptions {
                url: &server_url,
                target_path: &target_file,
                cancel_flag: None,
                max_retries: 2,
                retry_delay: Duration::from_millis(10),
                expected_checksum: None,
                expected_size: Some(128),
                max_bytes_per_sec: None,
            },
            mirrors: &[],
            concurrency: 2,
            chunk_size: 32,
        };

        let result = download_file_chunked_async(&client, &options, |ev| events.push(ev)).await;
        assert!(result.is_ok(), "async chunked download error: {:?}", result);
        assert!(target_file.exists());
        assert_eq!(fs::read(&target_file).unwrap(), *payload);

        assert!(
            events
                .iter()
                .any(|e| matches!(e, UpdateEvent::DownloadStarted { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, UpdateEvent::DownloadProgress { .. }))
        );

        server_guard.store(false, Ordering::Relaxed);
        let _ = fs::remove_file(&target_file);
    });
}
