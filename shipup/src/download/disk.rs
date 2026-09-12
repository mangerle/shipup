//! 目标磁盘可用空间预检模块。
//!
//! # 模块职责
//! 在下载与解压前核验目标分区剩余容量；探测失败时降级放行，避免因系统接口受限误杀正常更新。
//!
//! # 设计原理
//! - **实现初衷**：半途写满磁盘会导致进程或操作系统级故障，必须在写入前拦截。
//! - **核心优势**：不足时返回强类型 [`UpdateError::InsufficientDiskSpace`]；
//!   探测本身失败只记警告并放行。
//! - **代价与局限**：同卷临时文件与目标文件共享配额，预检需按「两倍包体」估算。

use crate::error::{Result, UpdateError};
use std::path::Path;

/// 检查指定目标路径所在磁盘分区的可用存储空间
///
/// # 设计原理
/// - **实现初衷**：在下载和解包前核验磁盘剩余容量，避免半途写满磁盘导致进程或操作系统崩溃。
/// - **容错降级**：若系统接口调用失败或环境受限，以警告日志记录并降级放行，杜绝误杀正常更新。
///
/// # Errors
/// 当可用空间低于 `required_bytes` 时返回 [`UpdateError::InsufficientDiskSpace`]。
/// 禁止双重记录：此处只构造错误上抛，日志由顶层消费方统一输出。
pub(crate) fn check_disk_space_available(target_path: &Path, required_bytes: u64) -> Result<()> {
    if required_bytes == 0 {
        return Ok(());
    }
    match get_available_disk_space(target_path) {
        Ok(available) => {
            if available < required_bytes {
                return Err(UpdateError::InsufficientDiskSpace {
                    required: required_bytes,
                    available,
                });
            }
            Ok(())
        }
        Err(e) => {
            log::warn!("探测磁盘可用空间失败: {}，降级跳过预检直接尝试写入", e);
            Ok(())
        }
    }
}

#[cfg(windows)]
fn get_available_disk_space(target_path: &Path) -> std::io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    let dir = if target_path.is_dir() {
        target_path
    } else {
        target_path.parent().unwrap_or_else(|| Path::new("."))
    };
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    wide.push(0);

    let mut free_bytes_available = 0u64;
    let mut total_number_of_bytes = 0u64;
    let mut total_number_of_free_bytes = 0u64;

    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            lp_directory_name: *const u16,
            lp_free_bytes_available_to_caller: *mut u64,
            lp_total_number_of_bytes: *mut u64,
            lp_total_number_of_free_bytes: *mut u64,
        ) -> i32;
    }

    let ret = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_bytes_available,
            &mut total_number_of_bytes,
            &mut total_number_of_free_bytes,
        )
    };

    if ret == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(free_bytes_available)
    }
}

#[cfg(unix)]
// 64 位 Linux/macOS 上 statvfs 字段已是 u64，32 位平台需要转换；
// 统一在函数级放行，避免特定 target 报 useless_conversion。
#[allow(clippy::useless_conversion)]
fn get_available_disk_space(target_path: &Path) -> std::io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let dir = if target_path.is_dir() {
        target_path
    } else {
        target_path.parent().unwrap_or_else(|| Path::new("."))
    };

    let c_path = CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    let res = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if res == 0 {
        let stat = unsafe { stat.assume_init() };
        let frsize: u64 = if stat.f_frsize > 0 {
            u64::try_from(stat.f_frsize).unwrap_or(0)
        } else {
            u64::try_from(stat.f_bsize).unwrap_or(0)
        };
        let bavail = u64::try_from(stat.f_bavail).unwrap_or(0);
        Ok(bavail.saturating_mul(frsize))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(windows, unix)))]
fn get_available_disk_space(_target_path: &Path) -> std::io::Result<u64> {
    Ok(u64::MAX)
}
