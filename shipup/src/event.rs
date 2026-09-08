// shipup 跨平台自更新系统 - 生命周期事件与进度模型

/// 更新生命周期事件枚举
///
/// # 设计原理
/// - **实现初衷**：采用纯数据枚举解耦更新引擎与上层 UI/日志系统。无论宿主是 GPUI、Slint、Egui 还是 CLI 终端，
///   只需订阅该事件流即可获得完整的更新生命周期通知。
/// - **核心优势**：轻量易复制（`Clone`），字段仅包含最必要的数值型状态，避免跨线程消息传递时的重度分配开销。
/// - **代价与局限**：事件仅为单向通知流，不负责向下层下载器反向传递复杂的控制指令（取消等控制由单独的原子标志位负责）。
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateEvent {
    /// 正在向远端请求并校验 Manifest 元数据
    CheckingManifest,

    /// 开始下载更新包资源
    DownloadStarted {
        /// 更新包预估总字节数（若 HTTP 响应头未提供则为 None）
        total_bytes: Option<u64>,
    },

    /// 下载流式进度更新
    DownloadProgress {
        /// 当前已下载字节数
        downloaded_bytes: u64,
        /// 更新包预估总字节数
        total_bytes: Option<u64>,
        /// 下载百分比进度（0.0 ~ 100.0）
        percent: Option<f32>,
    },

    /// 正在校验 SHA-256 哈希完整性
    VerifyingChecksum,

    /// 正在执行 Ed25519 数字签名验证
    VerifyingSignature,

    /// 正在解压归档更新包
    ExtractingArchive,

    /// 正在执行二进制替换或拉起安装器
    Installing,

    /// 更新全部安装替换完成，已进入就绪重启状态
    ReadyToRestart,
}
