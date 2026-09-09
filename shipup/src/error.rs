// shipup 跨平台自更新系统 - 统一强类型中文错误定义

use std::io;
use thiserror::Error;

/// 更新过程中可能产生的所有错误枚举
///
/// # 设计原理
/// - **实现初衷**：基于 `thiserror` 建立强类型、内聚的领域错误枚举，摒弃宽泛无类型的通用字符串，
///   为上层调用方提供明确的模式解构与细粒度错误拦截契约。
/// - **核心优势**：所有错误变体均附带精确的中文动态上下文（如状态码、目标路径、期望与实际哈希对比），
///   便于问题排查与自动化错误分类处理。
/// - **代价与局限**：对外部错误进行了内聚收敛转换，未直接透传部分第三方大型库的深层内部类型。
#[derive(Debug, Error)]
pub enum UpdateError {
    /// 网络连接或传输层错误
    #[error("网络请求失败: {0}")]
    Network(String),

    /// HTTP 状态码异常
    #[error("HTTP 请求状态异常: {status_code}, 响应: {message}")]
    HttpStatus { status_code: u16, message: String },

    /// Manifest JSON 元数据解析错误
    #[error("Manifest 元数据解析失败: {0}")]
    ManifestParse(String),

    /// 目标 Target 未匹配到对应的包
    #[error("当前目标平台 ({0}) 未在 Manifest 中找到适配的安装包")]
    PlatformNotFound(String),

    /// 远端版本不高于本地当前版本
    #[error("远程版本 ({0}) 不高于本地当前版本 ({1})，更新已被忽略")]
    NoUpdateAvailable(String, String),

    /// SHA-256 完整性哈希不匹配
    #[error("下载文件传输损坏: 计算的 SHA-256 ({actual}) 与期望值 ({expected}) 不一致")]
    ChecksumMismatch { expected: String, actual: String },

    /// Ed25519 验签未通过
    #[error("数字签名无效或文件已被篡改")]
    InvalidSignature,

    /// 客户端配置了公钥但远端包缺少签名
    #[error("签名配置缺失: 客户端启用了验签但 Manifest 未包含签名")]
    MissingSignature,

    /// 缺少验签公钥配置
    #[error("验签公钥缺失: 当前安全模式强制要求校验数字签名，但未提供公钥")]
    MissingPublicKey,

    /// 目标文件或目录写入权限不足
    #[error("目标目录写权限受限: {0}。对于系统受保护目录，建议配置为安装器（installer）模式")]
    PermissionDenied(String),

    /// Zip Slip 路径越界逃逸防护拦截
    #[error("解压缩安全告警: 检测到路径越界文件 ({0})，更新已中止")]
    ZipSlipViolation(String),

    /// 解压缩归档文件失败
    #[error("解压缩归档包失败: {0}")]
    ArchiveExtract(String),

    /// 原地二进制原子替换失败
    #[error("原地替换二进制失败: {0}")]
    SelfReplace(String),

    /// 拉起外部安装器子进程失败
    #[error("启动外部安装器失败: {0}")]
    InstallerSpawn(String),

    /// 用户主动发起了取消操作
    #[error("更新流程已被用户主动取消")]
    Cancelled,

    /// 新版本启动自愈回滚状态
    #[error("新版本启动连续崩溃，已自动触发自愈回滚至历史版本: {0}")]
    AutoRollback(String),

    /// SemVer 版本号格式错误
    #[error("版本号格式解析错误: {0}")]
    SemVer(String),

    /// Base64 编码解析错误
    #[error("Base64 解码错误: {0}")]
    Base64(String),

    /// 底层 IO 错误
    #[error("输入输出错误: {0}")]
    Io(#[from] io::Error),

    /// 传输协议不安全拦截（如明文 HTTP）
    #[error(
        "不安全传输协议: 地址 '{0}' 采用明文 HTTP 协议，默认被拒绝。如需强制允许请开启 dangerous_insecure_transport_protocol"
    )]
    InsecureTransportProtocol(String),

    /// 更新包大小不匹配或流式传输超出限制
    #[error("更新包文件体积异常: 期望大小为 {expected} 字节，实际为 {actual} 字节")]
    PayloadSizeMismatch { expected: u64, actual: u64 },

    /// 目标磁盘可用存储空间不足
    #[error("目标磁盘可用空间不足: 需要至少 {required} 字节，当前磁盘剩余可用 {available} 字节")]
    InsufficientDiskSpace { required: u64, available: u64 },

    /// 本地文件传输协议受限拦截（如未开启 allow_file_protocol）
    #[error(
        "本地文件传输协议受限: 地址 '{0}' 采用 file:// 协议，需通过 allow_file_protocol 显式允许"
    )]
    FileProtocolNotAllowed(String),
}

impl From<semver::Error> for UpdateError {
    fn from(err: semver::Error) -> Self {
        UpdateError::SemVer(err.to_string())
    }
}

impl From<base64::DecodeError> for UpdateError {
    fn from(err: base64::DecodeError) -> Self {
        UpdateError::Base64(err.to_string())
    }
}

/// 统一更新结果类型别名
pub type Result<T> = std::result::Result<T, UpdateError>;
