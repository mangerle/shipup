//! Manifest 协议模型与版本路由解析模块。
//!
//! # 模块职责
//! 定义发布清单（Manifest）的序列化契约与解析规则：
//! - 数据结构：[`Manifest`]、[`PackageInfo`]、[`ChannelInfo`]、[`SignatureEntry`]；
//! - 解析产物：[`ResolvedRelease`] 与 [`ResolveOptions`]（完成目标平台、通道与版本过滤后的最终结果）；
//! - 安全校验：清单时效性、版本序号单调性、TUF 门限签名与包体级签名访问器。
//!
//! # 子模块导航
//! - [`model`]：强类型数据模型、构造入口与基础访问器；
//! - [`resolve`]：通道裁决、平台 Target 匹配与编译期 Triple 探测；
//! - [`verify`]：规范化验签字节生成、时效性与门限多签校验；
//! - [`time`]：RFC 3339 时间戳解析工具；
//! - [`tests`]：模块单元测试。
//!
//! # 设计原理
//! - **实现初衷**：Manifest 是外部不可信输入，必须在系统边界一次性完成「反序列化 + 完整性校验 + 路由裁决」，
//!   内部各层此后只处理已确认合法的强类型数据，避免松散的字符串校验散布到调用链各处。
//! - **核心优势**：
//!   - 对外部字段一律标注 `#[serde(default)]` 并保留兜底变体，上游协议增删字段不会导致客户端反序列化崩溃；
//!   - 路由解析对「配置了通道但清单未声明该通道」直接报错，杜绝非预期的静默回退到默认通道；
//!   - 提供 `all_signatures()` 等聚合访问器，统一兼容历史单签名字段与新的多签名字段。
//! - **代价与局限**：清单本身不携带平台原生版本号语义，
//!   跨平台差异必须由发布端在各自 `packages` 分支内显式声明。
//!
//! # 安全契约
//! [`Manifest::verify_freshness`] 与 [`Manifest::verify_signatures_threshold`] 的调用顺序不可颠倒：
//! 必须先确认清单未过期，再校验其真伪，否则过期清单的重放攻击仍有窗口。

mod model;
mod resolve;
mod time;
mod verify;

#[cfg(test)]
mod tests;

// 保持原有的公开类型与函数路径不变（`shipup::manifest::Manifest` 等），
// 使子模块拆分对下游调用方完全透明。
pub use model::{
    ChannelInfo, InstallMode, Manifest, PackageInfo, PackageType, ResolveOptions, ResolvedRelease,
    SignatureEntry,
};
pub use resolve::current_target_triple;
pub use time::parse_rfc3339_to_unix;
