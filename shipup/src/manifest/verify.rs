//! Manifest 安全校验子模块。
//!
//! # 模块职责
//! 承载 Manifest 清单自身的完整性与新鲜度校验能力：
//! - 规范化验签字节生成 [`Manifest::compute_canonical_bytes`]（排除 `signature` 字段本身）；
//! - 单签兼容模式 [`Manifest::verify_signature`]；
//! - TUF 风格门限多签 [`Manifest::verify_signatures_threshold`]；
//! - 过期失效校验 [`Manifest::verify_freshness`]（防御重放攻击）；
//! - 候选签名聚合访问器 [`Manifest::all_signatures`]。
//!
//! # 兄弟模块导航
//! - [`super::model`]：被依赖的清单数据模型；
//! - [`super::time`]：RFC 3339 时间戳解析，供过期判定使用；
//! - [`super::resolve`]：通道与平台路由，与本模块无直接依赖。
//!
//! # 安全契约
//! [`Manifest::verify_freshness`] 与 [`Manifest::verify_signatures_threshold`] 的调用顺序不可颠倒：
//! 必须先确认清单未过期，再校验其真伪，否则过期清单的重放攻击仍有窗口。
//!
//! # 设计原理
//! - **实现初衷**：规范化字节生成采用轻量借用视图（[`CanonicalManifestView`]），
//!   仅持有现有字段的只读引用，在序列化时实现零额外深拷贝（Zero-Clone），显著降低 CPU 与内存开销。
//! - **核心优势**：门限多签自动收集 `signature` 与 `signatures` 中所有候选签名，
//!   杜绝单私钥被盗即被任意投毒的风险。
//! - **代价与局限**：借用视图结构体字段名与序列化标记需与 [`Manifest`] 保持强一致同步。

use crate::error::{Result, UpdateError};
use semver::Version;
use serde::Serialize;
use std::collections::BTreeMap;

use super::model::{ChannelInfo, Manifest, PackageInfo, SignatureEntry};
use super::time::parse_rfc3339_to_unix;

/// Manifest 只读规范化借用视图（用于零内存深拷贝生成确定性验签序列化字节）
#[derive(Serialize)]
struct CanonicalManifestView<'a> {
    version: &'a Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_supported_version: Option<&'a Version>,
    force_update: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub_date: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
    packages: &'a BTreeMap<String, PackageInfo>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    channels: &'a BTreeMap<String, ChannelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollout_percentage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_seq: Option<u64>,
}

impl Manifest {
    /// 提取 Manifest 规范化字节数据（排除 signature 字段本身），供生成与校验数字签名使用
    ///
    /// # 设计原理
    /// - **实现初衷**：在计算签名和验签前，需排除 `signature` 字段本身并生成确定性字节流。原先采用 `self.clone()` 全量深拷贝，存在无谓的堆内存分配与字符串克隆开销。
    /// - **核心优势**：通过轻量借用视图（[`CanonicalManifestView`]）仅持有现有字段的只读切片与引用，在序列化时实现零额外深拷贝（Zero-Clone），显著降低 CPU 与内存开销。
    /// - **代价与局限**：借用视图结构体字段名与序列化标记需与 Manifest 保持强一致同步。
    ///
    /// # Errors
    /// 当 JSON 序列化失败时返回 [`UpdateError::ManifestParse`]。
    pub fn compute_canonical_bytes(&self) -> Result<Vec<u8>> {
        let view = CanonicalManifestView {
            version: &self.version,
            min_supported_version: self.min_supported_version.as_ref(),
            force_update: self.force_update,
            pub_date: self.pub_date.as_deref(),
            notes: self.notes.as_deref(),
            packages: &self.packages,
            channels: &self.channels,
            signature: None,
            rollout_percentage: self.rollout_percentage,
            expires_at: self.expires_at.as_deref(),
            version_seq: self.version_seq,
        };
        serde_json::to_vec(&view)
            .map_err(|e| UpdateError::ManifestParse(format!("序列化规范化清单失败: {}", e)))
    }

    /// 收集针对 Manifest 清单本身的所有可用候选数字签名列表（合并单签与多签）
    pub fn all_signatures(&self) -> Vec<SignatureEntry> {
        let mut list =
            Vec::with_capacity(self.signatures.len() + usize::from(self.signature.is_some()));
        if let Some(ref sig) = self.signature {
            list.push(SignatureEntry {
                key_id: None,
                signature: sig.clone(),
            });
        }
        list.extend(self.signatures.iter().cloned());
        list
    }

    /// 使用配置的候选公钥环校验 Manifest 本身的完整性与数字签名（单签兼容模式）
    ///
    /// # Errors
    /// 当缺少签名字段或所有公钥均验签失败时返回错误。
    pub fn verify_signature(&self, public_keys: &[impl AsRef<str>]) -> Result<()> {
        self.verify_signatures_threshold(public_keys, 1)
    }

    /// 使用配置的候选公钥环校验 Manifest 本身的完整性与 TUF 风格门限多签
    ///
    /// # 设计原理
    /// - **实现初衷**：遵循 TUF 门限安全模型（M-of-N Threshold Signatures），要求至少达到 `threshold` 个独立受信任公钥的有效签名。
    /// - **核心优势**：自动收集 `signature` 与 `signatures` 中所有候选签名，杜绝单私钥被盗即被任意投毒的风险。
    ///
    /// # Errors
    /// 当签名数不足门限或未能通过足够数量的独立公钥校验时返回 [`UpdateError::ThresholdNotMet`]。
    pub fn verify_signatures_threshold(
        &self,
        public_keys: &[impl AsRef<str>],
        threshold: usize,
    ) -> Result<()> {
        let all_sigs = self.all_signatures();
        let canonical_bytes = self.compute_canonical_bytes()?;
        crate::signature::verify_ed25519_threshold(
            &canonical_bytes,
            &all_sigs,
            public_keys,
            threshold,
        )
    }

    /// 校验 Manifest 是否已超过指定的过期失效时间戳
    ///
    /// # 设计原理
    /// - **实现初衷**：防御重放攻击（Replay Attacks），杜绝攻击者使用已废弃但带有合法签名的旧版本清单。
    /// - **核心优势**：直接基于绝对 Unix 秒数比对，零额外外部重度依赖。
    ///
    /// # Errors
    /// 当配置了 `expires_at` 且当前时间已晚于该时间戳时，返回 [`UpdateError::ManifestExpired`]。
    pub fn verify_freshness(&self, now_unix: u64) -> Result<()> {
        if let Some(ref exp) = self.expires_at {
            if let Some(exp_ts) = parse_rfc3339_to_unix(exp) {
                if now_unix > exp_ts {
                    return Err(UpdateError::ManifestExpired(exp.clone()));
                }
            } else {
                return Err(UpdateError::ManifestParse(format!(
                    "无法解析 expires_at 时间戳: {}",
                    exp
                )));
            }
        }
        Ok(())
    }
}
