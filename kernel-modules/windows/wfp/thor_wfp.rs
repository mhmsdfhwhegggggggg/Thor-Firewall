// Thor Firewall — Windows Filtering Platform (WFP) Driver
// مشغّل Windows بصلاحيات Kernel-mode
//
// يُنفّذ:
//   - Callout driver للفحص عند طبقات WFP
//   - Named Pipe IPC مع user-mode agent
//   - فحص الحزم عند FWPM_LAYER_INBOUND_TRANSPORT_V4
//   - فحص الحزم عند FWPM_LAYER_OUTBOUND_TRANSPORT_V4
//   - Connection tracking
//
// يتطلب: windows-rs 0.58 + km crate للـ kernel-mode
//
// SPDX-License-Identifier: MIT

#![cfg(target_os = "windows")]
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::Foundation::*;
use windows::core::*;

// ============================================================================
// WFP Layer GUIDs
// ============================================================================

/// GUID الـ callout — يجب أن يكون ثابتاً عبر التحديثات
const THOR_CALLOUT_INBOUND_GUID: GUID = GUID {
    data1: 0xA1B2C3D4,
    data2: 0xE5F6,
    data3: 0x7890,
    data4: [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90],
};

const THOR_CALLOUT_OUTBOUND_GUID: GUID = GUID {
    data1: 0xB2C3D4E5,
    data2: 0xF6A7,
    data3: 0x8901,
    data4: [0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x91],
};

// ============================================================================
// Packet Verdict
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum Verdict {
    Allow   = FWP_ACTION_PERMIT.0,
    Block   = FWP_ACTION_BLOCK.0,
    Continue = FWP_ACTION_CONTINUE.0,
}

// ============================================================================
// WFP Statistics
// ============================================================================

#[derive(Debug, Default)]
pub struct WfpStats {
    pub inbound_packets: AtomicU64,
    pub outbound_packets: AtomicU64,
    pub blocked_inbound: AtomicU64,
    pub blocked_outbound: AtomicU64,
    pub bytes_inbound: AtomicU64,
    pub bytes_outbound: AtomicU64,
    pub callout_errors: AtomicU64,
}

impl WfpStats {
    pub fn snapshot(&self) -> WfpStatsSnapshot {
        WfpStatsSnapshot {
            inbound_packets:  self.inbound_packets.load(Ordering::Relaxed),
            outbound_packets: self.outbound_packets.load(Ordering::Relaxed),
            blocked_inbound:  self.blocked_inbound.load(Ordering::Relaxed),
            blocked_outbound: self.blocked_outbound.load(Ordering::Relaxed),
            bytes_inbound:    self.bytes_inbound.load(Ordering::Relaxed),
            bytes_outbound:   self.bytes_outbound.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WfpStatsSnapshot {
    pub inbound_packets:  u64,
    pub outbound_packets: u64,
    pub blocked_inbound:  u64,
    pub blocked_outbound: u64,
    pub bytes_inbound:    u64,
    pub bytes_outbound:   u64,
}

// ============================================================================
// Packet Metadata (from WFP classify callback)
// ============================================================================

#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub src_ip:   [u8; 4],
    pub dst_ip:   [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,    // IPPROTO_TCP=6, IPPROTO_UDP=17
    pub flags:    u8,    // TCP flags (SYN, ACK, RST...)
    pub pkt_len:  u16,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

// ============================================================================
// Decision Cache
// ============================================================================

/// كاش قرارات بسيط لتجنب تكرار ML على الحزم المتتالية
/// يُستخدم عندما يكون القرار نفسه لكل حزمة في التدفق

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::Mutex;

struct CacheEntry {
    verdict: Verdict,
    expires: Instant,
}

pub struct DecisionCache {
    entries: Mutex<HashMap<u64, CacheEntry>>,
    ttl:     Duration,
}

impl DecisionCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn flow_hash(meta: &PacketMeta) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        meta.src_ip.hash(&mut h);
        meta.dst_ip.hash(&mut h);
        meta.src_port.hash(&mut h);
        meta.dst_port.hash(&mut h);
        meta.protocol.hash(&mut h);
        h.finish()
    }

    pub fn get(&self, meta: &PacketMeta) -> Option<Verdict> {
        let hash = Self::flow_hash(meta);
        let mut cache = self.entries.lock();
        if let Some(entry) = cache.get(&hash) {
            if entry.expires > Instant::now() {
                return Some(entry.verdict);
            }
            cache.remove(&hash);
        }
        None
    }

    pub fn insert(&self, meta: &PacketMeta, verdict: Verdict) {
        let hash = Self::flow_hash(meta);
        self.entries.lock().insert(
            hash,
            CacheEntry {
                verdict,
                expires: Instant::now() + self.ttl,
            }
        );
    }

    /// تنظيف المدخلات المنتهية دورياً
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.lock().retain(|_, v| v.expires > now);
    }
}

// ============================================================================
// WFP Driver
// ============================================================================

pub struct ThorWfpDriver {
    engine_handle: HANDLE,
    stats:        Arc<WfpStats>,
    cache:        Arc<DecisionCache>,
    running:      Arc<AtomicBool>,
}

impl ThorWfpDriver {
    /// تهيئة محرك WFP وتسجيل الـ callouts
    pub fn new() -> anyhow::Result<Self> {
        // فتح WFP engine بصلاحيات dynamic session
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };

        let mut engine_handle = INVALID_HANDLE_VALUE;

        unsafe {
            FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut engine_handle,
            ).map_err(|e| anyhow::anyhow!("FwpmEngineOpen0 failed: {:?}", e))?;
        }

        let stats = Arc::new(WfpStats::default());
        let cache = Arc::new(DecisionCache::new(30));

        Ok(Self {
            engine_handle,
            stats,
            cache,
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// تسجيل callouts في WFP
    pub fn register_callouts(&self) -> anyhow::Result<()> {
        // Inbound callout
        let inbound_callout = FWPM_CALLOUT0 {
            calloutKey: THOR_CALLOUT_INBOUND_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR::null(),
                description: windows::core::PWSTR::null(),
            },
            applicableLayer: FWPM_LAYER_INBOUND_TRANSPORT_V4,
            ..Default::default()
        };

        unsafe {
            FwpmCalloutAdd0(
                self.engine_handle,
                &inbound_callout,
                None,
                None,
            ).map_err(|e| anyhow::anyhow!("FwpmCalloutAdd0 (inbound) failed: {:?}", e))?;
        }

        // Outbound callout
        let outbound_callout = FWPM_CALLOUT0 {
            calloutKey: THOR_CALLOUT_OUTBOUND_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR::null(),
                description: windows::core::PWSTR::null(),
            },
            applicableLayer: FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            ..Default::default()
        };

        unsafe {
            FwpmCalloutAdd0(
                self.engine_handle,
                &outbound_callout,
                None,
                None,
            ).map_err(|e| anyhow::anyhow!("FwpmCalloutAdd0 (outbound) failed: {:?}", e))?;
        }

        tracing::info!("WFP callouts registered successfully");
        Ok(())
    }

    /// معالجة حزمة واردة
    pub fn classify_packet(&self, meta: &PacketMeta) -> Verdict {
        // تحديث الإحصاءات
        match meta.direction {
            Direction::Inbound => {
                self.stats.inbound_packets.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_inbound.fetch_add(meta.pkt_len as u64, Ordering::Relaxed);
            }
            Direction::Outbound => {
                self.stats.outbound_packets.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_outbound.fetch_add(meta.pkt_len as u64, Ordering::Relaxed);
            }
        }

        // فحص الكاش أولاً
        if let Some(cached) = self.cache.get(meta) {
            return cached;
        }

        // قرار أولي بدون ML (سريع جداً)
        let verdict = self.fast_classify(meta);

        // تخزين في الكاش
        self.cache.insert(meta, verdict);

        verdict
    }

    /// تصنيف سريع (قبل ML) — قواعد ثابتة
    fn fast_classify(&self, meta: &PacketMeta) -> Verdict {
        // SYN flood early detection: SYN فقط بدون ACK من نفس المصدر كثيراً
        if meta.protocol == 6 && (meta.flags & 0x02 != 0) && (meta.flags & 0x10 == 0) {
            // SYN only — يُحلَّل بشكل أعمق في ML
        }

        // حظر المنافذ الخطيرة من خارج الشبكة المحلية
        let is_local = is_local_ip(&meta.src_ip);
        if !is_local && is_dangerous_port(meta.dst_port) {
            tracing::debug!(
                src = format!("{}.{}.{}.{}", meta.src_ip[0], meta.src_ip[1], meta.src_ip[2], meta.src_ip[3]),
                dst_port = meta.dst_port,
                "Blocked dangerous port from external IP"
            );
            self.stats.blocked_inbound.fetch_add(1, Ordering::Relaxed);
            return Verdict::Block;
        }

        Verdict::Continue  // للـ ML
    }

    pub fn stats(&self) -> WfpStatsSnapshot {
        self.stats.snapshot()
    }
}

impl Drop for ThorWfpDriver {
    fn drop(&mut self) {
        if self.engine_handle != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = FwpmEngineClose0(self.engine_handle);
            }
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn is_local_ip(ip: &[u8; 4]) -> bool {
    ip[0] == 10 ||
    (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
    (ip[0] == 192 && ip[1] == 168) ||
    ip[0] == 127
}

fn is_dangerous_port(port: u16) -> bool {
    matches!(port, 1433 | 1434 | 3306 | 5432 | 6379 | 27017 | 27018 | 9200 | 11211 | 2375 | 2376)
}

// ============================================================================
// Named Pipe IPC
// ============================================================================

pub mod ipc {
    use super::*;
    use windows::Win32::System::Pipes::*;
    use windows::Win32::Storage::FileSystem::*;
    use serde::{Serialize, Deserialize};

    const PIPE_NAME: &str = r"\\.\pipe\thor_firewall";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct IpcMessage {
        pub msg_type: String,
        pub flow_hash: Option<u64>,
        pub verdict: Option<String>,
        pub risk_score: Option<f32>,
    }

    /// خادم Pipe (يعمل في Kernel/Service)
    pub struct PipeServer {
        pipe_name: String,
    }

    impl PipeServer {
        pub fn new() -> Self {
            Self { pipe_name: PIPE_NAME.to_string() }
        }

        pub async fn listen<F>(&self, handler: F) -> anyhow::Result<()>
        where
            F: Fn(IpcMessage) -> IpcMessage + Send + Sync + 'static,
        {
            use tokio::net::windows::named_pipe::ServerOptions;

            loop {
                let server = ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(&self.pipe_name)?;

                server.connect().await?;

                let mut buf = vec![0u8; 4096];
                use tokio::io::AsyncReadExt;
                let n = tokio::io::AsyncReadExt::read(&mut &server, &mut buf).await?;

                if let Ok(msg) = serde_json::from_slice::<IpcMessage>(&buf[..n]) {
                    let response = handler(msg);
                    let response_bytes = serde_json::to_vec(&response)?;
                    use tokio::io::AsyncWriteExt;
                    tokio::io::AsyncWriteExt::write_all(&mut &server, &response_bytes).await?;
                }
            }
        }
    }
}
