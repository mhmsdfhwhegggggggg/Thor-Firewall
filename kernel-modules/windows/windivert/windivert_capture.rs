//! Thor Firewall — WinDivert Userspace Packet Capture (Windows)
//! =============================================================
//! مستوحى من: https://github.com/basil00/WinDivert
//!            https://github.com/microsoft/ebpf-for-windows (future)
//!
//! WinDivert يُمكّن من:
//!   - اعتراض وفلترة حزم الشبكة في userspace على Windows
//!   - تطبيق قرارات ML على مستوى WFP (Windows Filtering Platform)
//!   - جمع بيانات التدفق لتغذية نموذج MARL
//!
//! الفرق عن Linux eBPF:
//!   - Linux: XDP hooks in kernel (<100ns)
//!   - Windows: WinDivert in userspace (~1ms, كافٍ للـ NGFW)
//!   - المستقبل: ebpf-for-windows (Microsoft) → kernel-level
//!
//! SPDX-License-Identifier: MIT

#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc,
    time::timeout,
};
use tracing::{debug, error, info, warn};

// WinDivert FFI bindings (via windivert-sys crate)
// In production: use windivert crate v0.3+
// For now: define minimal FFI interface
mod ffi {
    pub const WINDIVERT_LAYER_NETWORK: u32 = 0;
    pub const WINDIVERT_FLAG_DEFAULT:  u64 = 0;
    pub const WINDIVERT_FLAG_DROP:     u64 = 4;

    pub const WINDIVERT_EVENT_NETWORK_PACKET: u32 = 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures
// ─────────────────────────────────────────────────────────────────────────────

/// IPv4 packet header (simplified)
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub src_addr:   Ipv4Addr,
    pub dst_addr:   Ipv4Addr,
    pub protocol:   u8,
    pub tot_len:    u16,
    pub ttl:        u8,
}

/// TCP header (simplified)
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port:  u16,
    pub dst_port:  u16,
    pub flags:     u8,
    pub seq:       u32,
    pub ack:       u32,
}

/// Captured packet (WinDivert)
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub timestamp_ns:   u64,
    pub direction:      PacketDirection,
    pub ip_header:      Option<Ipv4Header>,
    pub tcp_header:     Option<TcpHeader>,
    pub payload_len:    usize,
    pub payload_head:   [u8; 32],  // first 32 bytes
    pub if_index:       u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

/// Decision from ML inference server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketVerdict {
    Allow,
    Block,
    Throttle,
}

/// Flow key (5-tuple)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip:   u32,
    pub dst_ip:   u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Packet features for ML (50-dim)
#[derive(Debug, Serialize)]
pub struct PacketFeatures {
    pub flow_hash:        u64,
    pub features:         [f32; 50],
    pub timestamp_ns:     u64,
    pub direction:        u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// WinDivert Capture Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Windows packet capture engine using WinDivert.
///
/// WinDivert Filter Syntax examples:
///   - All TCP:        "tcp"
///   - Inbound only:   "inbound and tcp"
///   - Skip loopback:  "not loopback"
///   - High priority:  "tcp.DstPort == 443"
///
/// Thor default filter: "ip and not loopback"
pub struct WinDivertCapture {
    filter:         String,
    running:        Arc<AtomicBool>,
    packet_count:   Arc<AtomicU64>,
    drop_count:     Arc<AtomicU64>,
    verdict_cache:  Arc<tokio::sync::RwLock<HashMap<FlowKey, PacketVerdict>>>,
    ml_url:         String,
    http_client:    reqwest::Client,
}

impl WinDivertCapture {
    pub fn new(filter: impl Into<String>, ml_url: impl Into<String>) -> Self {
        Self {
            filter:       filter.into(),
            running:      Arc::new(AtomicBool::new(false)),
            packet_count: Arc::new(AtomicU64::new(0)),
            drop_count:   Arc::new(AtomicU64::new(0)),
            verdict_cache: Arc::new(tokio::sync::RwLock::new(HashMap::with_capacity(100_000))),
            ml_url:       ml_url.into(),
            http_client:  reqwest::Client::builder()
                .timeout(Duration::from_millis(5))
                .pool_max_idle_per_host(10)
                .build()
                .expect("HTTP client"),
        }
    }

    /// Start packet capture loop.
    /// Returns a receiver for captured packets and a sender for verdicts.
    pub async fn start(
        &self,
    ) -> Result<(mpsc::Receiver<CapturedPacket>, mpsc::Sender<(FlowKey, PacketVerdict)>)> {
        let (pkt_tx, pkt_rx) = mpsc::channel::<CapturedPacket>(10_000);
        let (verdict_tx, mut verdict_rx) = mpsc::channel::<(FlowKey, PacketVerdict)>(10_000);

        self.running.store(true, Ordering::Relaxed);
        info!("🪟 WinDivert capture started (filter: {})", self.filter);

        // Verdict cache updater
        let cache = Arc::clone(&self.verdict_cache);
        tokio::spawn(async move {
            while let Some((key, verdict)) = verdict_rx.recv().await {
                let mut c = cache.write().await;
                c.insert(key, verdict);
                // Evict oldest entries if cache too large
                if c.len() > 500_000 {
                    c.clear();
                }
            }
        });

        // NOTE: In production, this spawns a blocking thread that calls
        // WinDivertOpen() → WinDivertRecv() loop.
        // Here we provide the structure; actual WinDivert FFI calls
        // require the windivert crate linked against WinDivert.dll.
        //
        // Example production code:
        //   let handle = unsafe { WinDivertOpen(filter_cstr, LAYER_NETWORK, 0, 0) };
        //   loop {
        //       let mut pkt = [0u8; 65535];
        //       let mut addr = WINDIVERT_ADDRESS::default();
        //       let len = unsafe { WinDivertRecv(handle, pkt.as_mut_ptr(), pkt.len() as u32, &mut addr) };
        //       pkt_tx.send(parse_packet(&pkt[..len], &addr)).await?;
        //   }

        let running = Arc::clone(&self.running);
        let counter = Arc::clone(&self.packet_count);
        tokio::spawn(async move {
            info!("WinDivert capture loop ready (waiting for kernel events)");
            while running.load(Ordering::Relaxed) {
                // Placeholder: would be WinDivertRecv() blocking call
                tokio::time::sleep(Duration::from_millis(100)).await;
                counter.fetch_add(0, Ordering::Relaxed);
            }
        });

        Ok((pkt_rx, verdict_tx))
    }

    /// Parse raw WinDivert packet bytes into CapturedPacket
    pub fn parse_packet(&self, raw: &[u8], inbound: bool) -> Option<CapturedPacket> {
        if raw.len() < 20 { return None; }

        // Parse IPv4 header
        let ihl     = ((raw[0] & 0x0F) as usize) * 4;
        let proto   = raw[9];
        let tot_len = u16::from_be_bytes([raw[2], raw[3]]);
        let src_ip  = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
        let dst_ip  = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);

        let ip_header = Some(Ipv4Header {
            src_addr: src_ip,
            dst_addr: dst_ip,
            protocol: proto,
            tot_len,
            ttl: raw[8],
        });

        // Parse TCP header
        let tcp_header = if proto == 6 && raw.len() >= ihl + 20 {
            let tcp = &raw[ihl..];
            Some(TcpHeader {
                src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
                dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
                flags:    tcp[13],
                seq:      u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
                ack:      u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
            })
        } else {
            None
        };

        // Payload head
        let mut payload_head = [0u8; 32];
        let payload_start = if proto == 6 {
            ihl + ((raw.get(ihl + 12).copied().unwrap_or(80) >> 4) * 4) as usize
        } else if proto == 17 {
            ihl + 8
        } else {
            ihl
        };
        let copy_len = payload_head.len().min(raw.len().saturating_sub(payload_start));
        if copy_len > 0 {
            payload_head[..copy_len].copy_from_slice(&raw[payload_start..payload_start + copy_len]);
        }

        Some(CapturedPacket {
            timestamp_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            direction: if inbound { PacketDirection::Inbound } else { PacketDirection::Outbound },
            ip_header,
            tcp_header,
            payload_len: raw.len().saturating_sub(payload_start),
            payload_head,
            if_index: 0,
        })
    }

    /// Extract 50 features from a packet (same as Linux PacketParser)
    pub fn extract_features(&self, pkt: &CapturedPacket) -> [f32; 50] {
        let mut features = [0.0f32; 50];

        // Features 0-3: IP layer
        if let Some(ip) = &pkt.ip_header {
            let src = u32::from(ip.src_addr);
            let dst = u32::from(ip.dst_addr);
            features[0] = (ip.protocol as f32) / 255.0;
            features[1] = (ip.tot_len as f32)  / 65535.0;
            features[2] = (ip.ttl as f32)      / 255.0;
            features[3] = ((src >> 24) as f32)  / 255.0;   // src /24 prefix
        }

        // Features 4-9: TCP layer
        if let Some(tcp) = &pkt.tcp_header {
            features[4]  = (tcp.src_port as f32)  / 65535.0;
            features[5]  = (tcp.dst_port as f32)  / 65535.0;
            features[6]  = ((tcp.flags & 0x02 != 0) as i32) as f32;  // SYN
            features[7]  = ((tcp.flags & 0x10 != 0) as i32) as f32;  // ACK
            features[8]  = ((tcp.flags & 0x01 != 0) as i32) as f32;  // FIN
            features[9]  = ((tcp.flags & 0x04 != 0) as i32) as f32;  // RST

            // Known port classification
            features[10] = match tcp.dst_port {
                80 | 8080            => 0.1,   // HTTP
                443 | 8443           => 0.1,   // HTTPS
                22                   => 0.5,   // SSH (elevated)
                23                   => 0.9,   // Telnet (high risk)
                3389                 => 0.7,   // RDP
                445                  => 0.8,   // SMB
                1433 | 3306 | 5432   => 0.8,   // DB ports
                _                    => 0.3,
            };
        }

        // Features 10-17: Payload entropy (Shannon)
        let payload = &pkt.payload_head;
        let entropy = if pkt.payload_len > 0 {
            let mut counts = [0u32; 256];
            for &b in payload.iter() {
                counts[b as usize] += 1;
            }
            let n = payload.len() as f32;
            -counts.iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = (c as f32) / n;
                    p * p.log2()
                })
                .sum::<f32>() / 8.0  // normalize to [0, 1]
        } else {
            0.0
        };
        features[11] = entropy;
        features[12] = (pkt.payload_len as f32).min(65535.0) / 65535.0;
        features[13] = if pkt.direction == PacketDirection::Inbound { 0.0 } else { 1.0 };

        // Features 14-49: temporal/statistical (would be populated from FlowManager)
        features  // remaining are 0.0 for single-packet analysis
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.packet_count.load(Ordering::Relaxed),
            self.drop_count.load(Ordering::Relaxed),
        )
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("WinDivert capture stopped");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows Agent Main Loop
// ─────────────────────────────────────────────────────────────────────────────

/// Run the Thor Windows agent (WinDivert-based).
/// Equivalent to the Linux thor-agent but uses WinDivert instead of XDP.
pub async fn run_windows_agent(
    filter:    String,
    ml_url:    String,
    redis_url: String,
) -> Result<()> {
    info!("🪟 Thor Windows Agent starting (WinDivert mode)");
    info!("   Filter: {}", filter);
    info!("   ML URL: {}", ml_url);

    let capture = WinDivertCapture::new(&filter, &ml_url);
    let (mut pkt_rx, verdict_tx) = capture.start().await?;

    // ML inference client (same HTTP API as Linux agent)
    let ml_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(50))
        .build()?;

    let mut batch: Vec<PacketFeatures> = Vec::with_capacity(256);
    let mut last_send = Instant::now();

    while let Some(pkt) = pkt_rx.recv().await {
        let features = capture.extract_features(&pkt);

        // Extract flow key for verdict caching
        let flow_key = if let (Some(ip), Some(tcp)) = (&pkt.ip_header, &pkt.tcp_header) {
            Some(FlowKey {
                src_ip:   u32::from(ip.src_addr),
                dst_ip:   u32::from(ip.dst_addr),
                src_port: tcp.src_port,
                dst_port: tcp.dst_port,
                protocol: ip.protocol,
            })
        } else {
            None
        };

        // Check cache first (fast path)
        if let Some(key) = &flow_key {
            let cache = capture.verdict_cache.read().await;
            if let Some(verdict) = cache.get(key) {
                match verdict {
                    PacketVerdict::Block => continue,  // drop
                    _ => {}
                }
            }
        }

        // Build feature vector
        let pkt_feat = PacketFeatures {
            flow_hash: {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                if let Some(k) = &flow_key { k.hash(&mut h); }
                h.finish()
            },
            features,
            timestamp_ns: pkt.timestamp_ns,
            direction: pkt.direction as u8,
        };
        batch.push(pkt_feat);

        // Send batch to ML every 256 packets or 1ms timeout
        if batch.len() >= 256 || last_send.elapsed() > Duration::from_millis(1) {
            if !batch.is_empty() {
                let batch_to_send = std::mem::take(&mut batch);
                let client = ml_client.clone();
                let url    = ml_url.clone();
                let vtx    = verdict_tx.clone();

                tokio::spawn(async move {
                    // POST to FastAPI ML server
                    let _ = client.post(&url)
                        .json(&serde_json::json!({
                            "flows": batch_to_send.iter().map(|f| f.features.to_vec()).collect::<Vec<_>>(),
                            "flow_ids": batch_to_send.iter().map(|f| f.flow_hash.to_string()).collect::<Vec<_>>(),
                        }))
                        .send()
                        .await;
                });

                last_send = Instant::now();
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_packet() {
        let capture = WinDivertCapture::new("tcp", "http://localhost:8082");

        // Minimal IPv4+TCP packet (40 bytes)
        let mut raw = vec![0u8; 40];
        raw[0] = 0x45;            // version=4, IHL=5
        raw[9] = 6;               // protocol=TCP
        raw[2] = 0; raw[3] = 40; // tot_len=40
        raw[8] = 64;              // TTL=64
        // src IP: 192.168.1.100
        raw[12..16].copy_from_slice(&[192, 168, 1, 100]);
        // dst IP: 8.8.8.8
        raw[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // TCP: src=12345, dst=443, flags=SYN
        raw[20] = 0x30; raw[21] = 0x39;  // src_port=12345
        raw[22] = 0x01; raw[23] = 0xBB;  // dst_port=443
        raw[32] = 0x50;                   // data offset=5
        raw[33] = 0x02;                   // flags=SYN

        let pkt = capture.parse_packet(&raw, true);
        assert!(pkt.is_some());
        let pkt = pkt.unwrap();
        assert_eq!(pkt.direction, PacketDirection::Inbound);

        let features = capture.extract_features(&pkt);
        assert_eq!(features.len(), 50);
        // Protocol=TCP (6/255)
        assert!((features[0] - 6.0 / 255.0).abs() < 0.001);
        // SYN flag should be 1.0
        assert_eq!(features[6], 1.0);
        // dst_port=443 (low risk)
        assert_eq!(features[10], 0.1);
    }
}
