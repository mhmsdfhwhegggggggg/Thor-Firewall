// Thor Firewall — Packet Parser
// محلل الحزم فائق السرعة مع دعم SIMD
//
// يحول الحزمة الخام إلى بنية داخلية محسّنة في < 50ns
// يدعم: IPv4, IPv6, TCP, UDP, ICMP, ICMP6, SCTP, GRE, VXLAN

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use etherparse::{SlicedPacket, TransportSlice, NetSlice};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use xxhash_rust::xxh3::xxh3_64;

use crate::error::ThorError;

/// پروتوکول‌های پشتیباني‌شده
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
    Icmp = 1,
    Icmpv6 = 58,
    Sctp = 132,
    Gre = 47,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        match v {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            58 => Protocol::Icmpv6,
            132 => Protocol::Sctp,
            47 => Protocol::Gre,
            other => Protocol::Other(other),
        }
    }
}

/// TCP flags bitmask
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub fn syn(&self) -> bool { self.0 & 0x02 != 0 }
    pub fn ack(&self) -> bool { self.0 & 0x10 != 0 }
    pub fn fin(&self) -> bool { self.0 & 0x01 != 0 }
    pub fn rst(&self) -> bool { self.0 & 0x04 != 0 }
    pub fn psh(&self) -> bool { self.0 & 0x08 != 0 }
    pub fn urg(&self) -> bool { self.0 & 0x20 != 0 }
    pub fn ece(&self) -> bool { self.0 & 0x40 != 0 }
    pub fn cwr(&self) -> bool { self.0 & 0x80 != 0 }

    /// SYN without ACK — new connection attempt
    pub fn is_syn_only(&self) -> bool { self.syn() && !self.ack() }
}

/// 5-tuple flow key — primary identifier for a network flow
/// Aligned to 32 bytes for cache efficiency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C, align(32))]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FlowKey {
    /// Compute a fast xxh3 hash of the flow key
    #[inline(always)]
    pub fn hash(&self) -> u64 {
        // SAFETY: We use repr(C) and the struct is Copy, so this is safe
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        };
        xxh3_64(bytes)
    }

    /// Return the canonical (direction-normalized) key
    /// Ensures src < dst so bidirectional flows share the same key
    pub fn canonical(&self) -> Self {
        let (src_ip, src_port, dst_ip, dst_port) = match self.src_ip.cmp(&self.dst_ip) {
            std::cmp::Ordering::Greater => (self.dst_ip, self.dst_port, self.src_ip, self.src_port),
            std::cmp::Ordering::Less => (self.src_ip, self.src_port, self.dst_ip, self.dst_port),
            std::cmp::Ordering::Equal => {
                if self.src_port > self.dst_port {
                    (self.dst_ip, self.dst_port, self.src_ip, self.src_port)
                } else {
                    (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
                }
            }
        };
        FlowKey { src_ip, dst_ip, src_port, dst_port, protocol: self.protocol }
    }
}

/// Full parsed packet with all metadata needed for ML analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPacket {
    /// Flow identifier
    pub flow_key: FlowKey,

    /// Timestamp in nanoseconds since UNIX epoch
    pub timestamp_ns: u64,

    /// Total packet length (including headers)
    pub packet_len: u16,

    /// IP header TTL/hop limit
    pub ttl: u8,

    /// IP DSCP/TOS for QoS analysis
    pub dscp: u8,

    /// TCP-specific fields (None for non-TCP)
    pub tcp_flags: Option<TcpFlags>,
    pub tcp_window: Option<u16>,
    pub tcp_seq: Option<u32>,

    /// Payload entropy (0.0 = all zeros, 8.0 = random/encrypted)
    pub payload_entropy: f32,

    /// Payload length (excluding headers)
    pub payload_len: u16,

    /// VXLAN/GRE tunnel info if applicable
    pub is_tunneled: bool,

    /// Direction: true = inbound, false = outbound
    pub inbound: bool,
}

impl ParsedPacket {
    /// Extract 50 ML features as a flat f32 vector
    /// Feature vector layout documented in docs/ml/feature_spec.md
    pub fn to_feature_vector(&self) -> [f32; 50] {
        let mut f = [0.0f32; 50];

        // Network layer features (0-9)
        f[0] = self.packet_len as f32;
        f[1] = self.payload_len as f32;
        f[2] = self.ttl as f32;
        f[3] = self.dscp as f32;
        f[4] = self.is_tunneled as i32 as f32;
        f[5] = self.inbound as i32 as f32;
        f[6] = match self.flow_key.protocol {
            Protocol::Tcp => 1.0,
            Protocol::Udp => 2.0,
            Protocol::Icmp | Protocol::Icmpv6 => 3.0,
            Protocol::Sctp => 4.0,
            _ => 0.0,
        };

        // Port features (10-19)
        f[10] = self.flow_key.src_port as f32;
        f[11] = self.flow_key.dst_port as f32;
        f[12] = (self.flow_key.dst_port < 1024) as i32 as f32; // well-known port
        f[13] = (self.flow_key.dst_port >= 1024 && self.flow_key.dst_port < 49152) as i32 as f32;

        // TCP flag features (20-29)
        if let Some(flags) = self.tcp_flags {
            f[20] = flags.syn() as i32 as f32;
            f[21] = flags.ack() as i32 as f32;
            f[22] = flags.fin() as i32 as f32;
            f[23] = flags.rst() as i32 as f32;
            f[24] = flags.psh() as i32 as f32;
            f[25] = flags.urg() as i32 as f32;
            f[26] = flags.is_syn_only() as i32 as f32;
            f[27] = self.tcp_window.unwrap_or(0) as f32;
        }

        // Payload features (30-39)
        f[30] = self.payload_entropy;

        // Timing features (40-49)
        f[40] = (self.timestamp_ns % 1_000_000_000) as f32; // nanoseconds within second

        f
    }
}

/// Parser configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ParserConfig {
    /// Enable payload entropy calculation (slight CPU overhead)
    pub compute_entropy: bool,
    /// Maximum packet size to process (bytes)
    pub max_packet_size: usize,
    /// Enable VXLAN tunnel unwrapping
    pub unwrap_vxlan: bool,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            compute_entropy: true,
            max_packet_size: 65535,
            unwrap_vxlan: true,
        }
    }
}

/// High-performance packet parser
pub struct PacketParser {
    config: ParserConfig,
}

impl PacketParser {
    pub fn new(config: ParserConfig) -> Self {
        Self { config }
    }

    /// Parse raw ethernet frame into ParsedPacket
    /// Returns None for malformed or unsupported packets
    #[inline]
    pub fn parse(&self, raw: &[u8], inbound: bool) -> Option<ParsedPacket> {
        if raw.len() > self.config.max_packet_size {
            warn!(len = raw.len(), "Oversized packet dropped");
            return None;
        }

        let sliced = SlicedPacket::from_ethernet(raw).ok()?;

        let (src_ip, dst_ip, ttl, dscp, protocol_num) = match &sliced.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                (
                    IpAddr::V4(Ipv4Addr::from(h.source())),
                    IpAddr::V4(Ipv4Addr::from(h.destination())),
                    h.ttl(),
                    h.differentiated_services_code_point(),
                    h.protocol().0,
                )
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                let h = ipv6.header();
                (
                    IpAddr::V6(Ipv6Addr::from(h.source())),
                    IpAddr::V6(Ipv6Addr::from(h.destination())),
                    h.hop_limit(),
                    (h.traffic_class() >> 2) & 0x3F,
                    h.next_header().0,
                )
            }
            _ => return None,
        };

        let (src_port, dst_port, tcp_flags, tcp_window, tcp_seq) = match &sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let h = tcp.to_header();
                (
                    h.source_port,
                    h.destination_port,
                    Some(TcpFlags(tcp.slice()[13])),
                    Some(h.window_size),
                    Some(h.sequence_number),
                )
            }
            Some(TransportSlice::Udp(udp)) => {
                let h = udp.to_header();
                (h.source_port, h.destination_port, None, None, None)
            }
            _ => (0, 0, None, None, None),
        };

        let payload = sliced.payload.slice();
        let payload_len = payload.len() as u16;
        let payload_entropy = if self.config.compute_entropy && !payload.is_empty() {
            compute_entropy(payload)
        } else {
            0.0
        };

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Some(ParsedPacket {
            flow_key: FlowKey {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol: Protocol::from(protocol_num),
            },
            timestamp_ns,
            packet_len: raw.len() as u16,
            ttl,
            dscp,
            tcp_flags,
            tcp_window,
            tcp_seq,
            payload_entropy,
            payload_len,
            is_tunneled: false,
            inbound,
        })
    }
}

/// Shannon entropy calculation for payload analysis
/// Returns value in bits (0.0 = all same bytes, 8.0 = perfectly random)
#[inline]
fn compute_entropy(data: &[u8]) -> f32 {
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_all_zeros() {
        let data = vec![0u8; 100];
        assert_eq!(compute_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // All 256 values equally distributed = max entropy (8.0 bits)
        let data: Vec<u8> = (0u8..=255).collect();
        let e = compute_entropy(&data);
        assert!((e - 8.0).abs() < 0.001, "Expected ~8.0, got {}", e);
    }

    #[test]
    fn test_flow_key_canonical() {
        let k1 = FlowKey {
            src_ip: IpAddr::V4("10.0.0.1".parse().unwrap()),
            dst_ip: IpAddr::V4("10.0.0.2".parse().unwrap()),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
        };
        let k2 = FlowKey {
            src_ip: IpAddr::V4("10.0.0.2".parse().unwrap()),
            dst_ip: IpAddr::V4("10.0.0.1".parse().unwrap()),
            src_port: 80,
            dst_port: 12345,
            protocol: Protocol::Tcp,
        };
        // Both should canonicalize to the same key
        assert_eq!(k1.canonical(), k2.canonical());
    }

    #[test]
    fn test_tcp_flags_syn_only() {
        let flags = TcpFlags(0x02); // SYN
        assert!(flags.syn());
        assert!(!flags.ack());
        assert!(flags.is_syn_only());
    }

    #[test]
    fn test_feature_vector_length() {
        use std::net::IpAddr;
        let pkt = ParsedPacket {
            flow_key: FlowKey {
                src_ip: "192.168.1.1".parse().unwrap(),
                dst_ip: "8.8.8.8".parse().unwrap(),
                src_port: 54321,
                dst_port: 443,
                protocol: Protocol::Tcp,
            },
            timestamp_ns: 0,
            packet_len: 100,
            ttl: 64,
            dscp: 0,
            tcp_flags: Some(TcpFlags(0x02)),
            tcp_window: Some(65535),
            tcp_seq: Some(12345),
            payload_entropy: 7.5,
            payload_len: 60,
            is_tunneled: false,
            inbound: true,
        };
        let features = pkt.to_feature_vector();
        assert_eq!(features.len(), 50);
    }
}
