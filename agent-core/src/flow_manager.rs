// Thor Firewall - Flow Manager
// يجمع الحزم في تدفقات (5-tuple) ويحسب إحصائيات سلوكية

use crate::packet_parser::{ParsedPacket, IpAddr, IpProtocol};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// معرف فريد للتدفق
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct FlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: IpProtocol,
}

/// إحصائيات التدفق (تُغذى إلى نموذج التعلم المعزز)
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub packets_count: u64,
    pub bytes_count: u64,
    pub start_time: Instant,
    pub last_seen: Instant,
    pub avg_packet_size: f64,
    pub packet_rate: f64,     // حزمة/ثانية
    pub byte_rate: f64,       // بايت/ثانية
    pub flags_tcp: Option<TcpFlags>,
}

#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    pub syn: u32,
    pub ack: u32,
    pub fin: u32,
    pub rst: u32,
}

pub struct FlowManager {
    flows: HashMap<FlowKey, FlowStats>,
    idle_timeout: Duration,
}

impl FlowManager {
    pub fn new(idle_seconds: u64) -> Self {
        Self {
            flows: HashMap::new(),
            idle_timeout: Duration::from_secs(idle_seconds),
        }
    }

    /// تحديث التدفق بحزمة جديدة
    pub fn update(&mut self, pkt: &ParsedPacket) -> Option<FlowStats> {
        let (src_port, dst_port) = match (pkt.src_port, pkt.dst_port) {
            (Some(sp), Some(dp)) => (sp, dp),
            _ => return None, // ليست TCP/UDP
        };
        let key = FlowKey {
            src_ip: pkt.src_ip.clone(),
            dst_ip: pkt.dst_ip.clone(),
            src_port,
            dst_port,
            protocol: pkt.protocol,
        };
        let now = Instant::now();
        if let Some(stats) = self.flows.get_mut(&key) {
            // تحديث التدفق الموجود
            stats.packets_count += 1;
            stats.bytes_count += pkt.payload_len as u64;
            let dt = now.duration_since(stats.last_seen).as_secs_f64();
            if dt > 0.0 {
                stats.packet_rate = (stats.packets_count as f64) / now.duration_since(stats.start_time).as_secs_f64();
                stats.byte_rate = (stats.bytes_count as f64) / now.duration_since(stats.start_time).as_secs_f64();
            }
            stats.avg_packet_size = stats.bytes_count as f64 / stats.packets_count as f64;
            stats.last_seen = now;
            // TODO: تحليل أعلام TCP من الحمولة
            None
        } else {
            // تدفق جديد
            let stats = FlowStats {
                packets_count: 1,
                bytes_count: pkt.payload_len as u64,
                start_time: now,
                last_seen: now,
                avg_packet_size: pkt.payload_len as f64,
                packet_rate: 0.0,
                byte_rate: 0.0,
                flags_tcp: None,
            };
            self.flows.insert(key, stats);
            None
        }
    }

    /// إزالة التدفقات القديمة وإرجاعها لتحليلها
    pub fn expire_old_flows(&mut self) -> Vec<(FlowKey, FlowStats)> {
        let now = Instant::now();
        let mut expired = Vec::new();
        self.flows.retain(|key, stats| {
            if now.duration_since(stats.last_seen) > self.idle_timeout {
                expired.push((key.clone(), stats.clone()));
                false
            } else {
                true
            }
        });
        expired
    }

    /// إرجاع جميع التدفقات الحالية (للاستخدام في RL)
    pub fn get_all_flows(&self) -> Vec<FlowStats> {
        self.flows.values().cloned().collect()
    }
}
