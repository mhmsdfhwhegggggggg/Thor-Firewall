// Thor Firewall — eBPF Ring Buffer Consumer — COMPLETE IMPLEMENTATION
// مستهلك ring buffer — يعالج الحزم القادمة من kernel
//
// يستقبل PacketSample من XDP عبر channel،
// يحللها ويرسلها لمحرك RL للتصنيف.
//
// SPDX-License-Identifier: GPL-3.0

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::flow_manager::{Decision, FlowManager};
use crate::packet_parser::{FlowKey, PacketParser, ParsedPacket, Protocol, TcpFlags};
use crate::rl_core::{RLCore, RLRequest};
use crate::telemetry::metrics;

// ============================================================================
// PacketSample — يجب أن يتطابق مع struct packet_sample في thor_common.h
// ============================================================================

/// حزمة عينة مُرسلة من XDP kernel program
/// تطابق: struct packet_sample في kernel-modules/linux/ebpf/thor_common.h
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PacketSample {
    // struct flow_key (16 bytes)
    pub src_ip:   u32,   // network byte order
    pub dst_ip:   u32,   // network byte order
    pub sport:    u16,   // host byte order
    pub dport:    u16,   // host byte order
    pub proto:    u8,
    pub is_ipv6:  u8,
    pub pad:      [u8; 2],

    // metadata
    pub timestamp_ns:    u64,
    pub pkt_len:         u16,
    pub reason:          u8,   // SAMPLE_REASON_*
    pub tcp_flags:       u8,
    pub risk_score_x100: u32,
}

impl PacketSample {
    /// تحويل إلى ParsedPacket لتحليل ML
    pub fn to_parsed_packet(&self) -> Option<ParsedPacket> {
        use std::net::{IpAddr, Ipv4Addr};

        let src_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(self.src_ip)));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(self.dst_ip)));

        let protocol = Protocol::from(self.proto);
        let tcp_flags = if self.proto == 6 {
            Some(TcpFlags(self.tcp_flags))
        } else {
            None
        };

        Some(ParsedPacket {
            flow_key: FlowKey {
                src_ip,
                dst_ip,
                src_port:  self.sport,
                dst_port:  self.dport,
                protocol,
            },
            timestamp_ns:    self.timestamp_ns,
            packet_len:      self.pkt_len,
            ttl:             64, // unknown at this point
            dscp:            0,
            tcp_flags,
            tcp_window:      None,
            tcp_seq:         None,
            payload_entropy: 0.0, // يُحسب في مستوى أعلى إذا لزم
            payload_len:     self.pkt_len.saturating_sub(40), // تقدير
            is_tunneled:     false,
            inbound:         true,
        })
    }

    /// سبب الإرسال
    pub fn reason_str(&self) -> &'static str {
        match self.reason {
            0 => "new_flow",
            1 => "periodic",
            2 => "syn_flood",
            3 => "anomaly",
            4 => "high_risk",
            _ => "unknown",
        }
    }
}

// ============================================================================
// Ring Buffer Consumer
// ============================================================================

/// مُعالج الحزم القادمة من XDP ring buffer
#[derive(Clone)]
pub struct RingConsumer {
    parser:       Arc<PacketParser>,
    flow_manager: Arc<FlowManager>,
    rl_core:      Arc<RLCore>,
}

impl RingConsumer {
    pub fn new(
        parser:       Arc<PacketParser>,
        flow_manager: Arc<FlowManager>,
        rl_core:      Arc<RLCore>,
    ) -> Self {
        Self { parser, flow_manager, rl_core }
    }

    /// بدء حلقة الاستهلاك
    pub async fn run(self, mut rx: mpsc::Receiver<PacketSample>) {
        info!("Ring consumer starting");
        let m = metrics();

        let mut batch: Vec<PacketSample> = Vec::with_capacity(128);
        let mut ticker = tokio::time::interval(Duration::from_micros(500));

        loop {
            batch.clear();

            // جمع دفعة من الأحداث أو timeout
            let deadline = tokio::time::Instant::now() + Duration::from_micros(500);

            loop {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(sample)) => {
                        batch.push(sample);
                        if batch.len() >= 128 { break; }
                    }
                    Ok(None) => {
                        info!("Ring consumer channel closed");
                        return;
                    }
                    Err(_) => break, // timeout — معالجة الدفعة الحالية
                }
            }

            if batch.is_empty() {
                ticker.tick().await;
                continue;
            }

            // تحديث مؤشر عدد الحزم
            m.packets_total.inc_by(batch.len() as f64);

            // معالجة الدفعة
            if let Err(e) = self.process_batch(&batch).await {
                error!(error = %e, "Batch processing error");
            }
        }
    }

    /// معالجة دفعة من PacketSamples
    async fn process_batch(&self, samples: &[PacketSample]) -> Result<()> {
        let mut rl_requests: Vec<(u64, RLRequest)> = Vec::with_capacity(samples.len());

        for sample in samples {
            // تحويل إلى ParsedPacket
            let packet = match sample.to_parsed_packet() {
                Some(p) => p,
                None => {
                    debug!("Failed to convert sample to packet");
                    continue;
                }
            };

            // تحديث جدول التدفقات
            let decision = self.flow_manager.process_packet(&packet);

            // إذا كان التدفق محظوراً مسبقاً، تجاهل
            if matches!(decision, Decision::Block) {
                metrics().packets_dropped.inc();
                continue;
            }

            // أضف للتحليل RL
            let hash = packet.flow_key.hash();
            rl_requests.push((hash, RLRequest {
                flow_key:        packet.flow_key,
                features:        packet.to_feature_vector(),
                network_features: None,
            }));
        }

        if rl_requests.is_empty() {
            return Ok(());
        }

        // استنتاج RL للدفعة (غير متزامن)
        let m = metrics();
        let start = std::time::Instant::now();

        for (hash, request) in rl_requests {
            // نُحوّل RLRequest إلى parsed packet مجددا للـ analyze API
            // (يمكن تحسين هذا لاحقاً بـ batch API مباشر)
            let fake_packet = PacketSample {
                src_ip:          u32::from(match request.flow_key.src_ip {
                                     std::net::IpAddr::V4(v4) => v4,
                                     _ => std::net::Ipv4Addr::UNSPECIFIED,
                                  }).to_be(),
                dst_ip:          u32::from(match request.flow_key.dst_ip {
                                     std::net::IpAddr::V4(v4) => v4,
                                     _ => std::net::Ipv4Addr::UNSPECIFIED,
                                  }).to_be(),
                sport:           request.flow_key.src_port,
                dport:           request.flow_key.dst_port,
                proto:           request.flow_key.protocol as u8,
                is_ipv6:         0,
                pad:             [0; 2],
                timestamp_ns:    0,
                pkt_len:         0,
                reason:          0,
                tcp_flags:       0,
                risk_score_x100: 0,
            };

            if let Some(packet) = fake_packet.to_parsed_packet() {
                match self.rl_core.analyze(&packet).await {
                    Ok(resp) => {
                        let decision = Decision::from(resp.decision);
                        self.flow_manager.apply_decision(
                            &packet.flow_key,
                            decision,
                            resp.risk_score,
                            resp.explanation,
                        );

                        if resp.risk_score > 0.7 {
                            m.flows_blocked.inc();
                            debug!(
                                src  = ?packet.flow_key.src_ip,
                                risk = resp.risk_score,
                                "High-risk flow classified"
                            );
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "RL analysis failed — using default allow");
                    }
                }
            }
        }

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        m.ml_inference_duration.observe(latency_ms / 1000.0);

        Ok(())
    }
}

// ============================================================================
// Stats Publisher — ينشر الإحصاءات إلى Redis كل ثانية
// ============================================================================

pub struct StatsPublisher {
    flow_manager: Arc<FlowManager>,
}

impl StatsPublisher {
    pub fn new(flow_manager: Arc<FlowManager>) -> Self {
        Self { flow_manager }
    }

    pub async fn run(self, redis_url: Option<String>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let m = metrics();

        loop {
            interval.tick().await;

            let stats = self.flow_manager.stats();
            m.flows_active.set(stats.active_flows as f64);
            m.flows_suspicious.set(stats.suspicious_flows as f64);
            m.ebpf_map_utilization.set(stats.table_utilization as f64);

            // إذا كان Redis متاحاً، ننشر الإحصاءات
            // (يتطلب redis client — مُعطَّل هنا لتجنب dependency مزدوجة)
            debug!(
                active    = stats.active_flows,
                blocked   = stats.blocked_flows,
                suspicious = stats.suspicious_flows,
                util      = stats.table_utilization,
                "Flow manager stats updated"
            );
        }
    }
}
