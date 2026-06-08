//! Thor Firewall — Ring Buffer Event Processor
//! معالج أحداث الشبكة القادمة من eBPF kernel program
//!
//! Pipeline:
//! kernel XDP → eBPF ring buffer → user space → feature extraction → ML inference → decision
//!
//! SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::FlowFeatures;
use crate::rl_core::{FlowAction, ThorRLCore};
use crate::soar::{SOAREngine, build_playbook};

// ── Flow Event (matching eBPF struct) ────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FlowEvent {
    pub src_ip:       u32,
    pub dst_ip:       u32,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub protocol:     u8,
    pub packet_size:  u16,
    pub flags:        u8,
    pub timestamp_ns: u64,
    pub action:       u8,
}

impl FlowEvent {
    pub fn src_addr(&self) -> Ipv4Addr { Ipv4Addr::from(self.src_ip) }
    pub fn dst_addr(&self) -> Ipv4Addr { Ipv4Addr::from(self.dst_ip) }

    pub fn is_tcp(&self) -> bool { self.protocol == 6 }
    pub fn is_udp(&self) -> bool { self.protocol == 17 }

    /// SYN packet (TCP SYN=1, ACK=0)
    pub fn is_syn(&self) -> bool { self.is_tcp() && (self.flags & 0x12) == 0x02 }
    /// RST packet
    pub fn is_rst(&self) -> bool { self.is_tcp() && (self.flags & 0x04) != 0 }
}

// ── Flow Accumulator ──────────────────────────────────────────────────────────
// يجمع events من نفس الـ (src_ip, dst_ip, src_port, dst_port) خلال window

#[derive(Debug)]
struct FlowAccumulator {
    events: Vec<FlowEvent>,
    first_seen: Instant,
    last_seen: Instant,
    total_bytes: u64,
}

impl FlowAccumulator {
    fn new(event: FlowEvent) -> Self {
        Self {
            events: vec![event],
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            total_bytes: event.packet_size as u64,
        }
    }

    fn add(&mut self, event: FlowEvent) {
        self.last_seen = Instant::now();
        self.total_bytes += event.packet_size as u64;
        if self.events.len() < 1000 { self.events.push(event); }
    }

    fn duration_ms(&self) -> f32 {
        self.first_seen.elapsed().as_millis() as f32
    }

    fn is_expired(&self, timeout_ms: u128) -> bool {
        self.last_seen.elapsed().as_millis() > timeout_ms
    }
}

// ── Feature Extraction ────────────────────────────────────────────────────────

fn extract_features(acc: &FlowAccumulator) -> FlowFeatures {
    let events = &acc.events;
    let n = events.len() as f32;
    let dur = acc.duration_ms().max(1.0);

    let sizes: Vec<f32> = events.iter().map(|e| e.packet_size as f32).collect();
    let mean_size = sizes.iter().sum::<f32>() / n;
    let std_size  = (sizes.iter().map(|s| (s - mean_size).powi(2)).sum::<f32>() / n).sqrt();

    let fwd: Vec<&FlowEvent> = events.iter().filter(|e| e.dst_port < 1024).collect();
    let bwd: Vec<&FlowEvent> = events.iter().filter(|e| e.src_port < 1024).collect();

    let fwd_sizes: Vec<f32> = fwd.iter().map(|e| e.packet_size as f32).collect();
    let bwd_sizes: Vec<f32> = bwd.iter().map(|e| e.packet_size as f32).collect();

    let mean_or_zero = |v: &[f32]| if v.is_empty() { 0.0 } else { v.iter().sum::<f32>() / v.len() as f32 };
    let max_or_zero  = |v: &[f32]| v.iter().cloned().fold(0.0_f32, f32::max);
    let min_or_zero  = |v: &[f32]| v.iter().cloned().fold(f32::MAX, f32::min);

    let syn_count  = events.iter().filter(|e| e.is_syn()).count() as f32;
    let rst_count  = events.iter().filter(|e| e.is_rst()).count() as f32;
    let fin_count  = events.iter().filter(|e| e.is_tcp() && (e.flags & 0x01) != 0).count() as f32;
    let psh_count  = events.iter().filter(|e| e.is_tcp() && (e.flags & 0x08) != 0).count() as f32;
    let ack_count  = events.iter().filter(|e| e.is_tcp() && (e.flags & 0x10) != 0).count() as f32;

    FlowFeatures {
        flow_duration:                dur,
        total_fwd_packets:            fwd.len() as f32,
        total_bwd_packets:            bwd.len() as f32,
        total_length_fwd_packets:     fwd_sizes.iter().sum(),
        total_length_bwd_packets:     bwd_sizes.iter().sum(),
        fwd_packet_length_max:        max_or_zero(&fwd_sizes),
        fwd_packet_length_min:        min_or_zero(&fwd_sizes),
        fwd_packet_length_mean:       mean_or_zero(&fwd_sizes),
        fwd_packet_length_std:        0.0,
        bwd_packet_length_max:        max_or_zero(&bwd_sizes),
        bwd_packet_length_min:        min_or_zero(&bwd_sizes),
        bwd_packet_length_mean:       mean_or_zero(&bwd_sizes),
        bwd_packet_length_std:        0.0,
        flow_bytes_per_s:             acc.total_bytes as f32 / (dur / 1000.0),
        flow_packets_per_s:           n / (dur / 1000.0),
        flow_iat_mean:                dur / n.max(1.0),
        flow_iat_std:                 0.0,
        flow_iat_max:                 dur,
        flow_iat_min:                 0.0,
        fwd_iat_total:                dur / 2.0,
        fwd_iat_mean:                 dur / fwd.len().max(1) as f32,
        fwd_iat_std:                  0.0,
        fwd_iat_max:                  dur,
        fwd_iat_min:                  0.0,
        bwd_iat_total:                dur / 2.0,
        bwd_iat_mean:                 dur / bwd.len().max(1) as f32,
        bwd_iat_std:                  0.0,
        bwd_iat_max:                  dur,
        bwd_iat_min:                  0.0,
        fwd_psh_flags:                psh_count,
        bwd_psh_flags:                0.0,
        fwd_urg_flags:                0.0,
        bwd_urg_flags:                0.0,
        fwd_header_length:            fwd.len() as f32 * 20.0,
        bwd_header_length:            bwd.len() as f32 * 20.0,
        fwd_packets_per_s:            fwd.len() as f32 / (dur / 1000.0),
        bwd_packets_per_s:            bwd.len() as f32 / (dur / 1000.0),
        min_packet_length:            min_or_zero(&sizes),
        max_packet_length:            max_or_zero(&sizes),
        packet_length_mean:           mean_size,
        packet_length_std:            std_size,
        packet_length_variance:       std_size * std_size,
        fin_flag_count:               fin_count,
        syn_flag_count:               syn_count,
        rst_flag_count:               rst_count,
        psh_flag_count:               psh_count,
        ack_flag_count:               ack_count,
        urg_flag_count:               0.0,
        cwe_flag_count:               0.0,
        ece_flag_count:               0.0,
    }
}

// ── Event Processor ───────────────────────────────────────────────────────────

pub struct EventProcessor {
    rl_core:  ThorRLCore,
    soar:     SOAREngine,
    flows:    HashMap<(u32, u32, u16, u16), FlowAccumulator>,
    flow_timeout_ms: u128,
    batch_size: usize,
}

impl EventProcessor {
    pub fn new(rl_core: ThorRLCore, soar: SOAREngine) -> Self {
        Self {
            rl_core,
            soar,
            flows: HashMap::with_capacity(10_000),
            flow_timeout_ms: 5_000,   // 5 ثواني timeout لكل flow
            batch_size: 64,
        }
    }

    /// معالجة event واحد من ring buffer
    pub async fn process_event(&mut self, event: FlowEvent) {
        let key = (event.src_ip, event.dst_ip, event.src_port, event.dst_port);
        self.flows.entry(key)
            .and_modify(|acc| acc.add(event))
            .or_insert_with(|| FlowAccumulator::new(event));
    }

    /// تقييم الـ flows المنتهية وإرسالها للـ ML inference
    pub async fn flush_expired_flows(&mut self) {
        let expired_keys: Vec<_> = self.flows.iter()
            .filter(|(_, acc)| acc.is_expired(self.flow_timeout_ms))
            .map(|(k, _)| *k)
            .collect();

        if expired_keys.is_empty() { return; }

        // Batch feature extraction
        let mut features_batch = Vec::with_capacity(expired_keys.len());
        let mut flow_ids       = Vec::with_capacity(expired_keys.len());
        let mut src_ips        = Vec::new();

        for key in &expired_keys {
            if let Some(acc) = self.flows.remove(key) {
                let feats = extract_features(&acc);
                let flow_id = format!("{}-{}-{}-{}", key.0, key.1, key.2, key.3);
                features_batch.push(feats.to_vec());
                flow_ids.push(flow_id);
                src_ips.push(Ipv4Addr::from(key.0));
            }
        }

        // ML batch inference
        match self.rl_core.analyze_batch(&features_batch, &flow_ids).await {
            Ok(decisions) => {
                for ((action, risk, threat_type), src_ip) in decisions.iter().zip(src_ips.iter()) {
                    metrics::counter!("thor_flows_processed_total").increment(1);

                    if *action == FlowAction::Block {
                        metrics::counter!("thor_threats_total",
                            "threat_type" => threat_type.clone().unwrap_or_default()
                        ).increment(1);

                        // تشغيل SOAR playbook
                        let playbook = build_playbook(
                            threat_type.as_deref().unwrap_or("unknown"),
                            if *risk > 0.9 { "critical" } else { "high" },
                            std::net::IpAddr::V4(*src_ip),
                            *risk,
                        );

                        if !playbook.is_empty() {
                            let results = self.soar.execute_playbook(playbook).await;
                            for r in &results {
                                debug!("SOAR {}: {} ({}ms)", r.action, r.message, r.execution_time_ms);
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("ML batch inference failed: {}", e),
        }
    }
}
