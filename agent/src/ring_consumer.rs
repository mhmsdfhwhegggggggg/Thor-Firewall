// Thor Firewall — eBPF Ring Buffer Consumer
// قارئ Ring Buffer البرمجي للحزم المُرسَلة من kernel

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use aya::maps::RingBuf;
use aya::Ebpf;
use bytes::BytesMut;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::packet_parser::{PacketParser, ParsedPacket, RawPacket};
use crate::flow_manager::{Decision, FlowManager};
use crate::rl_core::{RLCore, RLInput};
use crate::telemetry::metrics;

// ============================================================================
// Ring Buffer Events (يجب أن تتطابق مع thor_common.h)
// ============================================================================

/// هيكل الحدث المُرسَل من XDP
/// يتوافق مع struct packet_sample في thor_common.h
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PacketSample {
    pub timestamp_ns: u64,
    pub src_ip:       u32,
    pub dst_ip:       u32,
    pub sport:        u16,
    pub dport:        u16,
    pub proto:        u8,
    pub tcp_flags:    u8,
    pub pkt_len:      u16,
    pub payload_len:  u16,
    pub _pad:         [u8; 2],
    /// أول 64 بايت من الحمولة
    pub payload:      [u8; 64],
}

impl PacketSample {
    /// تحويل إلى RawPacket للتحليل
    pub fn to_raw_packet(&self) -> RawPacket {
        RawPacket {
            timestamp_ns: self.timestamp_ns,
            src_ip:       self.src_ip,
            dst_ip:       self.dst_ip,
            sport:        self.sport,
            dport:        self.dport,
            proto:        self.proto,
            tcp_flags:    self.tcp_flags,
            pkt_len:      self.pkt_len,
            payload:      self.payload[..self.payload_len.min(64) as usize].to_vec(),
        }
    }
}

// ============================================================================
// Ring Buffer Consumer
// ============================================================================

/// قارئ Ring Buffer — يستهلك الأحداث ويرسلها للتحليل
pub struct RingConsumer {
    parser:       Arc<PacketParser>,
    flow_manager: Arc<FlowManager>,
    rl_core:      Arc<RLCore>,
    sample_tx:    mpsc::Sender<PacketSample>,
}

impl RingConsumer {
    pub fn new(
        parser:       Arc<PacketParser>,
        flow_manager: Arc<FlowManager>,
        rl_core:      Arc<RLCore>,
        sample_tx:    mpsc::Sender<PacketSample>,
    ) -> Self {
        Self { parser, flow_manager, rl_core, sample_tx }
    }

    /// بدء استهلاك Ring Buffer من BPF map
    pub async fn run(self, ebpf: Arc<tokio::sync::Mutex<Ebpf>>) -> Result<()> {
        info!("Ring buffer consumer starting");

        let (ring_tx, mut ring_rx) = mpsc::channel::<PacketSample>(65536);

        // Thread منفصل لقراءة Ring Buffer (polling)
        let ebpf_clone = ebpf.clone();
        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async move {
                let mut ebpf = ebpf_clone.lock().await;
                let ring_buf = match ebpf.map_mut("packet_samples") {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to get ring buffer map: {}", e);
                        return;
                    }
                };

                let mut ring = RingBuf::try_from(ring_buf).expect("ring buf");

                loop {
                    // Poll للأحداث الجديدة
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<PacketSample>() {
                            warn!("Ring buf item too small: {}", item.len());
                            continue;
                        }

                        let sample: PacketSample = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const PacketSample)
                        };

                        if ring_tx.send(sample).await.is_err() {
                            return;
                        }
                    }

                    // Sleep قصير لتجنب busy-wait
                    tokio::time::sleep(Duration::from_micros(100)).await;
                }
            });
        });

        // معالجة الأحداث المستلمة
        let mut batch: Vec<PacketSample> = Vec::with_capacity(64);

        loop {
            // جمع دفعة
            let timeout = tokio::time::sleep(Duration::from_micros(500));
            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    biased;
                    Some(sample) = ring_rx.recv() => {
                        batch.push(sample);
                        if batch.len() >= 64 { break; }
                    }
                    _ = &mut timeout => { break; }
                }
            }

            if batch.is_empty() { continue; }

            // معالجة الدفعة
            self.process_batch(&batch).await;
            batch.clear();
        }
    }

    /// معالجة دفعة من الأحداث
    async fn process_batch(&self, samples: &[PacketSample]) {
        let m = metrics();
        m.packets_total.inc_by(samples.len() as f64);

        let mut rl_inputs: Vec<(u64, RLInput)> = Vec::with_capacity(samples.len());

        for sample in samples {
            let raw = sample.to_raw_packet();

            // تحليل الحزمة واستخراج الميزات
            let (features, meta) = match self.parser.parse(&raw) {
                Ok(p) => p,
                Err(e) => {
                    debug!("Parse error: {}", e);
                    continue;
                }
            };

            // تحديث جدول التدفقات
            let (flow_hash, _) = self.flow_manager.update(&meta, &features);

            // إضافة للاستنتاج المُجمَّع
            let protocol = match sample.proto {
                6  => "tcp",
                17 => "udp",
                1  => "icmp",
                _  => "tcp",
            };

            rl_inputs.push((flow_hash, RLInput {
                flow_hash,
                features: features.as_array(),
                gnn_embedding: [0.0f32; 32],
                protocol: protocol.to_string(),
            }));
        }

        if rl_inputs.is_empty() { return; }

        // استنتاج ML للدفعة
        let start = std::time::Instant::now();
        match self.rl_core.analyze_batch(rl_inputs).await {
            Ok(decisions) => {
                let latency_us = start.elapsed().as_micros() as f64;
                m.ml_inference_duration.observe(latency_us / 1_000_000.0);

                for (hash, decision, risk) in &decisions {
                    if *risk > 0.8 || *decision == Decision::Block {
                        m.flows_blocked.inc();
                        debug!(
                            hash = hash,
                            risk = risk,
                            decision = ?decision,
                            "High-risk flow decision"
                        );
                    }
                }
            }
            Err(e) => {
                error!("ML batch inference error: {}", e);
            }
        }
    }
}

// ============================================================================
// Conntrack Event Consumer
// ============================================================================

/// قارئ أحداث connection tracking
pub struct ConntrackConsumer;

impl ConntrackConsumer {
    pub async fn run(ebpf: Arc<tokio::sync::Mutex<Ebpf>>) -> Result<()> {
        info!("Conntrack consumer starting");
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            // TODO: قراءة من conntrack_events ring buffer
        }
    }
}
