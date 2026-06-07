// Thor Firewall — Flow Manager
// مدير تدفقات الشبكة
//
// يتتبع حالة كل اتصال شبكي نشط مع ضغط فعال للذاكرة
// يدعم تحديث BPF maps مباشرة لتطبيق قرارات RL فورًا

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::time;
use tracing::{debug, info, warn};

use crate::packet_parser::{FlowKey, ParsedPacket, Protocol};

/// حالة التدفق الحالية
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    /// اتصال جديد — لم يُحلَّل بعد
    New,
    /// قيد التحليل من محرك RL
    Analyzing,
    /// مسموح به
    Allowed,
    /// محظور
    Blocked,
    /// مشبوه — مراقبة مكثفة
    Suspicious,
    /// انتهى — أُغلق الاتصال
    Terminated,
}

/// قرار المحرك الذكي
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Block,
    Throttle { rate_pps: u32 },
    Mirror,     // إرسال نسخة للتحليل العميق
    Redirect { port: u16 }, // إعادة توجيه لـ honeypot
}

/// إحصاءات تدفق الشبكة
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStats {
    /// إجمالي الحزم
    pub packets: u64,
    /// إجمالي البايتات
    pub bytes: u64,
    /// عدد إعادة الإرسال (TCP)
    pub retransmissions: u32,
    /// متوسط حجم الحزمة
    pub avg_packet_size: f32,
    /// تباين حجم الحزمة (للكشف عن الأنماط)
    pub packet_size_variance: f32,
    /// معدل الحزم (حزمة/ثانية)
    pub pps: f64,
    /// أول حزمة شُوهدت (نانوثانية)
    pub first_seen_ns: u64,
    /// آخر حزمة شُوهدت (نانوثانية)
    pub last_seen_ns: u64,
    /// وقت إنشاء الاتصال (ms) — للـ TCP
    pub connection_setup_ms: Option<f64>,
}

impl Default for FlowStats {
    fn default() -> Self {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Self {
            packets: 0,
            bytes: 0,
            retransmissions: 0,
            avg_packet_size: 0.0,
            packet_size_variance: 0.0,
            pps: 0.0,
            first_seen_ns: now_ns,
            last_seen_ns: now_ns,
            connection_setup_ms: None,
        }
    }
}

impl FlowStats {
    pub fn update(&mut self, packet: &ParsedPacket) {
        self.packets += 1;
        self.bytes += packet.packet_len as u64;
        self.last_seen_ns = packet.timestamp_ns;

        // Welford's online algorithm for mean and variance
        let n = self.packets as f32;
        let delta = packet.packet_len as f32 - self.avg_packet_size;
        self.avg_packet_size += delta / n;
        let delta2 = packet.packet_len as f32 - self.avg_packet_size;
        self.packet_size_variance += (delta * delta2 - self.packet_size_variance) / n;

        // Update PPS rate
        let duration_s = (self.last_seen_ns - self.first_seen_ns) as f64 / 1e9;
        if duration_s > 0.0 {
            self.pps = self.packets as f64 / duration_s;
        }
    }
}

/// سجل كامل لتدفق شبكي
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub state: FlowState,
    pub decision: Option<Decision>,
    pub stats: FlowStats,
    /// نقاط الخطر (0.0 = آمن، 1.0 = خطير جداً)
    pub risk_score: f32,
    /// شرح القرار من LLM
    pub explanation: Option<String>,
    /// علامات للتحليل
    pub tags: Vec<String>,
}

impl FlowRecord {
    pub fn new(key: FlowKey) -> Self {
        Self {
            key,
            state: FlowState::New,
            decision: None,
            stats: FlowStats::default(),
            risk_score: 0.0,
            explanation: None,
            tags: Vec::new(),
        }
    }
}

/// إعدادات مدير التدفقات
#[derive(Debug, Clone, Deserialize)]
pub struct FlowConfig {
    /// الحد الأقصى للتدفقات المتزامنة
    pub max_flows: usize,
    /// مهلة انتهاء التدفق الخامل (ثوانٍ)
    pub idle_timeout_secs: u64,
    /// مهلة التدفق الكلية (ثوانٍ)
    pub total_timeout_secs: u64,
    /// عدد حزم SYN التي تطلق تحليل RL
    pub syn_analysis_threshold: u32,
    /// Redis URL للمزامنة مع control plane
    pub redis_url: Option<String>,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            max_flows: 1_000_000,
            idle_timeout_secs: 60,
            total_timeout_secs: 3600,
            syn_analysis_threshold: 10,
            redis_url: None,
        }
    }
}

/// مدير التدفقات الرئيسي
#[derive(Clone)]
pub struct FlowManager {
    config: FlowConfig,
    /// جدول التجزئة الرئيسي (بدون قفل — DashMap)
    flows: Arc<DashMap<u64, FlowRecord>>,
    /// عدد التدفقات النشطة حالياً
    active_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl FlowManager {
    pub async fn new(config: FlowConfig) -> Result<Self> {
        let flows = Arc::new(DashMap::with_capacity(config.max_flows));
        let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let manager = Self { config, flows, active_count };

        // Start background cleanup task
        let manager_clone = manager.clone();
        tokio::spawn(async move {
            manager_clone.cleanup_loop().await;
        });

        info!("FlowManager initialized");
        Ok(manager)
    }

    /// معالجة حزمة جديدة — العملية الحرجة (يجب أن تكمل في < 1µs)
    #[inline]
    pub fn process_packet(&self, packet: &ParsedPacket) -> Decision {
        let hash = packet.flow_key.hash();

        // Fast path: تدفق معروف
        if let Some(mut record) = self.flows.get_mut(&hash) {
            record.stats.update(packet);
            record.last_seen_ns = packet.timestamp_ns;

            return match record.state {
                FlowState::Allowed => Decision::Allow,
                FlowState::Blocked => Decision::Block,
                FlowState::Suspicious => {
                    // Mirror every Nth packet for deeper analysis
                    if record.stats.packets % 10 == 0 {
                        Decision::Mirror
                    } else {
                        Decision::Allow
                    }
                }
                _ => Decision::Allow, // Default allow while analyzing
            };
        }

        // Slow path: تدفق جديد
        self.handle_new_flow(hash, packet)
    }

    fn handle_new_flow(&self, hash: u64, packet: &ParsedPacket) -> Decision {
        let count = self.active_count.load(std::sync::atomic::Ordering::Relaxed);
        if count >= self.config.max_flows {
            warn!("Flow table full ({} flows), dropping new flow", count);
            return Decision::Block;
        }

        let mut record = FlowRecord::new(packet.flow_key);
        record.stats.update(packet);

        // Quick heuristic: SYN flood detection
        if let Some(flags) = packet.tcp_flags {
            if flags.is_syn_only() {
                record.state = FlowState::Analyzing;
                record.tags.push("syn_new".to_string());
            }
        }

        self.flows.insert(hash, record);
        self.active_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        debug!(hash = hash, "New flow registered");
        Decision::Allow
    }

    /// تطبيق قرار محرك RL على تدفق
    pub fn apply_decision(&self, flow_key: &FlowKey, decision: Decision, risk_score: f32, explanation: Option<String>) {
        let hash = flow_key.hash();
        if let Some(mut record) = self.flows.get_mut(&hash) {
            record.decision = Some(decision);
            record.risk_score = risk_score;
            record.explanation = explanation;
            record.state = match decision {
                Decision::Allow => FlowState::Allowed,
                Decision::Block => FlowState::Blocked,
                Decision::Throttle { .. } | Decision::Mirror => FlowState::Suspicious,
                Decision::Redirect { .. } => FlowState::Suspicious,
            };
        }
    }

    /// إحصاءات عامة للنظام
    pub fn stats(&self) -> FlowManagerStats {
        let active = self.active_count.load(std::sync::atomic::Ordering::Relaxed);
        let blocked = self.flows.iter().filter(|r| r.state == FlowState::Blocked).count();
        let suspicious = self.flows.iter().filter(|r| r.state == FlowState::Suspicious).count();

        FlowManagerStats {
            active_flows: active,
            blocked_flows: blocked,
            suspicious_flows: suspicious,
            table_utilization: active as f32 / self.config.max_flows as f32,
        }
    }

    /// حلقة تنظيف التدفقات المنتهية
    async fn cleanup_loop(&self) {
        let idle_timeout = Duration::from_secs(self.config.idle_timeout_secs);
        let mut interval = time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);

            let timeout_ns = idle_timeout.as_nanos() as u64;
            let mut removed = 0usize;

            self.flows.retain(|_, record| {
                let age_ns = now_ns.saturating_sub(record.stats.last_seen_ns);
                if age_ns > timeout_ns {
                    removed += 1;
                    false
                } else {
                    true
                }
            });

            if removed > 0 {
                self.active_count.fetch_sub(removed, std::sync::atomic::Ordering::Relaxed);
                debug!(removed = removed, "Cleaned up expired flows");
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FlowManagerStats {
    pub active_flows: usize,
    pub blocked_flows: usize,
    pub suspicious_flows: usize,
    pub table_utilization: f32,
}

// Allow accessing last_seen_ns directly on record
impl FlowRecord {
    pub fn last_seen_ns(&self) -> u64 {
        self.stats.last_seen_ns
    }

    pub fn set_last_seen_ns(&mut self, ts: u64) {
        self.stats.last_seen_ns = ts;
    }
}
