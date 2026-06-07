// Thor Firewall — Reinforcement Learning Core
// نواة التعلم المعزز
//
// واجهة بين عميل Rust ونماذج Python (MARL + GNN)
// تستخدم PyO3 للاستدعاء المباشر أو REST API كخيار احتياطي

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::flow_manager::Decision;
use crate::packet_parser::{FlowKey, ParsedPacket};

/// طلب تحليل من محرك RL
#[derive(Debug, Clone, Serialize)]
pub struct RLRequest {
    /// معرف التدفق
    pub flow_key: FlowKey,
    /// متجه الميزات (50 قيمة)
    pub features: [f32; 50],
    /// ميزات مستوى الشبكة من GNN
    pub network_features: Option<NetworkFeatures>,
}

/// ميزات الشبكة الكلية من GNN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFeatures {
    /// عدد الاتصالات الفاشلة من نفس IP في آخر 60 ثانية
    pub failed_connections: u32,
    /// معدل تغيير IPs المصدر في آخر 10 ثوانٍ
    pub source_ip_churn: f32,
    /// نمط SYN عبر الشبكة (z-score)
    pub syn_pattern_zscore: f32,
    /// تضمين العقدة في الرسم البياني من GNN
    pub node_embedding: Vec<f32>,
}

/// استجابة محرك RL
#[derive(Debug, Clone, Deserialize)]
pub struct RLResponse {
    pub flow_key_hash: u64,
    pub decision: RLDecision,
    pub risk_score: f32,
    pub confidence: f32,
    pub explanation: Option<String>,
    /// اسم الوكيل الذي اتخذ القرار
    pub agent_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RLDecision {
    Allow,
    Block,
    Throttle { rate_pps: u32 },
    Mirror,
    Redirect { port: u16 },
}

impl From<RLDecision> for Decision {
    fn from(d: RLDecision) -> Self {
        match d {
            RLDecision::Allow => Decision::Allow,
            RLDecision::Block => Decision::Block,
            RLDecision::Throttle { rate_pps } => Decision::Throttle { rate_pps },
            RLDecision::Mirror => Decision::Mirror,
            RLDecision::Redirect { port } => Decision::Redirect { port },
        }
    }
}

/// وضع تشغيل محرك RL
#[derive(Debug, Clone, Deserialize)]
pub enum RLMode {
    /// استدعاء مباشر عبر PyO3 (أسرع — نفس العملية)
    InProcess,
    /// استدعاء عبر HTTP REST API (أبطأ — لكن أكثر مرونة)
    RestApi { url: String },
    /// وضع التجربة — قرارات عشوائية للاختبار
    Simulation,
}

/// إعدادات محرك RL
#[derive(Debug, Clone, Deserialize)]
pub struct RLConfig {
    pub mode: RLMode,
    /// حجم دفعة الطلبات (batch) لتحسين الأداء
    pub batch_size: usize,
    /// مهلة الانتظار لتجميع الدفعة (µs)
    pub batch_timeout_us: u64,
    /// الحد الأقصى للطلبات المعلقة
    pub max_pending: usize,
    /// عتبة نقاط الخطر لتفعيل حظر تلقائي
    pub auto_block_threshold: f32,
    /// عتبة نقاط الخطر لتفعيل المراقبة المكثفة
    pub suspicious_threshold: f32,
}

impl Default for RLConfig {
    fn default() -> Self {
        Self {
            mode: RLMode::Simulation,
            batch_size: 64,
            batch_timeout_us: 1000,
            max_pending: 10_000,
            auto_block_threshold: 0.85,
            suspicious_threshold: 0.5,
        }
    }
}

/// نواة محرك التعلم المعزز
#[derive(Clone)]
pub struct RLCore {
    config: RLConfig,
    /// قناة إرسال طلبات للمعالجة الدفعية
    request_tx: mpsc::Sender<(RLRequest, mpsc::Sender<RLResponse>)>,
    /// إحصاءات الأداء
    stats: Arc<RwLock<RLStats>>,
}

#[derive(Debug, Default, Serialize)]
pub struct RLStats {
    pub total_analyzed: u64,
    pub total_blocked: u64,
    pub total_allowed: u64,
    pub avg_latency_us: f64,
    pub false_positives: u64,
    pub false_negatives: u64,
}

impl RLCore {
    pub async fn new(config: RLConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(config.max_pending);
        let stats = Arc::new(RwLock::new(RLStats::default()));

        let core = Self {
            config: config.clone(),
            request_tx: tx,
            stats: stats.clone(),
        };

        // Start batch processing worker
        let config_clone = config.clone();
        let stats_clone = stats.clone();
        tokio::spawn(async move {
            batch_worker(rx, config_clone, stats_clone).await;
        });

        info!(mode = ?config.mode, "RLCore initialized");
        Ok(core)
    }

    /// إرسال حزمة للتحليل (غير متزامن)
    /// تُستدعى هذه الدالة فقط لحزم العينات — ليس كل حزمة
    pub async fn analyze(&self, packet: &ParsedPacket) -> Result<RLResponse> {
        let request = RLRequest {
            flow_key: packet.flow_key,
            features: packet.to_feature_vector(),
            network_features: None, // TODO: fill from GNN
        };

        let (resp_tx, mut resp_rx) = mpsc::channel(1);
        self.request_tx.send((request, resp_tx)).await
            .map_err(|_| anyhow::anyhow!("RL worker channel closed"))?;

        tokio::time::timeout(
            Duration::from_millis(50),
            resp_rx.recv()
        ).await
            .map_err(|_| anyhow::anyhow!("RL analysis timed out"))?
            .ok_or_else(|| anyhow::anyhow!("RL worker dropped response"))
    }

    pub async fn stats(&self) -> RLStats {
        let s = self.stats.read().await;
        RLStats {
            total_analyzed: s.total_analyzed,
            total_blocked: s.total_blocked,
            total_allowed: s.total_allowed,
            avg_latency_us: s.avg_latency_us,
            false_positives: s.false_positives,
            false_negatives: s.false_negatives,
        }
    }
}

/// معالج الدفعات — يجمع الطلبات ويرسلها دفعة واحدة لـ ML
async fn batch_worker(
    mut rx: mpsc::Receiver<(RLRequest, mpsc::Sender<RLResponse>)>,
    config: RLConfig,
    stats: Arc<RwLock<RLStats>>,
) {
    let batch_timeout = Duration::from_micros(config.batch_timeout_us);

    loop {
        let mut batch: Vec<(RLRequest, mpsc::Sender<RLResponse>)> = Vec::with_capacity(config.batch_size);

        // Collect first item
        match rx.recv().await {
            Some(item) => batch.push(item),
            None => {
                info!("RL batch worker shutting down");
                break;
            }
        }

        // Collect more items with timeout
        let deadline = tokio::time::Instant::now() + batch_timeout;
        while batch.len() < config.batch_size {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(item)) => batch.push(item),
                _ => break,
            }
        }

        // Process batch
        let start = tokio::time::Instant::now();
        let responses = run_inference(&config.mode, &batch.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>()).await;

        let latency_us = start.elapsed().as_micros() as f64;

        // Send responses
        for ((req, tx), response) in batch.into_iter().zip(responses.into_iter()) {
            let _ = tx.send(response).await;
        }

        // Update stats
        let mut s = stats.write().await;
        s.total_analyzed += 1;
        s.avg_latency_us = (s.avg_latency_us * 0.99) + (latency_us * 0.01);
    }
}

/// تشغيل الاستنتاج (inference) بحسب الوضع
async fn run_inference(mode: &RLMode, requests: &[RLRequest]) -> Vec<RLResponse> {
    match mode {
        RLMode::Simulation => {
            // وضع المحاكاة — قرارات بناءً على قواعد بسيطة للاختبار
            requests.iter().map(|req| {
                let risk = simulate_risk(req);
                RLResponse {
                    flow_key_hash: req.flow_key.hash(),
                    decision: if risk > 0.8 { RLDecision::Block } else { RLDecision::Allow },
                    risk_score: risk,
                    confidence: 0.7,
                    explanation: Some(format!("Simulation mode: risk={:.2}", risk)),
                    agent_id: "sim-agent-0".to_string(),
                }
            }).collect()
        }
        RLMode::RestApi { url } => {
            call_rest_api(url, requests).await
        }
        RLMode::InProcess => {
            call_python_model(requests)
        }
    }
}

/// محاكاة بسيطة لنقاط الخطر (للاختبار)
fn simulate_risk(req: &RLRequest) -> f32 {
    let features = &req.features;

    // SYN flood heuristic
    if features[20] > 0.0 && features[21] == 0.0 {
        // SYN without ACK
        return 0.6;
    }

    // Port scan heuristic
    if features[11] < 1024.0 && features[30] < 1.0 {
        // Well-known port with low entropy payload
        return 0.3;
    }

    // High entropy = possibly encrypted C2 traffic
    if features[30] > 7.5 && features[12] == 0.0 {
        return 0.7;
    }

    0.1
}

/// استدعاء REST API لنموذج Python
async fn call_rest_api(url: &str, requests: &[RLRequest]) -> Vec<RLResponse> {
    // TODO: implement HTTP client call to FastAPI ML endpoint
    warn!("REST API inference not yet fully implemented, using simulation");
    requests.iter().map(|req| RLResponse {
        flow_key_hash: req.flow_key.hash(),
        decision: RLDecision::Allow,
        risk_score: 0.1,
        confidence: 0.5,
        explanation: None,
        agent_id: "rest-fallback".to_string(),
    }).collect()
}

/// استدعاء مباشر لنموذج Python عبر PyO3
fn call_python_model(requests: &[RLRequest]) -> Vec<RLResponse> {
    // TODO: implement PyO3 bridge to MARL model
    warn!("PyO3 inference not yet implemented, using simulation");
    requests.iter().map(|req| RLResponse {
        flow_key_hash: req.flow_key.hash(),
        decision: RLDecision::Allow,
        risk_score: 0.1,
        confidence: 0.5,
        explanation: None,
        agent_id: "pyo3-stub".to_string(),
    }).collect()
}
