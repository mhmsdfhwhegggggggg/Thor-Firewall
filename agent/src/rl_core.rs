// Thor Firewall — Reinforcement Learning Core
// نواة التعلم المعزز — مُحدَّثة بـ HTTP client حقيقي
//
// يستدعي ml-inference FastAPI server عبر HTTP بدلاً من stubs
// SPDX-License-Identifier: MIT

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
    pub flow_key_hash: u64,
    pub features: Vec<f32>,
    pub protocol: String,
    pub gnn_embedding: Option<Vec<f32>>,
}

/// استجابة محرك RL
#[derive(Debug, Clone, Deserialize)]
pub struct RLResponse {
    pub flow_key_hash: u64,
    pub decision: String,
    pub risk_score: f32,
    pub confidence: f32,
    pub explanation: Option<String>,
    pub agent_id: String,
    pub inference_time_us: Option<u64>,
}

/// استجابة batch
#[derive(Debug, Clone, Deserialize)]
struct BatchAnalysisResponse {
    pub responses: Vec<RLResponse>,
    pub total_time_us: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct BatchAnalysisRequest {
    pub requests: Vec<RLRequest>,
}

impl RLResponse {
    pub fn to_decision(&self) -> Decision {
        match self.decision.as_str() {
            "block"    => Decision::Block,
            "throttle" => Decision::Throttle { rate_pps: 100 },
            "mirror"   => Decision::Mirror,
            "redirect" => Decision::Redirect { port: 9999 },
            _          => Decision::Allow,
        }
    }
}

/// وضع تشغيل محرك RL
#[derive(Debug, Clone)]
pub enum RLMode {
    /// استدعاء عبر HTTP REST API (الوضع الافتراضي)
    RestApi { url: String },
    /// وضع المحاكاة — للاختبار فقط
    Simulation,
}

/// إعدادات محرك RL
#[derive(Debug, Clone)]
pub struct RLConfig {
    pub mode: RLMode,
    pub batch_size: usize,
    pub batch_timeout_us: u64,
    pub max_pending: usize,
    pub auto_block_threshold: f32,
    pub suspicious_threshold: f32,
    pub http_timeout_ms: u64,
}

impl Default for RLConfig {
    fn default() -> Self {
        Self {
            mode: RLMode::RestApi {
                url: std::env::var("ML_INFERENCE_URL")
                    .unwrap_or_else(|_| "http://ml-inference:8082".to_string()),
            },
            batch_size: 64,
            batch_timeout_us: 1000,
            max_pending: 10_000,
            auto_block_threshold: 0.85,
            suspicious_threshold: 0.5,
            http_timeout_ms: 50,
        }
    }
}

/// إحصاءات الأداء
#[derive(Debug, Default, Serialize)]
pub struct RLStats {
    pub total_analyzed: u64,
    pub total_blocked: u64,
    pub total_allowed: u64,
    pub avg_latency_us: f64,
    pub http_errors: u64,
    pub simulation_mode: bool,
}

/// نواة محرك التعلم المعزز
#[derive(Clone)]
pub struct RLCore {
    config: RLConfig,
    request_tx: mpsc::Sender<(RLRequest, mpsc::Sender<RLResponse>)>,
    stats: Arc<RwLock<RLStats>>,
    http_client: Option<reqwest::Client>,
}

impl RLCore {
    pub async fn new(config: RLConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(config.max_pending);
        let stats = Arc::new(RwLock::new(RLStats {
            simulation_mode: matches!(config.mode, RLMode::Simulation),
            ..Default::default()
        }));

        // بناء HTTP client واحد مشترك (connection pooling)
        let http_client = if let RLMode::RestApi { .. } = &config.mode {
            Some(
                reqwest::Client::builder()
                    .timeout(Duration::from_millis(config.http_timeout_ms))
                    .tcp_keepalive(Duration::from_secs(60))
                    .pool_max_idle_per_host(10)
                    .build()
                    .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?
            )
        } else {
            None
        };

        let core = Self {
            config: config.clone(),
            request_tx: tx,
            stats: stats.clone(),
            http_client: http_client.clone(),
        };

        // بدء معالج الدفعات
        let config_clone = config.clone();
        let stats_clone = stats.clone();
        tokio::spawn(async move {
            batch_worker(rx, config_clone, http_client, stats_clone).await;
        });

        match &config.mode {
            RLMode::RestApi { url } => info!("RLCore initialized → REST API at {}", url),
            RLMode::Simulation => warn!("RLCore initialized in SIMULATION mode — not for production!"),
        }

        Ok(core)
    }

    /// إرسال حزمة للتحليل (غير متزامن)
    pub async fn analyze(&self, packet: &ParsedPacket) -> Result<RLResponse> {
        let features: Vec<f32> = packet.to_feature_vector().to_vec();
        let protocol = match packet.flow_key.protocol {
            crate::packet_parser::Protocol::Tcp  => "tcp",
            crate::packet_parser::Protocol::Udp  => "udp",
            crate::packet_parser::Protocol::Icmp => "icmp",
            _                                     => "other",
        }.to_string();

        let request = RLRequest {
            flow_key_hash: packet.flow_key.hash(),
            features,
            protocol,
            gnn_embedding: None,
        };

        let (resp_tx, mut resp_rx) = mpsc::channel(1);
        self.request_tx.send((request, resp_tx)).await
            .map_err(|_| anyhow::anyhow!("RL worker channel closed"))?;

        tokio::time::timeout(
            Duration::from_millis(100),
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
            http_errors: s.http_errors,
            simulation_mode: s.simulation_mode,
        }
    }
}

/// معالج الدفعات — يجمع الطلبات ويرسلها دفعة واحدة
async fn batch_worker(
    mut rx: mpsc::Receiver<(RLRequest, mpsc::Sender<RLResponse>)>,
    config: RLConfig,
    http_client: Option<reqwest::Client>,
    stats: Arc<RwLock<RLStats>>,
) {
    let batch_timeout = Duration::from_micros(config.batch_timeout_us);

    loop {
        let mut batch: Vec<(RLRequest, mpsc::Sender<RLResponse>)> = Vec::with_capacity(config.batch_size);

        match rx.recv().await {
            Some(item) => batch.push(item),
            None => {
                info!("RL batch worker shutting down");
                break;
            }
        }

        let deadline = tokio::time::Instant::now() + batch_timeout;
        while batch.len() < config.batch_size {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(item)) => batch.push(item),
                _ => break,
            }
        }

        let start = std::time::Instant::now();
        let requests: Vec<RLRequest> = batch.iter().map(|(r, _)| r.clone()).collect();
        let responses = run_inference(&config, &http_client, &requests).await;
        let latency_us = start.elapsed().as_micros() as f64;

        // إرسال الردود
        for ((_, tx), response) in batch.into_iter().zip(responses.into_iter()) {
            let _ = tx.send(response).await;
        }

        // تحديث الإحصاءات
        let mut s = stats.write().await;
        s.total_analyzed += requests.len() as u64;
        s.avg_latency_us = (s.avg_latency_us * 0.99) + (latency_us * 0.01);
    }
}

/// تشغيل inference بحسب الوضع
async fn run_inference(
    config: &RLConfig,
    http_client: &Option<reqwest::Client>,
    requests: &[RLRequest],
) -> Vec<RLResponse> {
    match &config.mode {
        RLMode::RestApi { url } => {
            call_ml_inference_api(url, http_client.as_ref().unwrap(), requests).await
        }
        RLMode::Simulation => {
            simulate_responses(requests)
        }
    }
}

/// استدعاء ML Inference Server الحقيقي عبر HTTP
async fn call_ml_inference_api(
    base_url: &str,
    client: &reqwest::Client,
    requests: &[RLRequest],
) -> Vec<RLResponse> {
    let url = format!("{}/v1/analyze/batch", base_url.trim_end_matches('/'));
    let payload = serde_json::json!({ "requests": requests });

    match client.post(&url).json(&payload).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<BatchAnalysisResponse>().await {
                Ok(batch_resp) => {
                    debug!(
                        count = batch_resp.responses.len(),
                        total_us = batch_resp.total_time_us,
                        "ML batch inference complete"
                    );
                    return batch_resp.responses;
                }
                Err(e) => {
                    error!("Failed to parse ML response: {} — falling back to simulation", e);
                }
            }
        }
        Ok(resp) => {
            warn!("ML inference API returned HTTP {} — falling back to simulation", resp.status());
        }
        Err(e) => {
            warn!("ML inference API unreachable: {} — falling back to simulation", e);
        }
    }

    // Fallback to simulation on error
    simulate_responses(requests)
}

/// محاكاة بسيطة للاستخدام في الاختبار أو عند انقطاع الخادم
fn simulate_responses(requests: &[RLRequest]) -> Vec<RLResponse> {
    requests.iter().map(|req| {
        let features = &req.features;
        let risk = simulate_risk(features);
        let decision = if risk > 0.85 { "block" }
                      else if risk > 0.5 { "mirror" }
                      else { "allow" };

        RLResponse {
            flow_key_hash: req.flow_key_hash,
            decision: decision.to_string(),
            risk_score: risk,
            confidence: 0.65,
            explanation: if decision != "allow" {
                Some(format!("[SIM] Risk score: {:.2}", risk))
            } else { None },
            agent_id: format!("sim-{}-agent", req.protocol),
            inference_time_us: Some(10),
        }
    }).collect()
}

fn simulate_risk(features: &[f32]) -> f32 {
    let mut risk = 0.05f32;
    if features.len() > 21 && features[20] > 0.0 && features[21] == 0.0 {
        risk += 0.4; // SYN without ACK
    }
    if features.len() > 30 && features[30] > 7.5 {
        risk += 0.3; // High entropy payload
    }
    if features.len() > 2 && features[2] > 100_000.0 {
        risk += 0.3; // Very high packet count
    }
    risk.min(0.99)
}
