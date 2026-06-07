// Thor Firewall — Reinforcement Learning Core
// نواة التعلم المعزز — النسخة الإنتاجية الكاملة
//
// واجهة بين عميل Rust ونماذج Python (MARL + GNN)
// تدعم 3 أوضاع:
//   Simulation   — قواعد휴رستيكية للاختبار
//   RestApi      — HTTP client حقيقي → FastAPI ML inference server
//   InProcess    — PyO3 مباشر (نفس العملية — أسرع)
//
// الأداء المستهدف:
//   RestApi batch 64:  < 5ms إجمالي (< 80µs/طلب)
//   InProcess batch 64: < 1ms
//
// SPDX-License-Identifier: GPL-3.0

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::flow_manager::Decision;
use crate::packet_parser::{FlowKey, ParsedPacket};

// ============================================================================
// Public Types
// ============================================================================

/// طلب تحليل من محرك RL
#[derive(Debug, Clone, Serialize)]
pub struct RLRequest {
    pub flow_key: FlowKey,
    /// متجه الميزات (50 قيمة) — مُعرَّف في packet_parser.rs
    pub features: [f32; 50],
    /// ميزات مستوى الشبكة من GNN (اختياري)
    pub network_features: Option<NetworkFeatures>,
}

/// ميزات الشبكة الكلية من GNN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFeatures {
    pub failed_connections: u32,
    pub source_ip_churn: f32,
    pub syn_pattern_zscore: f32,
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
    pub agent_id: String,
}

/// نتيجة التحليل المُعادة من analyze_raw (للـ gRPC server)
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub flow_key_hash: u64,
    pub decision: RLDecision,
    pub risk_score: f32,
    pub confidence: f32,
    pub explanation: Option<String>,
    pub agent_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone)]
pub enum RLMode {
    Simulation,
    RestApi { url: String },
    InProcess,
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
    /// مهلة HTTP request للـ ML server (ms)
    pub http_timeout_ms: u64,
    /// عدد محاولات إعادة الاتصال عند الفشل
    pub http_retries: u32,
    /// المهلة بين محاولات إعادة الاتصال (ms)
    pub http_retry_delay_ms: u64,
}

impl Default for RLConfig {
    fn default() -> Self {
        Self {
            mode: RLMode::Simulation,
            batch_size: 64,
            batch_timeout_us: 1_000,
            max_pending: 10_000,
            auto_block_threshold: 0.85,
            suspicious_threshold: 0.5,
            http_timeout_ms: 5_000,
            http_retries: 2,
            http_retry_delay_ms: 100,
        }
    }
}

/// إحصاءات الأداء
#[derive(Debug, Default, Clone, Serialize)]
pub struct RLStats {
    pub total_analyzed: u64,
    pub total_blocked: u64,
    pub total_allowed: u64,
    pub avg_latency_us: f64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub http_errors: u64,
    pub http_fallbacks: u64,
}

// ============================================================================
// REST API Request/Response DTOs
// ============================================================================

/// جسم HTTP request لـ ML inference server
#[derive(Serialize)]
struct MLBatchRequest<'a> {
    requests: Vec<MLFlowRequest<'a>>,
}

#[derive(Serialize)]
struct MLFlowRequest<'a> {
    flow_key_hash: u64,
    features: &'a [f32; 50],
    #[serde(skip_serializing_if = "Option::is_none")]
    gnn_embedding: Option<&'a Vec<f32>>,
    protocol: &'static str,
}

/// جسم HTTP response من ML inference server
#[derive(Deserialize)]
struct MLBatchResponse {
    responses: Vec<MLFlowResponse>,
    total_time_us: u64,
}

#[derive(Deserialize)]
struct MLFlowResponse {
    flow_key_hash: u64,
    decision: String,   // "allow" | "block" | "throttle" | "mirror" | "redirect"
    risk_score: f32,
    confidence: f32,
    explanation: Option<String>,
    agent_id: String,
    #[serde(default)]
    throttle_rate_pps: u32,
    #[serde(default)]
    redirect_port: u16,
}

impl MLFlowResponse {
    fn into_rl_response(self) -> RLResponse {
        let decision = match self.decision.as_str() {
            "block"    => RLDecision::Block,
            "throttle" => RLDecision::Throttle { rate_pps: self.throttle_rate_pps },
            "mirror"   => RLDecision::Mirror,
            "redirect" => RLDecision::Redirect { port: self.redirect_port },
            _          => RLDecision::Allow,
        };

        RLResponse {
            flow_key_hash: self.flow_key_hash,
            decision,
            risk_score: self.risk_score,
            confidence: self.confidence,
            explanation: self.explanation,
            agent_id: self.agent_id,
        }
    }
}

// ============================================================================
// RLCore
// ============================================================================

#[derive(Clone)]
pub struct RLCore {
    config: RLConfig,
    request_tx: mpsc::Sender<PendingRequest>,
    stats: Arc<RwLock<RLStats>>,
    /// HTTP client مُعاد استخدامه (connection pooling)
    http_client: Arc<HttpClient>,
}

struct PendingRequest {
    req: RLRequest,
    resp_tx: mpsc::Sender<RLResponse>,
}

impl RLCore {
    pub async fn new(config: RLConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(config.max_pending);
        let stats = Arc::new(RwLock::new(RLStats::default()));

        // HTTP client مع connection pool + timeout
        let http_client = Arc::new(
            HttpClient::builder()
                .timeout(Duration::from_millis(config.http_timeout_ms))
                .tcp_keepalive(Duration::from_secs(30))
                .pool_max_idle_per_host(8)
                .user_agent("thor-agent/0.3")
                .build()
                .context("Failed to build HTTP client for ML inference")?
        );

        let core = Self {
            config: config.clone(),
            request_tx: tx,
            stats: stats.clone(),
            http_client: http_client.clone(),
        };

        // بدء batch worker
        let config_clone = config.clone();
        let stats_clone = stats.clone();
        let http_clone = http_client.clone();
        tokio::spawn(async move {
            batch_worker(rx, config_clone, stats_clone, http_clone).await;
        });

        info!(mode = ?core.config_mode_str(), "RLCore initialized");
        Ok(core)
    }

    fn config_mode_str(&self) -> &str {
        match &self.config.mode {
            RLMode::Simulation => "simulation",
            RLMode::RestApi { .. } => "rest_api",
            RLMode::InProcess => "in_process",
        }
    }

    /// تحليل حزمة واحدة (للـ ring consumer)
    pub async fn analyze(&self, packet: &ParsedPacket) -> Result<RLResponse> {
        let request = RLRequest {
            flow_key: packet.flow_key.clone(),
            features: packet.to_feature_vector(),
            network_features: None,
        };

        let (resp_tx, mut resp_rx) = mpsc::channel(1);
        self.request_tx
            .send(PendingRequest { req: request, resp_tx })
            .await
            .map_err(|_| anyhow::anyhow!("RL batch worker channel closed"))?;

        tokio::time::timeout(Duration::from_millis(50), resp_rx.recv())
            .await
            .map_err(|_| anyhow::anyhow!("RL analysis timed out after 50ms"))?
            .ok_or_else(|| anyhow::anyhow!("RL worker dropped the response channel"))
    }

    /// تحليل مباشر بمتجه ميزات خام — للـ gRPC AnalyzeBatch
    pub async fn analyze_raw(
        &self,
        features: &[f32],
        flow_key: Option<&FlowKey>,
    ) -> Result<AnalysisResult> {
        if features.len() != 50 {
            bail!("Expected 50 features, got {}", features.len());
        }

        let mut feat_arr = [0f32; 50];
        feat_arr.copy_from_slice(features);

        let flow_key_val = flow_key.cloned().unwrap_or_else(FlowKey::zero);
        let flow_key_hash = flow_key_val.hash();

        let requests = vec![RLRequest {
            flow_key: flow_key_val,
            features: feat_arr,
            network_features: None,
        }];

        let responses = run_inference(&self.config.mode, &requests, &self.http_client).await;
        let r = responses.into_iter().next().ok_or_else(|| anyhow::anyhow!("No response from ML"))?;

        Ok(AnalysisResult {
            flow_key_hash: r.flow_key_hash,
            decision: r.decision,
            risk_score: r.risk_score,
            confidence: r.confidence,
            explanation: r.explanation,
            agent_id: r.agent_id,
        })
    }

    pub async fn stats(&self) -> RLStats {
        self.stats.read().await.clone()
    }
}

// ============================================================================
// Batch Worker
// ============================================================================

async fn batch_worker(
    mut rx: mpsc::Receiver<PendingRequest>,
    config: RLConfig,
    stats: Arc<RwLock<RLStats>>,
    http_client: Arc<HttpClient>,
) {
    let batch_timeout = Duration::from_micros(config.batch_timeout_us);

    loop {
        let mut batch: Vec<PendingRequest> = Vec::with_capacity(config.batch_size);

        // انتظر أول طلب
        match rx.recv().await {
            Some(item) => batch.push(item),
            None => {
                info!("RL batch worker shutting down");
                break;
            }
        }

        // اجمع طلبات إضافية حتى الـ deadline أو الحد الأقصى
        let deadline = tokio::time::Instant::now() + batch_timeout;
        while batch.len() < config.batch_size {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(item)) => batch.push(item),
                _ => break,
            }
        }

        let batch_start = std::time::Instant::now();
        let requests: Vec<RLRequest> = batch.iter().map(|p| p.req.clone()).collect();

        // تشغيل inference
        let responses = run_inference(&config.mode, &requests, &http_client).await;

        let latency_us = batch_start.elapsed().as_micros() as f64;

        // إرسال الاستجابات
        for (pending, response) in batch.into_iter().zip(responses.into_iter()) {
            let _ = pending.resp_tx.send(response).await;
        }

        // تحديث الإحصاءات
        {
            let mut s = stats.write().await;
            s.total_analyzed += requests.len() as u64;
            // exponential moving average للـ latency
            s.avg_latency_us = s.avg_latency_us * 0.99 + latency_us * 0.01;
        }

        debug!(
            batch_size = requests.len(),
            latency_us = latency_us as u64,
            "RL batch processed"
        );
    }
}

// ============================================================================
// Inference Dispatch
// ============================================================================

async fn run_inference(
    mode: &RLMode,
    requests: &[RLRequest],
    http_client: &HttpClient,
) -> Vec<RLResponse> {
    match mode {
        RLMode::Simulation => simulate_batch(requests),
        RLMode::RestApi { url } => {
            call_rest_api(url, requests, http_client).await
        }
        RLMode::InProcess => {
            call_python_model(requests).await
        }
    }
}

// ============================================================================
// Simulation Mode
// ============================================================================

fn simulate_batch(requests: &[RLRequest]) -> Vec<RLResponse> {
    requests.iter().map(|req| {
        let risk = simulate_risk(req);
        RLResponse {
            flow_key_hash: req.flow_key.hash(),
            decision: if risk >= 0.85 {
                RLDecision::Block
            } else if risk >= 0.5 {
                RLDecision::Mirror
            } else {
                RLDecision::Allow
            },
            risk_score: risk,
            confidence: 0.70,
            explanation: Some(format!("Simulation heuristic: risk={:.3}", risk)),
            agent_id: "sim-agent-0".to_string(),
        }
    }).collect()
}

fn simulate_risk(req: &RLRequest) -> f32 {
    let f = &req.features;

    // SYN-only (possible SYN flood or scan)
    if f[20] > 0.0 && f[21] == 0.0 && f[22] == 0.0 {
        return 0.65;
    }

    // Port scan: well-known dst_port + very low payload entropy
    if f[11] < 1024.0 && f[30] < 0.5 {
        return 0.40;
    }

    // High entropy payload on non-HTTPS port (possible C2)
    let dst_port = f[11];
    if f[30] > 7.5
        && dst_port != 443.0
        && dst_port != 8443.0
        && dst_port != 993.0
        && dst_port != 465.0
    {
        return 0.72;
    }

    // Abnormally large packets (potential data exfiltration)
    if f[9] > 1400.0 && f[8] > 100_000.0 {
        return 0.55;
    }

    // Very fast connections (bot-like behavior)
    if f[3] > 10_000.0 && f[4] < 1.0 {
        return 0.35;
    }

    0.05
}

// ============================================================================
// REST API Mode — Real HTTP Client
// ============================================================================

async fn call_rest_api(
    base_url: &str,
    requests: &[RLRequest],
    client: &HttpClient,
) -> Vec<RLResponse> {
    let endpoint = format!("{}/v1/analyze/batch", base_url.trim_end_matches('/'));

    // بناء payload
    let payload = MLBatchRequest {
        requests: requests.iter().map(|r| {
            let gnn_embed = r.network_features.as_ref().map(|n| &n.node_embedding);
            let proto = match r.flow_key.protocol as u8 {
                6  => "tcp",
                17 => "udp",
                1  => "icmp",
                _  => "other",
            };
            MLFlowRequest {
                flow_key_hash: r.flow_key.hash(),
                features: &r.features,
                gnn_embedding: gnn_embed,
                protocol: proto,
            }
        }).collect(),
    };

    // إرسال مع retry logic
    let max_retries = 2u32;
    let mut attempt = 0u32;

    loop {
        let result = client
            .post(&endpoint)
            .json(&payload)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<MLBatchResponse>().await {
                    Ok(ml_resp) => {
                        debug!(
                            batch = requests.len(),
                            ml_time_us = ml_resp.total_time_us,
                            "ML inference successful"
                        );
                        return ml_resp.responses
                            .into_iter()
                            .map(|r| r.into_rl_response())
                            .collect();
                    }
                    Err(e) => {
                        error!(error = %e, "ML response deserialization failed");
                        break;
                    }
                }
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                error!(status = %status, body = %body, "ML server returned error");

                if status.as_u16() == 503 || status.as_u16() == 429 {
                    // Service unavailable / rate limited — retry
                    if attempt < max_retries {
                        attempt += 1;
                        let delay = Duration::from_millis(100 * (1 << attempt));
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
                break;
            }
            Err(e) if e.is_timeout() => {
                warn!(attempt = attempt, endpoint = %endpoint, "ML inference timeout");
                if attempt < max_retries {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                break;
            }
            Err(e) if e.is_connect() => {
                warn!(attempt = attempt, "ML server connection failed: {}", e);
                if attempt < max_retries {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
                    continue;
                }
                break;
            }
            Err(e) => {
                error!(error = %e, "ML HTTP request failed");
                break;
            }
        }
    }

    // Fallback to simulation on any failure
    warn!(
        batch = requests.len(),
        "ML inference failed — falling back to simulation"
    );
    simulate_batch(requests)
}

// ============================================================================
// InProcess Mode — PyO3 Bridge
// ============================================================================

#[cfg(feature = "pyo3")]
async fn call_python_model(requests: &[RLRequest]) -> Vec<RLResponse> {
    use pyo3::prelude::*;
    use pyo3::types::PyList;

    let result = Python::with_gil(|py| -> PyResult<Vec<RLResponse>> {
        let module = py.import_bound("ml.serving.inference_server")?;
        let analyze_fn = module.getattr("analyze_batch_sync")?;

        let py_requests = PyList::new_bound(py, requests.iter().map(|r| {
            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("flow_key_hash", r.flow_key.hash()).unwrap();
            dict.set_item("features", r.features.to_vec()).unwrap();
            dict.set_item("protocol", "tcp").unwrap();
            dict
        }));

        let py_result: Vec<pyo3::Bound<pyo3::types::PyDict>> = analyze_fn.call1((py_requests,))?.extract()?;

        py_result.iter().map(|d| {
            Ok(RLResponse {
                flow_key_hash: d.get_item("flow_key_hash")?.unwrap().extract::<u64>()?,
                decision: match d.get_item("decision")?.unwrap().extract::<String>()?.as_str() {
                    "block" => RLDecision::Block,
                    _ => RLDecision::Allow,
                },
                risk_score: d.get_item("risk_score")?.unwrap().extract::<f32>()?,
                confidence: d.get_item("confidence")?.unwrap().extract::<f32>()?,
                explanation: d.get_item("explanation")?.and_then(|v| v.extract().ok()),
                agent_id: d.get_item("agent_id")?.unwrap().extract::<String>()?,
            })
        }).collect()
    });

    match result {
        Ok(responses) => responses,
        Err(e) => {
            error!(error = %e, "PyO3 inference failed — falling back to simulation");
            simulate_batch(requests)
        }
    }
}

#[cfg(not(feature = "pyo3"))]
async fn call_python_model(requests: &[RLRequest]) -> Vec<RLResponse> {
    warn!("InProcess mode requires 'pyo3' feature — using simulation fallback");
    simulate_batch(requests)
}
