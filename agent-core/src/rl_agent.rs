//! Thor Firewall — RL Agent
//! يتواصل مع inference_server.py عبر HTTP/gRPC ويُعيد قرارات BLOCK/ALLOW/THROTTLE
//! الاستخدام: let agent = RlAgent::new("http://ml-inference:8082"); agent.predict(&features).await?

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use std::sync::Arc;

// ── الهياكل الأساسية ──────────────────────────────────────────────────────────

/// مميزات التدفق الشبكي المُرسَلة إلى نموذج MARL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    pub src_ip:        u32,
    pub dst_ip:        u32,
    pub src_port:      u16,
    pub dst_port:      u16,
    pub protocol:      u8,
    pub packet_count:  u64,
    pub byte_count:    u64,
    pub duration_ms:   u64,
    pub pkt_rate:      f32,
    pub byte_rate:     f32,
    pub flags:         u8,   // TCP flags bitmask
    pub fwd_pkts:      u64,
    pub bwd_pkts:      u64,
    pub fwd_bytes:     u64,
    pub bwd_bytes:     u64,
    pub iat_mean:      f32,  // inter-arrival time mean
    pub iat_std:       f32,
    pub payload_entropy: f32,
    pub window_size:   u32,
    pub ttl:           u8,
}

/// قرار العميل لكل تدفق
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Allow,
    Block,
    Throttle { rate_kbps: u32 },
    Inspect,  // إرسال لفحص عميق
    RateLimit { max_conns: u16 },
}

/// الاستجابة الكاملة من نموذج MARL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDecision {
    pub action:         Action,
    pub confidence:     f32,   // 0.0–1.0
    pub threat_score:   f32,   // 0.0–10.0
    pub threat_class:   String,
    pub q_values:       Vec<f32>,
    pub reasoning:      Option<String>,
    pub inference_ms:   u64,
}

/// طلب HTTP لـ inference_server.py
#[derive(Serialize)]
struct InferenceRequest {
    features:  Vec<Vec<f32>>,
    model:     String,
    return_qvalues: bool,
}

/// استجابة HTTP من inference_server.py
#[derive(Deserialize)]
struct InferenceResponse {
    actions:      Vec<u8>,
    q_values:     Option<Vec<Vec<f32>>>,
    threat_scores: Vec<f32>,
    threat_classes: Vec<String>,
    confidence:   Vec<f32>,
    inference_ms: u64,
    model_version: String,
}

/// إحصائيات العميل لمراقبة الأداء
#[derive(Debug, Default)]
struct AgentStats {
    total_predictions: u64,
    block_count:       u64,
    allow_count:       u64,
    errors:            u64,
    avg_latency_ms:    f64,
}

// ── RlAgent ───────────────────────────────────────────────────────────────────

pub struct RlAgent {
    inference_url: String,
    client:        reqwest::Client,
    model_name:    String,
    stats:         Arc<RwLock<AgentStats>>,
    /// عتبة اتخاذ قرار الحجب — يمكن ضبطها ديناميكياً
    block_threshold: f32,
}

impl RlAgent {
    /// إنشاء عميل جديد
    pub fn new(inference_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .pool_max_idle_per_host(32)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            inference_url: inference_url.trim_end_matches('/').to_string(),
            client,
            model_name: "thor_marl".to_string(),
            stats: Arc::new(RwLock::new(AgentStats::default())),
            block_threshold: 0.7,
        }
    }

    /// تعيين عتبة الحجب (0.0–1.0)
    pub fn with_block_threshold(mut self, threshold: f32) -> Self {
        self.block_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// فحص صحة الـ inference server
    pub async fn health_check(&self) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/health", self.inference_url);
        let resp = self.client.get(&url).send().await?;
        let body: serde_json::Value = resp.json().await?;
        Ok(body.to_string())
    }

    /// تحويل FlowFeatures إلى مصفوفة أرقام عائمة يفهمها النموذج
    fn features_to_vec(f: &FlowFeatures) -> Vec<f32> {
        vec![
            f.src_ip as f32 / u32::MAX as f32,
            f.dst_ip as f32 / u32::MAX as f32,
            f.src_port as f32 / 65535.0,
            f.dst_port as f32 / 65535.0,
            f.protocol as f32 / 255.0,
            (f.packet_count as f32).ln_1p() / 20.0,
            (f.byte_count as f32).ln_1p() / 25.0,
            (f.duration_ms as f32).ln_1p() / 15.0,
            f.pkt_rate / 10000.0,
            f.byte_rate / 1_000_000.0,
            f.flags as f32 / 255.0,
            (f.fwd_pkts as f32).ln_1p() / 20.0,
            (f.bwd_pkts as f32).ln_1p() / 20.0,
            (f.fwd_bytes as f32).ln_1p() / 25.0,
            (f.bwd_bytes as f32).ln_1p() / 25.0,
            f.iat_mean / 1000.0,
            f.iat_std / 1000.0,
            f.payload_entropy / 8.0,
            f.window_size as f32 / 65535.0,
            f.ttl as f32 / 255.0,
        ]
    }

    /// تحويل رقم action (0-4) إلى Action enum
    fn decode_action(&self, action_id: u8, threat_score: f32, confidence: f32) -> Action {
        if confidence >= self.block_threshold && threat_score >= 7.0 {
            return Action::Block;
        }
        match action_id {
            0 => Action::Allow,
            1 => Action::Block,
            2 => Action::Throttle { rate_kbps: 512 },
            3 => Action::Inspect,
            4 => Action::RateLimit { max_conns: 10 },
            _ => Action::Inspect,
        }
    }

    /// التنبؤ لتدفق واحد
    pub async fn predict(
        &self,
        features: &FlowFeatures,
    ) -> Result<AgentDecision, Box<dyn std::error::Error>> {
        let results = self.batch_predict(&[features.clone()]).await?;
        results.into_iter().next()
            .ok_or_else(|| "Empty response from inference server".into())
    }

    /// التنبؤ لدفعة من التدفقات (batch) — أسرع بكثير من الاستدعاء الفردي
    pub async fn batch_predict(
        &self,
        flows: &[FlowFeatures],
    ) -> Result<Vec<AgentDecision>, Box<dyn std::error::Error>> {
        if flows.is_empty() {
            return Ok(vec![]);
        }

        let t0 = Instant::now();
        let feature_matrix: Vec<Vec<f32>> = flows
            .iter()
            .map(Self::features_to_vec)
            .collect();

        let req = InferenceRequest {
            features:    feature_matrix,
            model:       self.model_name.clone(),
            return_qvalues: true,
        };

        let url = format!("{}/predict", self.inference_url);
        let resp = self.client
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| format!("Inference HTTP error: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Inference server error {status}: {body}").into());
        }

        let inf: InferenceResponse = resp.json().await
            .map_err(|e| format!("Inference JSON parse error: {e}"))?;

        let elapsed = t0.elapsed().as_millis() as u64;

        let decisions: Vec<AgentDecision> = (0..flows.len())
            .map(|i| {
                let action_id = inf.actions.get(i).copied().unwrap_or(0);
                let threat_score = inf.threat_scores.get(i).copied().unwrap_or(0.0);
                let confidence = inf.confidence.get(i).copied().unwrap_or(0.0);
                let q_values = inf.q_values.as_ref()
                    .and_then(|qv| qv.get(i))
                    .cloned()
                    .unwrap_or_default();
                let threat_class = inf.threat_classes.get(i)
                    .cloned()
                    .unwrap_or_else(|| "benign".to_string());

                AgentDecision {
                    action:       self.decode_action(action_id, threat_score, confidence),
                    confidence,
                    threat_score,
                    threat_class,
                    q_values,
                    reasoning:    None,
                    inference_ms: inf.inference_ms,
                }
            })
            .collect();

        // تحديث الإحصائيات
        {
            let mut stats = self.stats.write().await;
            stats.total_predictions += flows.len() as u64;
            for d in &decisions {
                match d.action {
                    Action::Block => stats.block_count += 1,
                    Action::Allow => stats.allow_count += 1,
                    _ => {}
                }
            }
            let n = stats.total_predictions as f64;
            stats.avg_latency_ms = stats.avg_latency_ms * (n - 1.0) / n
                + elapsed as f64 / n;
        }

        Ok(decisions)
    }

    /// جلب إحصائيات العميل
    pub async fn stats(&self) -> (u64, u64, u64, f64) {
        let s = self.stats.read().await;
        (s.total_predictions, s.block_count, s.allow_count, s.avg_latency_ms)
    }
}

// ── اختبارات الوحدة ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_flow() -> FlowFeatures {
        FlowFeatures {
            src_ip: 0xC0A80101, dst_ip: 0xC0A80102,
            src_port: 12345, dst_port: 80,
            protocol: 6, packet_count: 100, byte_count: 50000,
            duration_ms: 1000, pkt_rate: 100.0, byte_rate: 50000.0,
            flags: 0x02, fwd_pkts: 60, bwd_pkts: 40,
            fwd_bytes: 30000, bwd_bytes: 20000,
            iat_mean: 10.0, iat_std: 2.0,
            payload_entropy: 5.5, window_size: 65535, ttl: 64,
        }
    }

    #[test]
    fn test_features_to_vec_length() {
        let flow = make_test_flow();
        let vec = RlAgent::features_to_vec(&flow);
        assert_eq!(vec.len(), 20, "Feature vector must have 20 dimensions");
    }

    #[test]
    fn test_features_normalized() {
        let flow = make_test_flow();
        let vec = RlAgent::features_to_vec(&flow);
        for (i, &v) in vec.iter().enumerate() {
            assert!(v >= 0.0, "Feature {i} is negative: {v}");
            assert!(v <= 100.0, "Feature {i} exceeds 100: {v}");
        }
    }

    #[test]
    fn test_decode_action_block_threshold() {
        let agent = RlAgent::new("http://localhost:8082")
            .with_block_threshold(0.7);
        // threat_score=8.5 + confidence=0.9 → يجب Block بغض النظر عن action_id
        let action = agent.decode_action(0, 8.5, 0.9);
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn test_decode_action_allow_low_threat() {
        let agent = RlAgent::new("http://localhost:8082");
        let action = agent.decode_action(0, 1.0, 0.3);
        assert_eq!(action, Action::Allow);
    }

    #[tokio::test]
    async fn test_health_check_connection_refused() {
        let agent = RlAgent::new("http://localhost:19999");
        let result = agent.health_check().await;
        assert!(result.is_err(), "Should fail when server is not running");
    }
}
