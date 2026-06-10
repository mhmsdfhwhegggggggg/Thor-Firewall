//! Thor Firewall — RL Decision Core
//! محرك قرارات التعلم المعزز — Rust
//!
//! يرسل batch requests إلى ML inference server (Python FastAPI)
//! ويستقبل القرارات (BLOCK/ALLOW + risk score + threat type)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FlowAction {
    Allow    = 0,
    Block    = 1,
    Monitor  = 2,
    Throttle = 3,
    Redirect = 4,
}

impl std::fmt::Display for FlowAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow    => write!(f, "ALLOW"),
            Self::Block    => write!(f, "BLOCK"),
            Self::Monitor  => write!(f, "MONITOR"),
            Self::Throttle => write!(f, "THROTTLE"),
            Self::Redirect => write!(f, "REDIRECT"),
        }
    }
}

// ── ML Server Request/Response ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct BatchRequest {
    flows:    Vec<Vec<f32>>,
    flow_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FlowDecision {
    flow_id:     Option<String>,
    action:      u8,
    action_name: String,
    confidence:  f32,
    risk_score:  f32,
    blocked:     bool,
    threat_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    decisions:         Vec<FlowDecision>,
    batch_size:        usize,
    inference_time_ms: f64,
    model_version:     String,
}

// ── RL Core ──────────────────────────────────────────────────────────────────

pub struct ThorRLCore {
    ml_url:     String,
    api_url:    String,
    api_key:    String,
    batch_size: usize,
    http:       reqwest::Client,
    endpoint:   String,
}

impl ThorRLCore {
    /// ml_url     — ML inference server URL  (e.g. "http://thor-ml:8082")
    /// api_url    — Control plane URL         (e.g. "http://thor-control-plane:8000")
    /// api_key    — X-API-Key for auth
    /// batch_size — Maximum flows per ML call
    pub async fn new(
        ml_url:     &str,
        api_url:    &str,
        api_key:    &str,
        batch_size: usize,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .pool_max_idle_per_host(32)
            .tcp_nodelay(true)
            .build()
            .context("Failed to build HTTP client")?;

        let endpoint = format!("{}/v1/analyze/batch", ml_url.trim_end_matches('/'));

        let core = Self {
            ml_url:  ml_url.to_string(),
            api_url: api_url.to_string(),
            api_key: api_key.to_string(),
            batch_size,
            http,
            endpoint,
        };

        if let Err(e) = core.health_check().await {
            warn!(
                "ML inference not reachable at startup: {} — will retry on demand", e
            );
        }

        Ok(core)
    }

    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/health", self.ml_url.trim_end_matches('/'));
        let resp = self.http
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await
            .context("ML health check request failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("ML health check returned {}", resp.status());
        }
        Ok(())
    }

    /// تحليل batch من flows وإعادة قرارات الحظر/السماح
    pub async fn analyze_batch(
        &self,
        features: &[Vec<f32>],
        flow_ids: &[String],
    ) -> Result<Vec<(FlowAction, f32, Option<String>)>> {
        if features.is_empty() {
            return Ok(vec![]);
        }

        // إذا كان الـ batch أكبر من الحد، قسّمه
        if features.len() > self.batch_size {
            let mut results = Vec::with_capacity(features.len());
            for (chunk_f, chunk_id) in features
                .chunks(self.batch_size)
                .zip(flow_ids.chunks(self.batch_size))
            {
                let partial = self._send_batch(chunk_f, chunk_id).await?;
                results.extend(partial);
            }
            return Ok(results);
        }

        self._send_batch(features, flow_ids).await
    }

    async fn _send_batch(
        &self,
        features: &[Vec<f32>],
        flow_ids: &[String],
    ) -> Result<Vec<(FlowAction, f32, Option<String>)>> {
        let t0 = Instant::now();

        let body = BatchRequest {
            flows:    features.to_vec(),
            flow_ids: flow_ids.to_vec(),
        };

        let resp = self.http
            .post(&self.endpoint)
            .header("X-API-Key", &self.api_key)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {} failed", self.endpoint))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "ML inference returned {}: {}",
                status,
                &body_text[..body_text.len().min(200)]
            );
        }

        let batch: BatchResponse = resp.json().await
            .context("Failed to deserialize ML response")?;

        let elapsed = t0.elapsed();
        debug!(
            "ML batch: {} flows | inference={:.3}ms | total={:.3}ms | model={}",
            batch.batch_size,
            batch.inference_time_ms,
            elapsed.as_secs_f64() * 1000.0,
            batch.model_version,
        );

        metrics::histogram!(
            "thor_rl_decision_latency_ms",
            elapsed.as_secs_f64() * 1000.0
        );

        let results: Vec<(FlowAction, f32, Option<String>)> = batch
            .decisions
            .into_iter()
            .map(|d| {
                let action = match d.action {
                    _ if d.blocked => FlowAction::Block,
                    _ if d.risk_score > 0.85 => FlowAction::Block,
                    _ if d.risk_score > 0.60 => FlowAction::Monitor,
                    _ if d.risk_score > 0.40 => FlowAction::Throttle,
                    _ => FlowAction::Allow,
                };
                (action, d.risk_score, d.threat_type)
            })
            .collect();

        Ok(results)
    }

    pub async fn analyze_single(
        &self,
        features: Vec<f32>,
        flow_id: &str,
    ) -> Result<(FlowAction, f32, Option<String>)> {
        let results = self
            .analyze_batch(&[features], &[flow_id.to_string()])
            .await?;
        results
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Empty batch response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_action_display() {
        assert_eq!(FlowAction::Block.to_string(), "BLOCK");
        assert_eq!(FlowAction::Allow.to_string(), "ALLOW");
    }

    #[tokio::test]
    async fn test_empty_batch() {
        let core = ThorRLCore {
            ml_url:     "http://localhost:8082".into(),
            api_url:    "http://localhost:8000".into(),
            api_key:    "test_key".into(),
            batch_size: 64,
            http:       reqwest::Client::new(),
            endpoint:   "http://localhost:8082/v1/analyze/batch".into(),
        };
        let result = core.analyze_batch(&[], &[]).await.unwrap();
        assert!(result.is_empty());
    }
}
