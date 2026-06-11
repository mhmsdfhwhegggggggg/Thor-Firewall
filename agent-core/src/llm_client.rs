//! Thor Firewall — LLM Client
//! يتصل بـ Mistral-7B عبر vLLM (OpenAI-compatible API) أو llama.cpp
//! الاستخدام: let llm = LlmClient::new("http://vllm:8000/v1"); llm.explain_alert(&alert).await?

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio_stream::StreamExt;

#[derive(Serialize)]
struct ChatMessage {
    role:    String,
    content: String,
}

#[derive(Serialize)]
struct ChatRequest {
    model:       String,
    messages:    Vec<ChatMessage>,
    max_tokens:  u32,
    temperature: f32,
    stream:      bool,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: Option<ChatContent>,
    delta:   Option<ChatContent>,
}

#[derive(Deserialize)]
struct ChatContent {
    content: Option<String>,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Clone)]
pub struct AlertContext {
    pub threat_class:  String,
    pub threat_score:  f32,
    pub src_ip:        String,
    pub dst_ip:        String,
    pub action_taken:  String,
    pub rule_id:       Option<String>,
    pub packet_count:  u64,
    pub byte_count:    u64,
    pub duration_ms:   u64,
}

pub struct LlmClient {
    base_url:    String,
    model:       String,
    client:      reqwest::Client,
    max_tokens:  u32,
    temperature: f32,
    system_prompt: String,
}

impl LlmClient {
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build LLM HTTP client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            model: "mistralai/Mistral-7B-Instruct-v0.2".to_string(),
            client,
            max_tokens: 512,
            temperature: 0.2,
            system_prompt: concat!(
                "You are Thor Firewall's AI security analyst. ",
                "Analyze network threats concisely in 2-3 sentences. ",
                "Always end with: Recommended Action: <action>. ",
                "Use technical but clear language."
            ).to_string(),
        }
    }

    pub fn with_model(mut self, model: &str) -> Self {
        self.model = model.to_string();
        self
    }

    /// تفسير تنبيه أمني بلغة طبيعية
    pub async fn explain_alert(
        &self,
        ctx: &AlertContext,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let user_msg = format!(
            "Analyze this network threat:\n\
            - Type: {}\n\
            - Score: {:.1}/10\n\
            - Source: {} → Destination: {}\n\
            - Action: {}\n\
            - Packets: {}, Bytes: {}, Duration: {}ms\n\
            {}",
            ctx.threat_class,
            ctx.threat_score,
            ctx.src_ip,
            ctx.dst_ip,
            ctx.action_taken,
            ctx.packet_count,
            ctx.byte_count,
            ctx.duration_ms,
            ctx.rule_id.as_deref()
                .map(|r| format!("- Rule: {r}"))
                .unwrap_or_default(),
        );

        let req = ChatRequest {
            model:       self.model.clone(),
            messages: vec![
                ChatMessage { role: "system".to_string(), content: self.system_prompt.clone() },
                ChatMessage { role: "user".to_string(),   content: user_msg },
            ],
            max_tokens:  self.max_tokens,
            temperature: self.temperature,
            stream: false,
        };

        let url = format!("{}/chat/completions", self.base_url);
        let resp = self.client.post(&url)
            .json(&req)
            .send().await
            .map_err(|e| format!("LLM HTTP error: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("LLM error {status}: {body}").into());
        }

        let chat: ChatResponse = resp.json().await
            .map_err(|e| format!("LLM JSON parse error: {e}"))?;

        chat.choices.first()
            .and_then(|c| c.message.as_ref())
            .and_then(|m| m.content.clone())
            .ok_or_else(|| "Empty LLM response".into())
    }

    /// توليد SIGMA rule من وصف هجوم
    pub async fn generate_sigma_rule(
        &self,
        description: &str,
        mitre_technique: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let prompt = format!(
            "Generate a valid Sigma YAML rule for the following attack:\n\
            Description: {description}\n\
            MITRE Technique: {mitre_technique}\n\n\
            Return only valid YAML, no explanations."
        );

        let req = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: "You are a Sigma rule expert. Generate precise, valid Sigma YAML rules only.".to_string(),
                },
                ChatMessage { role: "user".to_string(), content: prompt },
            ],
            max_tokens: 1024,
            temperature: 0.1,
            stream: false,
        };

        let url = format!("{}/chat/completions", self.base_url);
        let resp = self.client.post(&url).json(&req).send().await?;
        let chat: ChatResponse = resp.json().await?;

        chat.choices.first()
            .and_then(|c| c.message.as_ref())
            .and_then(|m| m.content.clone())
            .ok_or_else(|| "Empty Sigma rule response".into())
    }

    /// اقتراح remediation خطوة بخطوة
    pub async fn suggest_remediation(
        &self,
        threat_class: &str,
        affected_host: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let prompt = format!(
            "List exactly 5 remediation steps for a {threat_class} attack on host {affected_host}.\n\
            Format: numbered list, one step per line, be specific and actionable."
        );

        let req = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage { role: "system".to_string(), content: self.system_prompt.clone() },
                ChatMessage { role: "user".to_string(), content: prompt },
            ],
            max_tokens: 512,
            temperature: 0.2,
            stream: false,
        };

        let url = format!("{}/chat/completions", self.base_url);
        let resp = self.client.post(&url).json(&req).send().await?;
        let chat: ChatResponse = resp.json().await?;

        let text = chat.choices.first()
            .and_then(|c| c.message.as_ref())
            .and_then(|m| m.content.clone())
            .unwrap_or_default();

        // استخراج الخطوات المرقّمة
        let steps: Vec<String> = text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .collect();

        Ok(steps)
    }

    /// التحقق من توفر الـ LLM server
    pub async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let url = format!("{}/models", self.base_url);
        let resp = self.client.get(&url)
            .timeout(Duration::from_secs(3))
            .send().await?;
        Ok(resp.status().is_success())
    }
}

// ── اختبارات ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alert_ctx() -> AlertContext {
        AlertContext {
            threat_class:  "syn_flood".to_string(),
            threat_score:  8.5,
            src_ip:        "1.2.3.4".to_string(),
            dst_ip:        "10.0.0.5".to_string(),
            action_taken:  "BLOCK".to_string(),
            rule_id:       Some("THOR-001".to_string()),
            packet_count:  50000,
            byte_count:    2_500_000,
            duration_ms:   5000,
        }
    }

    #[test]
    fn test_client_builds() {
        let _ = LlmClient::new("http://vllm:8000/v1");
    }

    #[test]
    fn test_client_with_model() {
        let c = LlmClient::new("http://vllm:8000/v1")
            .with_model("mistralai/Mixtral-8x7B-Instruct-v0.1");
        assert_eq!(c.model, "mistralai/Mixtral-8x7B-Instruct-v0.1");
    }

    #[tokio::test]
    async fn test_health_check_unavailable() {
        let c = LlmClient::new("http://localhost:19998/v1");
        let result = c.health_check().await;
        assert!(result.is_err());
    }

    #[test]
    fn test_alert_context_fields() {
        let ctx = make_alert_ctx();
        assert_eq!(ctx.threat_score, 8.5);
        assert_eq!(ctx.action_taken, "BLOCK");
    }
}
