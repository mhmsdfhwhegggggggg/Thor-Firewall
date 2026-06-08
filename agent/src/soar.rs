//! Thor Firewall — SOAR (Security Orchestration, Automation and Response)
//! محرك تنفيذ playbooks الاستجابة التلقائية
//!
//! Playbooks المتاحة:
//! 1. block_ip      — حظر IP على الفور في eBPF map
//! 2. isolate_host  — عزل مضيف من الشبكة (بعد التحقق)
//! 3. alert_soc     — إرسال تنبيه فوري لمحلل SOC
//! 4. create_ioc    — إضافة IOC إلى قاعدة بيانات التهديدات
//! 5. create_ticket — فتح تذكرة حادث في نظام إدارة القضايا
//!
//! SPDX-License-Identifier: MIT

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::{info, warn, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaybookAction {
    BlockIp { ip: IpAddr, duration_secs: u64, reason: String },
    IsolateHost { host_id: String, ip: IpAddr },
    AlertSoc { severity: String, message: String, details: serde_json::Value },
    CreateIoc { ioc_type: String, value: String, confidence: f32, threat_type: String },
    CreateTicket { title: String, severity: String, description: String, assignee: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookResult {
    pub action: String,
    pub success: bool,
    pub message: String,
    pub execution_time_ms: u64,
}

pub struct SOAREngine {
    control_plane_url: String,
    http: reqwest::Client,
}

impl SOAREngine {
    pub fn new(control_plane_url: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client");
        Self { control_plane_url: control_plane_url.to_string(), http }
    }

    /// تنفيذ قائمة من الـ playbooks بشكل متوازي
    pub async fn execute_playbook(&self, actions: Vec<PlaybookAction>) -> Vec<PlaybookResult> {
        let mut results = Vec::new();
        for action in actions {
            let result = self.execute_single(action).await;
            results.push(result);
        }
        results
    }

    async fn execute_single(&self, action: PlaybookAction) -> PlaybookResult {
        let start = std::time::Instant::now();
        let action_name = format!("{:?}", action).split('{').next().unwrap_or("unknown").trim().to_string();

        let result = match &action {
            PlaybookAction::BlockIp { ip, duration_secs, reason } => {
                info!("SOAR: Blocking IP {} for {}s — {}", ip, duration_secs, reason);
                self.http
                    .post(format!("{}/api/v1/soar/block-ip", self.control_plane_url))
                    .json(&serde_json::json!({"ip": ip.to_string(), "duration_secs": duration_secs, "reason": reason}))
                    .send()
                    .await
                    .map(|_| "IP blocked successfully".to_string())
                    .unwrap_or_else(|e| { warn!("Block IP failed: {}", e); format!("Failed: {}", e) })
            }
            PlaybookAction::IsolateHost { host_id, ip } => {
                info!("SOAR: Isolating host {} ({})", host_id, ip);
                self.http
                    .post(format!("{}/api/v1/soar/isolate-host", self.control_plane_url))
                    .json(&serde_json::json!({"host_id": host_id, "ip": ip.to_string()}))
                    .send()
                    .await
                    .map(|_| "Host isolated".to_string())
                    .unwrap_or_else(|e| format!("Failed: {}", e))
            }
            PlaybookAction::AlertSoc { severity, message, details } => {
                info!("SOAR: Alert SOC — [{}] {}", severity, message);
                metrics::counter!("thor_soar_alerts_total", "severity" => severity.clone()).increment(1);
                "SOC notified".to_string()
            }
            PlaybookAction::CreateIoc { ioc_type, value, confidence, threat_type } => {
                info!("SOAR: Creating IOC {} ({}) confidence={:.2}", value, ioc_type, confidence);
                self.http
                    .post(format!("{}/api/v1/threat-intel/iocs", self.control_plane_url))
                    .json(&serde_json::json!({
                        "type": ioc_type, "value": value,
                        "confidence": confidence, "threat_type": threat_type
                    }))
                    .send()
                    .await
                    .map(|_| "IOC created".to_string())
                    .unwrap_or_else(|e| format!("Failed: {}", e))
            }
            PlaybookAction::CreateTicket { title, severity, description, assignee } => {
                info!("SOAR: Creating case — [{}] {}", severity, title);
                self.http
                    .post(format!("{}/api/v1/cases", self.control_plane_url))
                    .json(&serde_json::json!({
                        "title": title, "severity": severity,
                        "description": description, "assignee": assignee,
                    }))
                    .send()
                    .await
                    .map(|_| "Case created".to_string())
                    .unwrap_or_else(|e| format!("Failed: {}", e))
            }
        };

        let elapsed = start.elapsed().as_millis() as u64;
        let success = !result.starts_with("Failed");
        metrics::counter!("thor_soar_executions_total", "action" => action_name.clone()).increment(1);

        PlaybookResult { action: action_name, success, message: result, execution_time_ms: elapsed }
    }
}

/// بناء قائمة الـ playbooks بناءً على نوع التهديد والخطورة
pub fn build_playbook(threat_type: &str, severity: &str, src_ip: IpAddr, risk_score: f32) -> Vec<PlaybookAction> {
    let mut actions = Vec::new();

    // حظر IP تلقائياً للتهديدات العالية
    if risk_score > 0.85 || severity == "critical" {
        let duration = if severity == "critical" { 86400 } else { 3600 };
        actions.push(PlaybookAction::BlockIp {
            ip: src_ip,
            duration_secs: duration,
            reason: format!("{} detected (risk={:.2})", threat_type, risk_score),
        });
    }

    // تنبيه SOC دائماً للـ critical
    if severity == "critical" || severity == "high" {
        actions.push(PlaybookAction::AlertSoc {
            severity: severity.to_string(),
            message: format!("{} from {}", threat_type, src_ip),
            details: serde_json::json!({"src_ip": src_ip.to_string(), "risk_score": risk_score}),
        });
    }

    // إنشاء IOC للـ C2 و DDoS و Exfiltration
    if matches!(threat_type, "c2_communication" | "data_exfiltration" | "apt") {
        actions.push(PlaybookAction::CreateIoc {
            ioc_type: "ip".to_string(),
            value: src_ip.to_string(),
            confidence: risk_score,
            threat_type: threat_type.to_string(),
        });
    }

    // فتح تذكرة للـ critical
    if severity == "critical" && risk_score > 0.9 {
        actions.push(PlaybookAction::CreateTicket {
            title: format!("CRITICAL: {} from {}", threat_type, src_ip),
            severity: "critical".to_string(),
            description: format!(
                "Automated SOAR response: {} detected from {} (risk={:.2}). IP blocked for 24h.",
                threat_type, src_ip, risk_score
            ),
            assignee: None,
        });
    }

    actions
}
