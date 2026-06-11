//! Thor Firewall — TheHive5 Integration (Complete)
//!
//! يدمج TheHive REST API v1 بالكامل:
//!  • Cases     : إنشاء، تحديث، إغلاق قضايا الأمن
//!  • Alerts    : إنشاء تنبيهات آلية من Thor events
//!  • Observables: إضافة IPs، domains، hashes، emails لأي case/alert
//!  • Tasks     : إنشاء مهام تحقيق + متابعة تنفيذها
//!  • Comments  : إضافة تعليقات تحليلية على القضايا
//!  • MITRE ATT&CK: تصنيف الحوادث بتقنيات ATT&CK
//!
//! الاستخدام:
//!   let hive  = TheHiveClient::new("http://thehive:9000", "api-key");
//!   let alert = hive.create_alert_from_thor_event(&event).await?;
//!   let case  = hive.promote_alert_to_case(&alert.id).await?;
//!   hive.add_observable_ip(&case.id, "1.2.3.4", "C2 IP from RL block").await?;

use std::{collections::HashMap, sync::Arc, time::Duration};
use serde::{Deserialize, Serialize};
use reqwest::Client;

// ── هياكل TheHive API ─────────────────────────────────────────────────────────

/// خطورة الحادثة (TheHive severity scale)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Severity {
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

impl Severity {
    pub fn from_risk_score(score: f32) -> Self {
        match score as u8 {
            0..=3   => Self::Low,
            4..=6   => Self::Medium,
            7..=8   => Self::High,
            _       => Self::Critical,
        }
    }

    pub fn as_num(&self) -> u8 { *self as u8 }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low      => write!(f, "Low"),
            Severity::Medium   => write!(f, "Medium"),
            Severity::High     => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

/// حالة القضية
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum CaseStatus {
    New,
    InProgress,
    Indeterminate,
    FalsePositive,
    TruePositive,
    Duplicate,
    Other,
}

/// حالة التنبيه
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum AlertStatus {
    New,
    Updated,
    Ignored,
    Imported,
}

/// TLP (Traffic Light Protocol)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum Tlp {
    White  = 0,
    Green  = 1,
    Amber  = 2,
    Red    = 3,
}

/// PAP (Permissible Actions Protocol)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum Pap {
    White  = 0,
    Green  = 1,
    Amber  = 2,
    Red    = 3,
}

/// تنبيه TheHive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id:          String,
    pub title:       String,
    pub description: String,
    pub severity:    u8,
    #[serde(rename = "tlp")]
    pub tlp:         u8,
    #[serde(rename = "pap")]
    pub pap:         u8,
    #[serde(rename = "type")]
    pub alert_type:  String,
    pub source:      String,
    #[serde(rename = "sourceRef")]
    pub source_ref:  String,
    pub status:      AlertStatus,
    pub tags:        Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at:  Option<u64>,
    #[serde(rename = "caseId")]
    pub case_id:     Option<String>,
}

/// قضية (Case) TheHive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id:          String,
    #[serde(rename = "_id")]
    pub internal_id: Option<String>,
    pub title:       String,
    pub description: String,
    pub severity:    u8,
    pub status:      CaseStatus,
    pub tlp:         u8,
    pub pap:         u8,
    pub tags:        Vec<String>,
    pub flag:        bool,
    #[serde(rename = "startDate")]
    pub start_date:  Option<u64>,
    #[serde(rename = "endDate")]
    pub end_date:    Option<u64>,
    #[serde(rename = "caseId")]
    pub case_number: Option<u32>,
    pub assignee:    Option<String>,
}

/// كائن قابل للملاحظة (Observable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observable {
    pub id:            String,
    #[serde(rename = "dataType")]
    pub data_type:     String,   // ip / domain / hash / url / mail / ...
    pub data:          String,
    pub message:       Option<String>,
    pub tlp:           u8,
    pub tags:          Vec<String>,
    pub ioc:           bool,     // هل هو مؤشر اختراق مؤكد؟
    pub sighted:       bool,
    #[serde(rename = "createdAt")]
    pub created_at:    Option<u64>,
}

/// مهمة تحقيق داخل قضية
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseTask {
    pub id:          String,
    pub title:       String,
    pub description: Option<String>,
    pub status:      String,   // Waiting / InProgress / Completed / Cancel
    pub flag:        bool,
    pub order:       u32,
    pub assignee:    Option<String>,
    #[serde(rename = "startDate")]
    pub start_date:  Option<u64>,
    #[serde(rename = "endDate")]
    pub end_date:    Option<u64>,
}

/// Thor Event مبسط (مُدخل من RL Agent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThorThreatEvent {
    pub event_id:    String,
    pub src_ip:      String,
    pub dst_ip:      String,
    pub src_port:    u16,
    pub dst_port:    u16,
    pub protocol:    String,
    pub threat_class: String,
    pub threat_score: f32,
    pub action:      String,   // BLOCK / ALLOW / QUARANTINE
    pub timestamp:   u64,
    pub description: String,
    pub tags:        Vec<String>,
    pub mitre_ttps:  Vec<String>,  // مثل: ["T1059", "T1566"]
}

// ── طلبات API ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CreateAlertRequest {
    title:        String,
    description:  String,
    severity:     u8,
    #[serde(rename = "type")]
    alert_type:   String,
    source:       String,
    #[serde(rename = "sourceRef")]
    source_ref:   String,
    tlp:          u8,
    pap:          u8,
    tags:         Vec<String>,
    observables:  Vec<ObservableRequest>,
    #[serde(rename = "externalLink")]
    external_link: Option<String>,
}

#[derive(Serialize)]
struct CreateCaseRequest {
    title:       String,
    description: String,
    severity:    u8,
    tlp:         u8,
    pap:         u8,
    tags:        Vec<String>,
    flag:        bool,
    tasks:       Vec<TaskRequest>,
}

#[derive(Serialize, Clone)]
struct TaskRequest {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assignee: Option<String>,
}

#[derive(Serialize, Clone)]
struct ObservableRequest {
    #[serde(rename = "dataType")]
    data_type: String,
    data:      String,
    message:   Option<String>,
    tlp:       u8,
    tags:      Vec<String>,
    ioc:       bool,
    sighted:   bool,
}

#[derive(Serialize)]
struct CommentRequest {
    message: String,
}

// ── TheHiveClient ─────────────────────────────────────────────────────────────

pub struct TheHiveClient {
    base_url: String,
    api_key:  String,
    http:     Client,
}

impl TheHiveClient {
    /// إنشاء client جديد (يدعم TheHive 5.x و 4.x)
    pub fn new(base_url: &str, api_key: &str) -> Arc<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build TheHive HTTP client");
        Arc::new(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key:  api_key.to_string(),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn auth_header(&self) -> (&'static str, String) {
        ("Authorization", format!("Bearer {}", self.api_key))
    }

    // ── صحة الخدمة ───────────────────────────────────────────────────────────

    pub async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let (k, v) = self.auth_header();
        let resp = self.http.get(&self.url("status"))
            .header(k, v)
            .timeout(Duration::from_secs(5))
            .send().await?;
        Ok(resp.status().is_success())
    }

    // ── Alerts ───────────────────────────────────────────────────────────────

    /// إنشاء تنبيه يدوي كامل الخيارات
    pub async fn create_alert(
        &self,
        title:       &str,
        description: &str,
        severity:    Severity,
        alert_type:  &str,
        source:      &str,
        source_ref:  &str,
        tlp:         Tlp,
        tags:        Vec<String>,
    ) -> Result<Alert, Box<dyn std::error::Error + Send + Sync>> {
        let req = CreateAlertRequest {
            title:        title.to_string(),
            description:  description.to_string(),
            severity:     severity.as_num(),
            alert_type:   alert_type.to_string(),
            source:       source.to_string(),
            source_ref:   source_ref.to_string(),
            tlp:          tlp as u8,
            pap:          Pap::Amber as u8,
            tags,
            observables:  vec![],
            external_link: None,
        };

        let (k, v) = self.auth_header();
        let resp = self.http.post(&self.url("alert"))
            .header(k, v)
            .json(&req)
            .send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("TheHive create_alert HTTP {status}: {body}").into());
        }

        let alert: Alert = resp.json().await
            .map_err(|e| format!("TheHive alert JSON: {e}"))?;

        log::info!("TheHive: alert created id={} title='{}'", alert.id, alert.title);
        Ok(alert)
    }

    /// إنشاء تنبيه تلقائي من Thor ThreatEvent (High-Level API)
    pub async fn create_alert_from_thor_event(
        &self,
        event: &ThorThreatEvent,
    ) -> Result<Alert, Box<dyn std::error::Error + Send + Sync>> {
        let severity = Severity::from_risk_score(event.threat_score);
        let tlp = match severity {
            Severity::Critical => Tlp::Red,
            Severity::High     => Tlp::Amber,
            _                  => Tlp::Green,
        };

        let description = format!(
            "## Thor Firewall Automated Alert\n\n\
            **Threat Class**: `{}`\n\
            **Action Taken**: `{}`\n\
            **Risk Score**: `{:.1}/10.0`\n\n\
            ### Network Details\n\
            | Field | Value |\n\
            |-------|-------|\n\
            | Source IP | `{}` |\n\
            | Dest IP   | `{}` |\n\
            | Protocol  | `{}` |\n\
            | Src Port  | `{}` |\n\
            | Dst Port  | `{}` |\n\n\
            ### Description\n{}\n\n\
            ### MITRE ATT&CK TTPs\n{}\n",
            event.threat_class, event.action, event.threat_score,
            event.src_ip, event.dst_ip, event.protocol,
            event.src_port, event.dst_port,
            event.description,
            if event.mitre_ttps.is_empty() {
                "_None detected_".to_string()
            } else {
                event.mitre_ttps.iter().map(|t| format!("- `{t}`")).collect::<Vec<_>>().join("\n")
            }
        );

        let mut tags = event.tags.clone();
        tags.push(format!("action:{}", event.action.to_lowercase()));
        tags.push(format!("threat:{}", event.threat_class.to_lowercase().replace(' ', "-")));
        tags.push("source:thor-firewall".to_string());
        for ttp in &event.mitre_ttps {
            tags.push(format!("mitre:{ttp}"));
        }

        let req = CreateAlertRequest {
            title: format!("[Thor] {} — {} (score {:.1})",
                event.action, event.threat_class, event.threat_score),
            description,
            severity:     severity.as_num(),
            alert_type:   "thor-network-event".to_string(),
            source:       "Thor Firewall".to_string(),
            source_ref:   event.event_id.clone(),
            tlp:          tlp as u8,
            pap:          Pap::Amber as u8,
            tags,
            observables:  vec![ObservableRequest {
                data_type: "ip".to_string(),
                data:      event.src_ip.clone(),
                message:   Some(format!("Source IP — threat class: {}", event.threat_class)),
                tlp:       tlp as u8,
                tags:      vec!["src_ip".to_string()],
                ioc:       severity >= Severity::High,
                sighted:   true,
            }],
            external_link: None,
        };

        let (k, v) = self.auth_header();
        let resp = self.http.post(&self.url("alert"))
            .header(k, v).json(&req).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("TheHive create_alert HTTP {status}: {body}").into());
        }

        let alert: Alert = resp.json().await?;
        log::info!("TheHive: auto-alert created for event {} ({})", event.event_id, event.src_ip);
        Ok(alert)
    }

    /// ترقية تنبيه إلى قضية
    pub async fn promote_alert_to_case(
        &self,
        alert_id: &str,
    ) -> Result<Case, Box<dyn std::error::Error + Send + Sync>> {
        let (k, v) = self.auth_header();
        let resp = self.http.post(&self.url(&format!("alert/{alert_id}/case")))
            .header(k, v).send().await?;

        if !resp.status().is_success() {
            return Err(format!("TheHive promote_alert HTTP {}", resp.status()).into());
        }

        let case: Case = resp.json().await?;
        log::info!("TheHive: alert {alert_id} promoted to case {}", case.id);
        Ok(case)
    }

    /// جلب تنبيه بمعرّفه
    pub async fn get_alert(&self, alert_id: &str) -> Result<Alert, Box<dyn std::error::Error + Send + Sync>> {
        let (k, v) = self.auth_header();
        let resp = self.http.get(&self.url(&format!("alert/{alert_id}")))
            .header(k, v).send().await?;
        resp.json().await.map_err(|e| format!("TheHive get_alert JSON: {e}").into())
    }

    // ── Cases ────────────────────────────────────────────────────────────────

    /// إنشاء قضية جديدة مع مهام تحقيق افتراضية
    pub async fn create_case(
        &self,
        title:       &str,
        description: &str,
        severity:    Severity,
        tlp:         Tlp,
        tags:        Vec<String>,
    ) -> Result<Case, Box<dyn std::error::Error + Send + Sync>> {
        let default_tasks = vec![
            TaskRequest {
                title: "1. Scope & Containment".to_string(),
                description: Some("Identify affected systems and contain the threat".to_string()),
                assignee: None,
            },
            TaskRequest {
                title: "2. Forensic Analysis".to_string(),
                description: Some("Collect and analyze evidence from affected systems".to_string()),
                assignee: None,
            },
            TaskRequest {
                title: "3. Threat Intelligence".to_string(),
                description: Some("Enrich IoCs via Cortex analyzers and external feeds".to_string()),
                assignee: None,
            },
            TaskRequest {
                title: "4. Eradication & Recovery".to_string(),
                description: Some("Remove threat and restore normal operations".to_string()),
                assignee: None,
            },
            TaskRequest {
                title: "5. Lessons Learned".to_string(),
                description: Some("Document findings and update detection rules".to_string()),
                assignee: None,
            },
        ];

        let req = CreateCaseRequest {
            title:       title.to_string(),
            description: description.to_string(),
            severity:    severity.as_num(),
            tlp:         tlp as u8,
            pap:         Pap::Amber as u8,
            tags,
            flag:        severity >= Severity::High,
            tasks:       default_tasks,
        };

        let (k, v) = self.auth_header();
        let resp = self.http.post(&self.url("case"))
            .header(k, v).json(&req).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("TheHive create_case HTTP {status}: {body}").into());
        }

        let case: Case = resp.json().await?;
        log::info!("TheHive: case created #{:?} — '{}'", case.case_number, case.title);
        Ok(case)
    }

    /// جلب قضية بمعرّفها
    pub async fn get_case(&self, case_id: &str) -> Result<Case, Box<dyn std::error::Error + Send + Sync>> {
        let (k, v) = self.auth_header();
        let resp = self.http.get(&self.url(&format!("case/{case_id}")))
            .header(k, v).send().await?;
        resp.json().await.map_err(|e| format!("TheHive get_case JSON: {e}").into())
    }

    /// إغلاق قضية مع حكم نهائي
    pub async fn close_case(
        &self,
        case_id: &str,
        status:  CaseStatus,
        summary: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let body = serde_json::json!({
            "status": status,
            "summary": summary
        });
        let (k, v) = self.auth_header();
        let resp = self.http.patch(&self.url(&format!("case/{case_id}")))
            .header(k, v).json(&body).send().await?;
        if resp.status().is_success() {
            log::info!("TheHive: case {case_id} closed ({:?})", status);
            Ok(())
        } else {
            Err(format!("TheHive close_case HTTP {}", resp.status()).into())
        }
    }

    // ── Observables ──────────────────────────────────────────────────────────

    /// إضافة observable لقضية (generic)
    pub async fn add_observable(
        &self,
        case_id:   &str,
        data_type: &str,
        data:      &str,
        message:   &str,
        is_ioc:    bool,
        tags:      Vec<String>,
    ) -> Result<Observable, Box<dyn std::error::Error + Send + Sync>> {
        let req = ObservableRequest {
            data_type: data_type.to_string(),
            data:      data.to_string(),
            message:   Some(message.to_string()),
            tlp:       Tlp::Amber as u8,
            tags,
            ioc:       is_ioc,
            sighted:   true,
        };

        let (k, v) = self.auth_header();
        let resp = self.http.post(&self.url(&format!("case/{case_id}/observable")))
            .header(k, v).json(&req).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("TheHive add_observable HTTP {status}: {body}").into());
        }

        resp.json().await.map_err(|e| format!("TheHive observable JSON: {e}").into())
    }

    /// اختصارات لأنواع Observables الشائعة
    pub async fn add_observable_ip(
        &self, case_id: &str, ip: &str, message: &str,
    ) -> Result<Observable, Box<dyn std::error::Error + Send + Sync>> {
        self.add_observable(case_id, "ip", ip, message, true, vec!["network".to_string()]).await
    }

    pub async fn add_observable_domain(
        &self, case_id: &str, domain: &str, message: &str,
    ) -> Result<Observable, Box<dyn std::error::Error + Send + Sync>> {
        self.add_observable(case_id, "domain", domain, message, true, vec!["network".to_string()]).await
    }

    pub async fn add_observable_hash(
        &self, case_id: &str, hash: &str, message: &str,
    ) -> Result<Observable, Box<dyn std::error::Error + Send + Sync>> {
        self.add_observable(case_id, "hash", hash, message, true, vec!["malware".to_string()]).await
    }

    pub async fn add_observable_url(
        &self, case_id: &str, url: &str, message: &str,
    ) -> Result<Observable, Box<dyn std::error::Error + Send + Sync>> {
        self.add_observable(case_id, "url", url, message, true, vec!["network".to_string()]).await
    }

    pub async fn add_observable_email(
        &self, case_id: &str, email: &str, message: &str,
    ) -> Result<Observable, Box<dyn std::error::Error + Send + Sync>> {
        self.add_observable(case_id, "mail", email, message, false, vec!["phishing".to_string()]).await
    }

    /// إضافة مجموعة IoCs دفعة واحدة (من CAPEv2 أو Cortex)
    pub async fn bulk_add_observables(
        &self,
        case_id:  &str,
        iocs:     &[(String, String, String)], // (type, value, message)
    ) -> Vec<Result<Observable, Box<dyn std::error::Error + Send + Sync>>> {
        let mut results = Vec::new();
        for (data_type, data, message) in iocs {
            let r = self.add_observable(case_id, data_type, data, message, true, vec![]).await;
            results.push(r);
        }
        results
    }

    // ── Tasks ────────────────────────────────────────────────────────────────

    /// جلب مهام قضية
    pub async fn list_tasks(&self, case_id: &str) -> Result<Vec<CaseTask>, Box<dyn std::error::Error + Send + Sync>> {
        let (k, v) = self.auth_header();
        let resp = self.http.get(&self.url(&format!("case/{case_id}/task")))
            .header(k, v).send().await?;
        resp.json().await.map_err(|e| format!("TheHive list_tasks JSON: {e}").into())
    }

    /// إضافة مهمة جديدة لقضية
    pub async fn add_task(
        &self,
        case_id:     &str,
        title:       &str,
        description: Option<&str>,
        assignee:    Option<&str>,
    ) -> Result<CaseTask, Box<dyn std::error::Error + Send + Sync>> {
        let req = TaskRequest {
            title:       title.to_string(),
            description: description.map(str::to_string),
            assignee:    assignee.map(str::to_string),
        };
        let (k, v) = self.auth_header();
        let resp = self.http.post(&self.url(&format!("case/{case_id}/task")))
            .header(k, v).json(&req).send().await?;
        if !resp.status().is_success() {
            return Err(format!("TheHive add_task HTTP {}", resp.status()).into());
        }
        resp.json().await.map_err(|e| format!("TheHive task JSON: {e}").into())
    }

    // ── Comments ─────────────────────────────────────────────────────────────

    /// إضافة تعليق تحليلي لقضية
    pub async fn add_comment(
        &self,
        case_id: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let req = CommentRequest { message: message.to_string() };
        let (k, v) = self.auth_header();
        let resp = self.http.post(&self.url(&format!("case/{case_id}/comment")))
            .header(k, v).json(&req).send().await?;
        if resp.status().is_success() {
            log::info!("TheHive: comment added to case {case_id}");
            Ok(())
        } else {
            Err(format!("TheHive add_comment HTTP {}", resp.status()).into())
        }
    }

    // ── High-Level Thor Integration ───────────────────────────────────────────

    /// إنشاء تنبيه + ترقيته لقضية تلقائياً إذا كان الخطر عالياً
    pub async fn handle_thor_event(
        &self,
        event: &ThorThreatEvent,
    ) -> Result<(Alert, Option<Case>), Box<dyn std::error::Error + Send + Sync>> {
        // 1. إنشاء التنبيه دائماً
        let alert = self.create_alert_from_thor_event(event).await?;

        // 2. ترقية إلى قضية إذا كان الخطر عالياً (>= 7.0)
        let case = if event.threat_score >= 7.0 {
            match self.promote_alert_to_case(&alert.id).await {
                Ok(c) => {
                    // إضافة IPs كـ observables
                    let _ = self.add_observable_ip(&c.id, &event.src_ip,
                        &format!("Source IP — {}", event.threat_class)).await;
                    if event.dst_ip != event.src_ip {
                        let _ = self.add_observable_ip(&c.id, &event.dst_ip,
                            "Destination IP").await;
                    }

                    // إضافة تعليق تلقائي
                    let comment = format!(
                        "## 🤖 Thor Automated Analysis\n\n\
                        - **Threat**: `{}` (score `{:.1}`)\n\
                        - **Action**: `{}`\n\
                        - **Protocol**: `{}:{} → {}:{}`\n\
                        - **MITRE TTPs**: {}\n\
                        - **Auto-promoted**: score ≥ 7.0 threshold\n",
                        event.threat_class, event.threat_score, event.action,
                        event.src_ip, event.src_port, event.dst_ip, event.dst_port,
                        if event.mitre_ttps.is_empty() {
                            "None".to_string()
                        } else {
                            event.mitre_ttps.join(", ")
                        }
                    );
                    let _ = self.add_comment(&c.id, &comment).await;

                    log::info!(
                        "TheHive: event {} auto-promoted to case {} (score {:.1})",
                        event.event_id, c.id, event.threat_score
                    );
                    Some(c)
                }
                Err(e) => {
                    log::warn!("TheHive: could not promote alert {}: {e}", alert.id);
                    None
                }
            }
        } else {
            log::debug!("TheHive: alert created (score {:.1} < 7.0, no auto-promotion)", event.threat_score);
            None
        };

        Ok((alert, case))
    }

    /// إضافة IoCs من تقرير CAPEv2 لقضية موجودة
    pub async fn attach_cape_iocs(
        &self,
        case_id:      &str,
        cape_iocs:    &crate::capev2_client::ExtractedIocs,
        cape_task_id: u64,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let mut added = 0usize;

        for ip in &cape_iocs.ips {
            if self.add_observable_ip(case_id, ip,
                &format!("From CAPEv2 sandbox task #{}", cape_task_id)).await.is_ok()
            { added += 1; }
        }
        for domain in &cape_iocs.domains {
            if self.add_observable_domain(case_id, domain,
                &format!("From CAPEv2 sandbox task #{}", cape_task_id)).await.is_ok()
            { added += 1; }
        }
        for hash in &cape_iocs.file_hashes {
            if self.add_observable_hash(case_id, hash,
                &format!("Malware hash from CAPEv2 task #{}", cape_task_id)).await.is_ok()
            { added += 1; }
        }

        // إضافة تعليق بملخص الدمج
        let _ = self.add_comment(case_id, &format!(
            "## 🦠 CAPEv2 Analysis (Task #{})\n\n\
            Automatically added IoCs:\n\
            - {} IPs\n- {} domains\n- {} file hashes\n- {} YARA signatures\n- {} malware families\n\n\
            **Families**: {}",
            cape_task_id,
            cape_iocs.ips.len(), cape_iocs.domains.len(),
            cape_iocs.file_hashes.len(), cape_iocs.yara_signatures.len(),
            cape_iocs.malware_families.len(),
            if cape_iocs.malware_families.is_empty() { "Unknown".to_string() }
            else { cape_iocs.malware_families.join(", ") }
        )).await;

        log::info!("TheHive: added {} IoCs from CAPEv2 task {} to case {}", added, cape_task_id, case_id);
        Ok(added)
    }

    /// إضافة نتائج Cortex analysis لقضية موجودة
    pub async fn attach_cortex_findings(
        &self,
        case_id:  &str,
        analysis: &crate::cortex_client::AggregatedAnalysis,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let verdict_str = format!("{:?}", analysis.verdict);
        let comment = format!(
            "## 🔬 Cortex Analysis\n\n\
            **Observable**: `{}`\n\
            **Type**: `{}`\n\
            **Verdict**: `{}`\n\
            **Risk Score**: `{:.1}/10.0`\n\n\
            ### Analyzer Findings\n{}\n",
            analysis.observable, analysis.observable_type,
            verdict_str, analysis.risk_score,
            if analysis.details.is_empty() {
                "_No findings_".to_string()
            } else {
                analysis.details.iter()
                    .map(|d| format!("- **{}** [{}]: {}", d.analyzer, d.level, d.description))
                    .collect::<Vec<_>>().join("\n")
            }
        );
        self.add_comment(case_id, &comment).await
    }
}

// ── اختبارات ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_risk_score() {
        assert_eq!(Severity::from_risk_score(0.0),  Severity::Low);
        assert_eq!(Severity::from_risk_score(2.5),  Severity::Low);
        assert_eq!(Severity::from_risk_score(5.0),  Severity::Medium);
        assert_eq!(Severity::from_risk_score(7.5),  Severity::High);
        assert_eq!(Severity::from_risk_score(9.0),  Severity::Critical);
        assert_eq!(Severity::from_risk_score(10.0), Severity::Critical);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High     > Severity::Medium);
        assert!(Severity::Medium   > Severity::Low);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
        assert_eq!(Severity::High.to_string(),     "High");
        assert_eq!(Severity::Low.to_string(),      "Low");
    }

    #[test]
    fn test_thor_event_serializes() {
        let ev = ThorThreatEvent {
            event_id:    "evt-001".to_string(),
            src_ip:      "1.2.3.4".to_string(),
            dst_ip:      "5.6.7.8".to_string(),
            src_port:    54321,
            dst_port:    443,
            protocol:    "TCP".to_string(),
            threat_class: "Port Scan".to_string(),
            threat_score: 8.0,
            action:      "BLOCK".to_string(),
            timestamp:   1700000000,
            description: "Detected port scan".to_string(),
            tags:        vec!["scan".to_string()],
            mitre_ttps:  vec!["T1046".to_string()],
        };
        let j = serde_json::to_string(&ev).unwrap();
        assert!(j.contains("1.2.3.4"));
        assert!(j.contains("T1046"));
    }

    #[test]
    fn test_severity_num() {
        assert_eq!(Severity::Low.as_num(),      1);
        assert_eq!(Severity::Medium.as_num(),   2);
        assert_eq!(Severity::High.as_num(),     3);
        assert_eq!(Severity::Critical.as_num(), 4);
    }

    #[tokio::test]
    async fn test_health_check_fails_gracefully() {
        let c = TheHiveClient::new("http://localhost:19999", "key");
        let r = c.health_check().await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_create_alert_fails_gracefully() {
        let c = TheHiveClient::new("http://localhost:19999", "key");
        let r = c.create_alert("test", "desc", Severity::High, "test",
            "thor", "ref-001", Tlp::Amber, vec![]).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_handle_thor_event_fails_gracefully() {
        let c = TheHiveClient::new("http://localhost:19999", "key");
        let ev = ThorThreatEvent {
            event_id: "e1".to_string(), src_ip: "1.2.3.4".to_string(),
            dst_ip: "5.6.7.8".to_string(), src_port: 1234, dst_port: 443,
            protocol: "tcp".to_string(), threat_class: "Scan".to_string(),
            threat_score: 9.0, action: "BLOCK".to_string(), timestamp: 0,
            description: "test".to_string(), tags: vec![], mitre_ttps: vec![],
        };
        let r = c.handle_thor_event(&ev).await;
        assert!(r.is_err());
    }
}
