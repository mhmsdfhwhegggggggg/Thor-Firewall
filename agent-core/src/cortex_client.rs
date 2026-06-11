//! Thor Firewall — Cortex Integration (Complete)
//!
//! يدمج Cortex REST API بالكامل داخل Thor:
//!  • Analyzers  : تشغيل محللات على IPs، domains، hashes، URLs، emails
//!  • Responders : تنفيذ استجابات على تنبيهات TheHive
//!  • Jobs       : إدارة مهام التحليل (إنشاء، متابعة، جلب نتائج)
//!  • Reports    : جلب تقارير التحليل المنظّمة
//!  • Observables: رسم خريطة أنواع الكائنات المدعومة
//!
//! الاستخدام:
//!   let cortex = CortexClient::new("http://cortex:9001", "api-key");
//!   let jobs   = cortex.analyze_ip("1.2.3.4").await?;
//!   let report = cortex.wait_for_job(&job_id).await?;

use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, timeout};
use reqwest::{Client, StatusCode};

// ── الثوابت ───────────────────────────────────────────────────────────────────

const JOB_POLL_INTERVAL_MS: u64 = 2_000;
const JOB_TIMEOUT_SECS:     u64 = 300;     // 5 دقائق حد أقصى لكل مهمة
const MAX_CONCURRENT_JOBS:  usize = 10;

// ── هياكل الـ API ─────────────────────────────────────────────────────────────

/// نوع الكائن القابل للتحليل
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ObservableType {
    Ip,
    Domain,
    Url,
    #[serde(rename = "hash")]
    FileHash,
    Mail,
    Filename,
    Uri,
    #[serde(rename = "mail_subject")]
    MailSubject,
    Regexp,
    Registry,
    Other,
}

impl ObservableType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObservableType::Ip          => "ip",
            ObservableType::Domain      => "domain",
            ObservableType::Url         => "url",
            ObservableType::FileHash    => "hash",
            ObservableType::Mail        => "mail",
            ObservableType::Filename    => "filename",
            ObservableType::Uri         => "uri",
            ObservableType::MailSubject => "mail_subject",
            ObservableType::Regexp      => "regexp",
            ObservableType::Registry    => "registry",
            ObservableType::Other       => "other",
        }
    }
}

/// محلل Cortex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analyzer {
    pub id:             String,
    pub name:           String,
    pub version:        String,
    pub description:    String,
    #[serde(rename = "dataTypeList")]
    pub data_type_list: Vec<String>,
    pub license:        Option<String>,
    pub url:            Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at:     Option<u64>,
}

/// مستجيب (Responder) Cortex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Responder {
    pub id:          String,
    pub name:        String,
    pub version:     String,
    pub description: String,
    #[serde(rename = "dataTypeList")]
    pub data_type_list: Vec<String>,
}

/// حالة مهمة التحليل
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum JobStatus {
    Waiting,
    InProgress,
    Success,
    Failure,
    Deleted,
}

/// مهمة تحليل Cortex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id:           String,
    pub status:       JobStatus,
    #[serde(rename = "analyzerId")]
    pub analyzer_id:  String,
    #[serde(rename = "analyzerName")]
    pub analyzer_name: String,
    pub data:         String,
    #[serde(rename = "dataType")]
    pub data_type:    String,
    #[serde(rename = "startDate")]
    pub start_date:   Option<u64>,
    #[serde(rename = "endDate")]
    pub end_date:     Option<u64>,
    pub report:       Option<JobReport>,
}

/// تقرير نتائج التحليل
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobReport {
    pub summary:      Option<ReportSummary>,
    pub full:         Option<serde_json::Value>,
    pub success:      bool,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub taxonomies: Vec<Taxonomy>,
}

/// تصنيف نتيجة التحليل (مثل: VirusTotal → malicious)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Taxonomy {
    pub namespace: String,    // مثل: "VT"
    pub predicate: String,    // مثل: "score"
    pub value:     String,    // مثل: "45/70"
    pub level:     TaxLevel,  // info / safe / suspicious / malicious
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TaxLevel {
    Info,
    Safe,
    Suspicious,
    Malicious,
}

/// نتيجة تحليل مجمّعة من محللات متعددة
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedAnalysis {
    pub observable:      String,
    pub observable_type: String,
    pub jobs:            Vec<Job>,
    pub verdict:         AnalysisVerdict,
    pub risk_score:      f32,   // 0.0–10.0
    pub details:         Vec<AnalyzerFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnalysisVerdict {
    Safe,
    Suspicious,
    Malicious,
    Unknown,
}

/// نتيجة من محلل واحد
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerFinding {
    pub analyzer:    String,
    pub level:       String,
    pub namespace:   String,
    pub description: String,
}

/// طلب تشغيل محلل
#[derive(Serialize)]
struct AnalyzeRequest {
    #[serde(rename = "dataType")]
    data_type:   String,
    data:        String,
    #[serde(rename = "analyzerId")]
    analyzer_id: String,
    tlp:         u8,     // 0=White, 1=Green, 2=Amber, 3=Red
    message:     Option<String>,
    parameters:  HashMap<String, serde_json::Value>,
}

/// طلب تشغيل مستجيب
#[derive(Serialize)]
struct RespondRequest {
    #[serde(rename = "responderId")]
    responder_id:  String,
    #[serde(rename = "objectType")]
    object_type:   String,
    #[serde(rename = "objectId")]
    object_id:     String,
    tlp:           u8,
    message:       Option<String>,
}

// ── CortexClient ──────────────────────────────────────────────────────────────

pub struct CortexClient {
    base_url:  String,
    api_key:   String,
    http:      Client,
    /// محللات مخزّنة مؤقتاً (cache) لتجنب جلبها في كل طلب
    analyzers_cache: Arc<tokio::sync::RwLock<Vec<Analyzer>>>,
}

impl CortexClient {
    /// إنشاء client جديد
    pub fn new(base_url: &str, api_key: &str) -> Arc<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build Cortex HTTP client");

        Arc::new(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key:  api_key.to_string(),
            http,
            analyzers_cache: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        })
    }

    /// إضافة Authorization header
    fn auth_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", self.api_key).parse().unwrap(),
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/{}", self.base_url, path.trim_start_matches('/'))
    }

    // ── صحة الخدمة ───────────────────────────────────────────────────────────

    pub async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.http.get(&format!("{}/api/status", self.base_url))
            .headers(self.auth_headers())
            .timeout(Duration::from_secs(5))
            .send().await?;
        Ok(resp.status().is_success())
    }

    // ── Analyzers ────────────────────────────────────────────────────────────

    /// جلب جميع المحللات المتاحة
    pub async fn list_analyzers(&self) -> Result<Vec<Analyzer>, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.http.get(&self.url("analyzer"))
            .headers(self.auth_headers())
            .send().await?;

        if !resp.status().is_success() {
            return Err(format!("Cortex list_analyzers: HTTP {}", resp.status()).into());
        }

        let analyzers: Vec<Analyzer> = resp.json().await
            .map_err(|e| format!("Cortex analyzers JSON: {e}"))?;

        // تحديث الـ cache
        *self.analyzers_cache.write().await = analyzers.clone();
        log::info!("Cortex: {} analyzers available", analyzers.len());
        Ok(analyzers)
    }

    /// جلب المحللات التي تدعم نوع كائن معين
    pub async fn analyzers_for_type(
        &self,
        data_type: &ObservableType,
    ) -> Result<Vec<Analyzer>, Box<dyn std::error::Error + Send + Sync>> {
        let all = self.list_analyzers().await?;
        let type_str = data_type.as_str();
        Ok(all.into_iter()
            .filter(|a| a.data_type_list.iter().any(|t| t == type_str))
            .collect())
    }

    /// جلب محلل واحد بالاسم
    pub async fn get_analyzer_by_name(
        &self,
        name: &str,
    ) -> Result<Option<Analyzer>, Box<dyn std::error::Error + Send + Sync>> {
        let all = {
            let cache = self.analyzers_cache.read().await;
            if cache.is_empty() { None } else { Some(cache.clone()) }
        };

        let analyzers = match all {
            Some(a) => a,
            None    => self.list_analyzers().await?,
        };

        Ok(analyzers.into_iter().find(|a| a.name.contains(name)))
    }

    // ── Jobs ─────────────────────────────────────────────────────────────────

    /// تشغيل محلل واحد على كائن
    pub async fn run_analyzer(
        &self,
        analyzer_id: &str,
        data:        &str,
        data_type:   &ObservableType,
        tlp:         u8,
    ) -> Result<Job, Box<dyn std::error::Error + Send + Sync>> {
        let req = AnalyzeRequest {
            data_type:   data_type.as_str().to_string(),
            data:        data.to_string(),
            analyzer_id: analyzer_id.to_string(),
            tlp,
            message:     None,
            parameters:  HashMap::new(),
        };

        let resp = self.http.post(&self.url("analyzer/run"))
            .headers(self.auth_headers())
            .json(&req)
            .send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Cortex run_analyzer HTTP {status}: {body}").into());
        }

        let job: Job = resp.json().await
            .map_err(|e| format!("Cortex run_analyzer JSON: {e}"))?;

        log::info!("Cortex: job {} started (analyzer={}, data={})",
            job.id, job.analyzer_name, data);
        Ok(job)
    }

    /// جلب حالة مهمة
    pub async fn get_job(&self, job_id: &str) -> Result<Job, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.http.get(&self.url(&format!("job/{job_id}")))
            .headers(self.auth_headers())
            .send().await?;

        if !resp.status().is_success() {
            return Err(format!("Cortex get_job HTTP {}", resp.status()).into());
        }

        resp.json().await.map_err(|e| format!("Cortex get_job JSON: {e}").into())
    }

    /// جلب تقرير مهمة (يتضمن النتائج الكاملة)
    pub async fn get_job_report(&self, job_id: &str) -> Result<Job, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.http.get(&self.url(&format!("job/{job_id}/report")))
            .headers(self.auth_headers())
            .send().await?;

        resp.json().await.map_err(|e| format!("Cortex get_job_report JSON: {e}").into())
    }

    /// انتظار انتهاء مهمة (polling)
    pub async fn wait_for_job(
        &self,
        job_id: &str,
    ) -> Result<Job, Box<dyn std::error::Error + Send + Sync>> {
        let t0 = Instant::now();
        let max = Duration::from_secs(JOB_TIMEOUT_SECS);

        loop {
            if t0.elapsed() > max {
                return Err(format!("Job {job_id} timed out after {JOB_TIMEOUT_SECS}s").into());
            }

            let job = self.get_job(job_id).await?;

            match job.status {
                JobStatus::Success | JobStatus::Failure | JobStatus::Deleted => {
                    log::info!("Cortex: job {} finished ({:?})", job_id, job.status);
                    return Ok(job);
                }
                _ => {
                    log::debug!("Cortex: job {} still running...", job_id);
                    sleep(Duration::from_millis(JOB_POLL_INTERVAL_MS)).await;
                }
            }
        }
    }

    /// حذف مهمة
    pub async fn delete_job(&self, job_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.http.delete(&self.url(&format!("job/{job_id}")))
            .headers(self.auth_headers())
            .send().await?;
        if resp.status().is_success() {
            log::info!("Cortex: job {job_id} deleted");
            Ok(())
        } else {
            Err(format!("Cortex delete_job HTTP {}", resp.status()).into())
        }
    }

    /// جلب قائمة المهام الأخيرة
    pub async fn list_jobs(
        &self,
        limit: usize,
        data_type: Option<&str>,
    ) -> Result<Vec<Job>, Box<dyn std::error::Error + Send + Sync>> {
        let mut url = self.url("job");
        if let Some(dt) = data_type {
            url = format!("{url}?dataType={dt}&limit={limit}");
        } else {
            url = format!("{url}?limit={limit}");
        }

        let resp = self.http.get(&url)
            .headers(self.auth_headers())
            .send().await?;

        resp.json().await.map_err(|e| format!("Cortex list_jobs JSON: {e}").into())
    }

    // ── التحليل الشامل (High-Level API) ─────────────────────────────────────

    /// تشغيل جميع المحللات المتاحة على IP وانتظار النتائج
    pub async fn analyze_ip(
        &self,
        ip: &str,
    ) -> Result<AggregatedAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        self.analyze_observable(ip, &ObservableType::Ip, 2).await
    }

    /// تحليل domain
    pub async fn analyze_domain(
        &self,
        domain: &str,
    ) -> Result<AggregatedAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        self.analyze_observable(domain, &ObservableType::Domain, 2).await
    }

    /// تحليل hash (MD5/SHA1/SHA256)
    pub async fn analyze_hash(
        &self,
        hash: &str,
    ) -> Result<AggregatedAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        self.analyze_observable(hash, &ObservableType::FileHash, 2).await
    }

    /// تحليل URL
    pub async fn analyze_url(
        &self,
        url: &str,
    ) -> Result<AggregatedAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        self.analyze_observable(url, &ObservableType::Url, 2).await
    }

    /// تحليل عنوان بريد إلكتروني
    pub async fn analyze_email(
        &self,
        email: &str,
    ) -> Result<AggregatedAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        self.analyze_observable(email, &ObservableType::Mail, 2).await
    }

    /// تحليل كائن بتشغيل جميع المحللات المناسبة بالتوازي
    pub async fn analyze_observable(
        &self,
        data:      &str,
        data_type: &ObservableType,
        tlp:       u8,
    ) -> Result<AggregatedAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        let analyzers = self.analyzers_for_type(data_type).await?;

        if analyzers.is_empty() {
            log::warn!("Cortex: no analyzers for type {:?}", data_type);
            return Ok(AggregatedAnalysis {
                observable:      data.to_string(),
                observable_type: data_type.as_str().to_string(),
                jobs:            vec![],
                verdict:         AnalysisVerdict::Unknown,
                risk_score:      0.0,
                details:         vec![],
            });
        }

        log::info!("Cortex: running {} analyzers on {} ({:?})",
            analyzers.len(), data, data_type);

        // تشغيل المحللات بالتوازي (MAX_CONCURRENT_JOBS في وقت واحد)
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_JOBS));
        let mut handles = Vec::new();

        for analyzer in analyzers {
            let client   = Arc::new(Self {
                base_url: self.base_url.clone(),
                api_key:  self.api_key.clone(),
                http:     self.http.clone(),
                analyzers_cache: Arc::clone(&self.analyzers_cache),
            });
            let data_clone  = data.to_string();
            let type_clone  = data_type.clone();
            let sem_clone   = Arc::clone(&sem);

            handles.push(tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.ok()?;

                // تشغيل المحلل
                let job = client.run_analyzer(
                    &analyzer.id, &data_clone, &type_clone, tlp
                ).await.ok()?;

                // انتظار النتيجة
                client.wait_for_job(&job.id).await.ok()
            }));
        }

        // جمع النتائج
        let mut completed_jobs: Vec<Job> = Vec::new();
        for h in handles {
            if let Ok(Some(job)) = h.await {
                completed_jobs.push(job);
            }
        }

        // تحليل النتائج وحساب Verdict
        let (verdict, risk_score, details) = self.aggregate_results(&completed_jobs);

        log::info!("Cortex: analysis complete — verdict={:?} score={:.1}",
            verdict, risk_score);

        Ok(AggregatedAnalysis {
            observable:      data.to_string(),
            observable_type: data_type.as_str().to_string(),
            jobs:            completed_jobs,
            verdict,
            risk_score,
            details,
        })
    }

    /// تجميع نتائج المحللات وحساب الحكم النهائي
    fn aggregate_results(&self, jobs: &[Job]) -> (AnalysisVerdict, f32, Vec<AnalyzerFinding>) {
        let mut findings = Vec::new();
        let mut malicious_count = 0u32;
        let mut suspicious_count = 0u32;
        let mut safe_count = 0u32;
        let mut total = 0u32;

        for job in jobs {
            if job.status != JobStatus::Success { continue; }
            if let Some(report) = &job.report {
                if let Some(summary) = &report.summary {
                    for tax in &summary.taxonomies {
                        total += 1;
                        match tax.level {
                            TaxLevel::Malicious  => malicious_count += 1,
                            TaxLevel::Suspicious => suspicious_count += 1,
                            TaxLevel::Safe       => safe_count += 1,
                            TaxLevel::Info       => {}
                        }
                        findings.push(AnalyzerFinding {
                            analyzer:    job.analyzer_name.clone(),
                            level:       format!("{:?}", tax.level),
                            namespace:   tax.namespace.clone(),
                            description: format!("{}: {}", tax.predicate, tax.value),
                        });
                    }
                }
            }
        }

        let verdict = if malicious_count > 0 {
            AnalysisVerdict::Malicious
        } else if suspicious_count > 0 {
            AnalysisVerdict::Suspicious
        } else if safe_count > 0 {
            AnalysisVerdict::Safe
        } else {
            AnalysisVerdict::Unknown
        };

        // risk_score: نسبة المحللات التي أعطت Malicious × 10
        let risk = if total > 0 {
            (malicious_count as f32 / total as f32) * 10.0
            + (suspicious_count as f32 / total as f32) * 5.0
        } else {
            0.0
        };

        (verdict, risk.min(10.0), findings)
    }

    // ── Responders ───────────────────────────────────────────────────────────

    /// جلب جميع المستجيبين المتاحين
    pub async fn list_responders(&self) -> Result<Vec<Responder>, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self.http.get(&self.url("responder"))
            .headers(self.auth_headers())
            .send().await?;

        resp.json().await.map_err(|e| format!("Cortex list_responders JSON: {e}").into())
    }

    /// تشغيل مستجيب على تنبيه TheHive
    pub async fn run_responder(
        &self,
        responder_id: &str,
        object_type:  &str,   // "alert" / "case" / "case_task"
        object_id:    &str,
        tlp:          u8,
    ) -> Result<Job, Box<dyn std::error::Error + Send + Sync>> {
        let req = RespondRequest {
            responder_id: responder_id.to_string(),
            object_type:  object_type.to_string(),
            object_id:    object_id.to_string(),
            tlp,
            message: None,
        };

        let resp = self.http.post(&self.url("responder/run"))
            .headers(self.auth_headers())
            .json(&req)
            .send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Cortex run_responder HTTP {status}: {body}").into());
        }

        let job: Job = resp.json().await?;
        log::info!("Cortex: responder job {} started (responder={}, object={})",
            job.id, responder_id, object_id);
        Ok(job)
    }

    // ── Integration مع Thor: تحليل تلقائي من RL Agent decisions ─────────────

    /// تحليل IP تلقائياً عند اتخاذ قرار BLOCK
    pub async fn auto_analyze_on_block(
        &self,
        src_ip:      &str,
        threat_class: &str,
        threat_score: f32,
    ) -> Result<AggregatedAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        log::info!(
            "Cortex: auto-analyzing {} (threat={} score={:.1}) after BLOCK decision",
            src_ip, threat_class, threat_score
        );
        self.analyze_ip(src_ip).await
    }

    /// تحليل domain من DNS query مشبوهة
    pub async fn analyze_suspicious_domain(
        &self,
        domain: &str,
        context: &str,
    ) -> Result<AggregatedAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Cortex: analyzing suspicious domain {} (context: {})", domain, context);
        self.analyze_domain(domain).await
    }
}

// ── اختبارات ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observable_type_as_str() {
        assert_eq!(ObservableType::Ip.as_str(),       "ip");
        assert_eq!(ObservableType::Domain.as_str(),   "domain");
        assert_eq!(ObservableType::FileHash.as_str(), "hash");
        assert_eq!(ObservableType::Url.as_str(),      "url");
        assert_eq!(ObservableType::Mail.as_str(),     "mail");
    }

    #[test]
    fn test_aggregated_analysis_serializes() {
        let a = AggregatedAnalysis {
            observable:      "1.2.3.4".to_string(),
            observable_type: "ip".to_string(),
            jobs:            vec![],
            verdict:         AnalysisVerdict::Malicious,
            risk_score:      8.5,
            details:         vec![],
        };
        let j = serde_json::to_string(&a).unwrap();
        assert!(j.contains("1.2.3.4"));
        assert!(j.contains("Malicious"));
    }

    #[test]
    fn test_aggregate_results_empty_jobs() {
        let client = CortexClient::new("http://cortex:9001", "key");
        let (verdict, score, findings) = client.aggregate_results(&[]);
        assert_eq!(verdict, AnalysisVerdict::Unknown);
        assert_eq!(score, 0.0);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_aggregate_results_malicious() {
        let client = CortexClient::new("http://cortex:9001", "key");
        let jobs = vec![Job {
            id: "j1".to_string(), status: JobStatus::Success,
            analyzer_id: "VT_1_0".to_string(), analyzer_name: "VirusTotal".to_string(),
            data: "1.2.3.4".to_string(), data_type: "ip".to_string(),
            start_date: None, end_date: None,
            report: Some(JobReport {
                success: true, error_message: None, full: None,
                summary: Some(ReportSummary {
                    taxonomies: vec![Taxonomy {
                        namespace: "VT".to_string(), predicate: "score".to_string(),
                        value: "45/70".to_string(), level: TaxLevel::Malicious,
                    }]
                })
            })
        }];
        let (verdict, score, findings) = client.aggregate_results(&jobs);
        assert_eq!(verdict, AnalysisVerdict::Malicious);
        assert!(score > 0.0);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_taxonomy_levels() {
        assert!(matches!(TaxLevel::Malicious,  TaxLevel::Malicious));
        assert!(matches!(TaxLevel::Suspicious, TaxLevel::Suspicious));
        assert!(matches!(TaxLevel::Safe,       TaxLevel::Safe));
        assert!(matches!(TaxLevel::Info,       TaxLevel::Info));
    }

    #[tokio::test]
    async fn test_health_check_fails_gracefully() {
        let c = CortexClient::new("http://localhost:19997", "key");
        let r = c.health_check().await;
        assert!(r.is_err(), "Should fail when Cortex is not running");
    }

    #[tokio::test]
    async fn test_list_analyzers_fails_gracefully() {
        let c = CortexClient::new("http://localhost:19997", "key");
        let r = c.list_analyzers().await;
        assert!(r.is_err());
    }
}
