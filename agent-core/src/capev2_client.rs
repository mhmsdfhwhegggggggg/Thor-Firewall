//! Thor Firewall — CAPEv2 Sandbox Integration (Complete)
//!
//! يدمج CAPEv2 Malware Sandbox REST API بالكامل:
//!  • رفع ملفات للتحليل الديناميكي (submit file/URL)
//!  • متابعة مهام التحليل (polling) حتى الانتهاء
//!  • جلب تقارير كاملة: سلوك + شبكة + YARA + signatures
//!  • استخراج IoCs (IPs، domains، registry، mutexes)
//!  • دمج تلقائي مع Thor: تحليل exe عند اكتشافه في الشبكة
//!
//! الاستخدام:
//!   let cape = CapeClient::new("http://cape:8000", "api-key");
//!   let task  = cape.submit_file_bytes(bytes, "malware.exe").await?;
//!   let report = cape.wait_for_report(task.id).await?;
//!   let iocs   = report.extract_iocs();

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use reqwest::{Client, multipart};

// ── ثوابت ────────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS: u64  = 3_000;
const TASK_TIMEOUT_SECS: u64 = 600;     // 10 دقائق للتحليل الديناميكي
const MAX_FILE_SIZE_MB:  u64 = 100;

// ── الهياكل ───────────────────────────────────────────────────────────────────

/// حالة مهمة التحليل
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Reported,
    Failed,
    Recovered,
}

/// مهمة CAPEv2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapeTask {
    pub id:         u64,
    pub status:     TaskStatus,
    pub target:     String,
    pub category:   String,   // file / url
    pub score:      Option<f32>,
    pub added:      Option<String>,
    pub completed:  Option<String>,
    pub machine:    Option<String>,
}

/// API Response لرفع ملف
#[derive(Debug, Deserialize)]
struct SubmitResponse {
    task_id:  Option<u64>,
    task_ids: Option<Vec<u64>>,
    error:    Option<bool>,
    message:  Option<String>,
}

/// تقرير تحليل CAPEv2 كامل
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapeReport {
    pub task_id:    u64,
    pub score:      f32,
    pub info:       TaskInfo,
    pub signatures: Vec<Signature>,
    pub network:    NetworkActivity,
    pub behavior:   BehaviorSummary,
    pub yara:       Vec<YaraMatch>,
    pub target:     TargetInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskInfo {
    pub id:       u64,
    pub added:    Option<String>,
    pub ended:    Option<String>,
    pub machine:  Option<String>,
    pub duration: Option<i64>,
    pub package:  Option<String>,
}

/// توقيع سلوكي مكتشف
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub name:        String,
    pub description: String,
    pub severity:    u8,       // 1=Info, 2=Warning, 3=Alert
    pub categories:  Vec<String>,
    pub families:    Vec<String>,
    pub marks:       Vec<serde_json::Value>,
}

/// نشاط شبكي مرصود
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkActivity {
    pub dns:      Vec<DnsQuery>,
    pub http:     Vec<HttpRequest>,
    pub tcp:      Vec<TcpConnection>,
    pub udp:      Vec<UdpFlow>,
    pub hosts:    Vec<String>,
    pub domains:  Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub hostname:  String,
    pub ips:       Vec<String>,
    #[serde(rename = "type")]
    pub query_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub uri:     String,
    pub host:    String,
    pub method:  String,
    pub port:    u16,
    pub status:  Option<u16>,
    pub path:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnection {
    pub src:      String,
    pub dst:      String,
    pub sport:    u16,
    pub dport:    u16,
    pub offset:   Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpFlow {
    pub src:   String,
    pub dst:   String,
    pub sport: u16,
    pub dport: u16,
}

/// ملخص سلوكي
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehaviorSummary {
    pub processes:       Vec<ProcessInfo>,
    pub files_opened:    Vec<String>,
    pub files_written:   Vec<String>,
    pub files_deleted:   Vec<String>,
    pub registry_keys:   Vec<String>,
    pub mutexes:         Vec<String>,
    pub api_calls:       Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub process_id:   u32,
    pub process_name: String,
    pub parent_id:    u32,
    pub command_line: Option<String>,
}

/// تطابق YARA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub name:        String,
    pub description: Option<String>,
    pub author:      Option<String>,
    pub families:    Vec<String>,
    pub strings:     Vec<YaraString>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub name:   String,
    pub value:  String,
    pub offset: u64,
}

/// معلومات الملف المُحلَّل
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetInfo {
    pub file:     Option<FileInfo>,
    pub url:      Option<String>,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileInfo {
    pub name:     String,
    pub path:     String,
    pub size:     u64,
    pub md5:      String,
    pub sha1:     String,
    pub sha256:   String,
    pub sha512:   String,
    pub crc32:    String,
    #[serde(rename = "type")]
    pub file_type: String,
    pub yara:     Vec<String>,
}

/// Indicators of Compromise مستخرجة من التقرير
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtractedIocs {
    pub ips:              Vec<String>,
    pub domains:          Vec<String>,
    pub urls:             Vec<String>,
    pub registry_keys:    Vec<String>,
    pub mutexes:          Vec<String>,
    pub file_hashes:      Vec<String>,
    pub yara_signatures:  Vec<String>,
    pub malware_families: Vec<String>,
}

impl CapeReport {
    /// استخراج جميع IoCs من التقرير
    pub fn extract_iocs(&self) -> ExtractedIocs {
        let mut iocs = ExtractedIocs::default();

        // IPs من الاتصالات
        iocs.ips.extend(self.network.hosts.clone());
        iocs.ips.extend(
            self.network.tcp.iter().map(|c| c.dst.clone())
        );

        // Domains من DNS
        iocs.domains.extend(self.network.domains.clone());
        iocs.domains.extend(
            self.network.dns.iter().map(|d| d.hostname.clone())
        );

        // URLs من HTTP
        iocs.urls.extend(
            self.network.http.iter()
                .map(|h| format!("{}://{}:{}{}", "http", h.host, h.port, h.path))
        );

        // Registry keys
        iocs.registry_keys.extend(self.behavior.registry_keys.clone());

        // Mutexes
        iocs.mutexes.extend(self.behavior.mutexes.clone());

        // File hashes
        if let Some(f) = &self.target.file {
            if !f.md5.is_empty()    { iocs.file_hashes.push(format!("md5:{}", f.md5)); }
            if !f.sha256.is_empty() { iocs.file_hashes.push(format!("sha256:{}", f.sha256)); }
        }

        // YARA
        iocs.yara_signatures.extend(
            self.yara.iter().map(|y| y.name.clone())
        );

        // Malware families من signatures
        for sig in &self.signatures {
            iocs.malware_families.extend(sig.families.clone());
        }

        // إزالة التكرار
        let dedup = |v: &mut Vec<String>| {
            let seen: HashSet<String> = v.drain(..).collect();
            *v = seen.into_iter().collect();
            v.sort();
        };
        dedup(&mut iocs.ips);
        dedup(&mut iocs.domains);
        dedup(&mut iocs.urls);
        dedup(&mut iocs.registry_keys);
        dedup(&mut iocs.mutexes);
        dedup(&mut iocs.file_hashes);
        dedup(&mut iocs.yara_signatures);
        dedup(&mut iocs.malware_families);

        iocs
    }

    /// هل التحليل يُعتبر خطيراً؟ (score >= 7.0)
    pub fn is_malicious(&self) -> bool { self.score >= 7.0 }

    /// أعلى severity في signatures
    pub fn max_severity(&self) -> u8 {
        self.signatures.iter().map(|s| s.severity).max().unwrap_or(0)
    }

    /// ملخص للـ logging
    pub fn summary(&self) -> String {
        format!(
            "score={:.1} sigs={} yara={} net_hosts={} families={}",
            self.score,
            self.signatures.len(),
            self.yara.len(),
            self.network.hosts.len(),
            self.signatures.iter()
                .flat_map(|s| s.families.iter().cloned())
                .collect::<HashSet<_>>().len()
        )
    }
}

// ── CapeClient ────────────────────────────────────────────────────────────────

pub struct CapeClient {
    base_url: String,
    api_key:  Option<String>,
    http:     Client,
}

impl CapeClient {
    /// إنشاء client جديد
    pub fn new(base_url: &str, api_key: Option<&str>) -> Arc<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(60))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build CAPEv2 HTTP client");
        Arc::new(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key:  api_key.map(str::to_string),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn auth_header(&self) -> Option<String> {
        self.api_key.as_ref().map(|k| format!("Token {k}"))
    }

    // ── رفع ملفات ────────────────────────────────────────────────────────────

    /// رفع ملف (bytes) للتحليل
    pub async fn submit_file_bytes(
        &self,
        bytes:     Vec<u8>,
        filename:  &str,
        machine:   Option<&str>,
        package:   Option<&str>,
    ) -> Result<CapeTask, Box<dyn std::error::Error + Send + Sync>> {
        let size_mb = bytes.len() as u64 / 1_048_576;
        if size_mb > MAX_FILE_SIZE_MB {
            return Err(format!("File too large: {size_mb}MB > {MAX_FILE_SIZE_MB}MB limit").into());
        }

        log::info!("CAPEv2: submitting file {} ({} bytes)", filename, bytes.len());

        let part = multipart::Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")?;

        let mut form = multipart::Form::new().part("file", part);
        if let Some(m) = machine { form = form.text("machine", m.to_string()); }
        if let Some(p) = package { form = form.text("package", p.to_string()); }

        let mut req = self.http.post(&self.url("apiv2/tasks/create/file/"))
            .multipart(form);
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(format!("CAPEv2 submit HTTP {}", resp.status()).into());
        }

        let sub: SubmitResponse = resp.json().await?;
        if sub.error.unwrap_or(false) {
            return Err(format!("CAPEv2 submit error: {}", sub.message.unwrap_or_default()).into());
        }

        let task_id = sub.task_id
            .or_else(|| sub.task_ids.as_ref()?.first().copied())
            .ok_or("CAPEv2: no task_id returned")?;

        log::info!("CAPEv2: file submitted → task_id={}", task_id);
        self.get_task(task_id).await
    }

    /// رفع URL للتحليل
    pub async fn submit_url(
        &self,
        url:      &str,
        machine:  Option<&str>,
    ) -> Result<CapeTask, Box<dyn std::error::Error + Send + Sync>> {
        log::info!("CAPEv2: submitting URL {}", url);

        let mut params = vec![("url", url.to_string())];
        if let Some(m) = machine { params.push(("machine", m.to_string())); }

        let mut req = self.http.post(&self.url("apiv2/tasks/create/url/"))
            .form(&params);
        if let Some(auth) = self.auth_header() { req = req.header("Authorization", auth); }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(format!("CAPEv2 submit URL HTTP {}", resp.status()).into());
        }

        let sub: SubmitResponse = resp.json().await?;
        let task_id = sub.task_id
            .or_else(|| sub.task_ids.as_ref()?.first().copied())
            .ok_or("CAPEv2: no task_id")?;

        self.get_task(task_id).await
    }

    // ── جلب المهام ───────────────────────────────────────────────────────────

    /// جلب معلومات مهمة بمعرّفها
    pub async fn get_task(
        &self,
        task_id: u64,
    ) -> Result<CapeTask, Box<dyn std::error::Error + Send + Sync>> {
        let mut req = self.http.get(&self.url(&format!("apiv2/tasks/view/{task_id}/")));
        if let Some(auth) = self.auth_header() { req = req.header("Authorization", auth); }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(format!("CAPEv2 get_task HTTP {}", resp.status()).into());
        }

        #[derive(Deserialize)]
        struct Wrapper { data: CapeTask }
        let w: Wrapper = resp.json().await?;
        Ok(w.data)
    }

    /// جلب قائمة المهام الأخيرة
    pub async fn list_tasks(
        &self,
        limit:  usize,
        status: Option<&str>,
    ) -> Result<Vec<CapeTask>, Box<dyn std::error::Error + Send + Sync>> {
        let mut url = self.url(&format!("apiv2/tasks/list/{limit}/"));
        if let Some(s) = status { url = format!("{url}?status={s}"); }

        let mut req = self.http.get(&url);
        if let Some(auth) = self.auth_header() { req = req.header("Authorization", auth); }

        let resp = req.send().await?;

        #[derive(Deserialize)]
        struct Wrapper { data: Vec<CapeTask> }
        let w: Wrapper = resp.json().await?;
        Ok(w.data)
    }

    // ── التقارير ─────────────────────────────────────────────────────────────

    /// جلب تقرير مهمة كاملة
    pub async fn get_report(
        &self,
        task_id: u64,
    ) -> Result<CapeReport, Box<dyn std::error::Error + Send + Sync>> {
        let mut req = self.http.get(&self.url(&format!("apiv2/tasks/get/report/{task_id}/")))
            .timeout(Duration::from_secs(60));
        if let Some(auth) = self.auth_header() { req = req.header("Authorization", auth); }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(format!("CAPEv2 get_report HTTP {}", resp.status()).into());
        }

        resp.json().await.map_err(|e| format!("CAPEv2 report JSON: {e}").into())
    }

    /// انتظار اكتمال التحليل وجلب التقرير (polling)
    pub async fn wait_for_report(
        &self,
        task_id: u64,
    ) -> Result<CapeReport, Box<dyn std::error::Error + Send + Sync>> {
        let t0  = Instant::now();
        let max = Duration::from_secs(TASK_TIMEOUT_SECS);

        log::info!("CAPEv2: waiting for task {} to complete...", task_id);

        loop {
            if t0.elapsed() > max {
                return Err(format!("CAPEv2 task {task_id} timed out after {TASK_TIMEOUT_SECS}s").into());
            }

            let task = self.get_task(task_id).await?;
            log::debug!("CAPEv2: task {} status = {:?}", task_id, task.status);

            match task.status {
                TaskStatus::Reported | TaskStatus::Completed => {
                    log::info!("CAPEv2: task {} done — fetching report", task_id);
                    return self.get_report(task_id).await;
                }
                TaskStatus::Failed | TaskStatus::Recovered => {
                    return Err(format!("CAPEv2 task {task_id} failed").into());
                }
                _ => sleep(Duration::from_millis(POLL_INTERVAL_MS)).await,
            }
        }
    }

    // ── حذف مهمة ─────────────────────────────────────────────────────────────

    pub async fn delete_task(
        &self,
        task_id: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut req = self.http.get(&self.url(&format!("apiv2/tasks/delete/{task_id}/")));
        if let Some(auth) = self.auth_header() { req = req.header("Authorization", auth); }
        let resp = req.send().await?;
        if resp.status().is_success() {
            log::info!("CAPEv2: task {task_id} deleted");
            Ok(())
        } else {
            Err(format!("CAPEv2 delete task HTTP {}", resp.status()).into())
        }
    }

    // ── صحة الخدمة ───────────────────────────────────────────────────────────

    pub async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut req = self.http.get(&self.url("apiv2/cuckoo/status/"))
            .timeout(Duration::from_secs(5));
        if let Some(auth) = self.auth_header() { req = req.header("Authorization", auth); }
        let resp = req.send().await?;
        Ok(resp.status().is_success())
    }

    // ── Integration مع Thor ───────────────────────────────────────────────────

    /// تحليل ملف exe مكتشف في الشبكة تلقائياً
    pub async fn auto_analyze_network_payload(
        &self,
        payload:  Vec<u8>,
        filename: &str,
        src_ip:   &str,
    ) -> Result<ExtractedIocs, Box<dyn std::error::Error + Send + Sync>> {
        log::info!(
            "CAPEv2: auto-analyzing payload from {} → {} ({} bytes)",
            src_ip, filename, payload.len()
        );

        let task = self.submit_file_bytes(payload, filename, None, None).await?;
        let report = self.wait_for_report(task.id).await?;

        log::info!(
            "CAPEv2: analysis done for {} — {}",
            filename, report.summary()
        );

        if report.is_malicious() {
            log::warn!(
                "🚨 CAPEv2: MALICIOUS payload from {} — score={:.1} families={:?}",
                src_ip, report.score,
                report.signatures.iter().flat_map(|s| s.families.iter().cloned())
                    .collect::<HashSet<_>>()
            );
        }

        Ok(report.extract_iocs())
    }
}

// ── اختبارات ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> CapeReport {
        CapeReport {
            task_id: 1, score: 8.5,
            info: TaskInfo { id: 1, added: None, ended: None, machine: Some("win10".to_string()),
                duration: Some(120), package: Some("exe".to_string()) },
            signatures: vec![Signature {
                name: "ransomware_behavior".to_string(),
                description: "Ransomware detected".to_string(),
                severity: 3, categories: vec!["ransomware".to_string()],
                families: vec!["WannaCry".to_string()], marks: vec![],
            }],
            network: NetworkActivity {
                hosts:   vec!["192.168.1.100".to_string()],
                domains: vec!["evil.com".to_string()],
                dns:     vec![DnsQuery { hostname: "c2.evil.com".to_string(),
                    ips: vec!["10.0.0.1".to_string()], query_type: "A".to_string() }],
                http:    vec![HttpRequest { uri: "http://evil.com/gate.php".to_string(),
                    host: "evil.com".to_string(), method: "POST".to_string(),
                    port: 80, status: Some(200), path: "/gate.php".to_string() }],
                tcp:     vec![TcpConnection { src: "10.0.0.2".to_string(), dst: "192.168.1.100".to_string(),
                    sport: 54321, dport: 443, offset: None }],
                udp:     vec![],
            },
            behavior: BehaviorSummary {
                processes:     vec![ProcessInfo { process_id: 1234, process_name: "malware.exe".to_string(),
                    parent_id: 4, command_line: Some("malware.exe /silent".to_string()) }],
                files_written: vec!["C:\\Users\\victim\\enc_file.doc".to_string()],
                files_deleted: vec![], files_opened: vec![],
                registry_keys: vec!["HKCU\\Software\\Microsoft\\Windows\\Run".to_string()],
                mutexes:       vec!["Global\\WannaCryMutex".to_string()],
                api_calls:     vec!["CryptEncrypt".to_string(), "InternetOpenUrl".to_string()],
            },
            yara: vec![YaraMatch { name: "WannaCry".to_string(),
                description: Some("WannaCry ransomware".to_string()),
                author: None, families: vec!["WannaCry".to_string()],
                strings: vec![] }],
            target: TargetInfo {
                file: Some(FileInfo { name: "malware.exe".to_string(),
                    sha256: "abc123def456".to_string(), md5: "deadbeef".to_string(),
                    ..Default::default() }),
                url: None, category: "file".to_string(),
            },
        }
    }

    #[test]
    fn test_extract_iocs_completeness() {
        let r = sample_report();
        let iocs = r.extract_iocs();
        assert!(iocs.ips.contains(&"192.168.1.100".to_string()));
        assert!(iocs.domains.iter().any(|d| d.contains("evil.com")));
        assert!(!iocs.registry_keys.is_empty());
        assert!(iocs.mutexes.contains(&"Global\\WannaCryMutex".to_string()));
        assert!(iocs.file_hashes.iter().any(|h| h.starts_with("sha256:")));
        assert!(iocs.yara_signatures.contains(&"WannaCry".to_string()));
        assert!(iocs.malware_families.contains(&"WannaCry".to_string()));
    }

    #[test]
    fn test_is_malicious_threshold() {
        let r = sample_report(); // score=8.5
        assert!(r.is_malicious());

        let mut safe = sample_report();
        safe.score = 3.0;
        assert!(!safe.is_malicious());
    }

    #[test]
    fn test_max_severity() {
        let r = sample_report();
        assert_eq!(r.max_severity(), 3);
    }

    #[test]
    fn test_report_summary_format() {
        let r = sample_report();
        let s = r.summary();
        assert!(s.contains("score="));
        assert!(s.contains("sigs="));
        assert!(s.contains("yara="));
    }

    #[test]
    fn test_report_serializes() {
        let r = sample_report();
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("ransomware_behavior"));
        assert!(j.contains("WannaCry"));
    }

    #[tokio::test]
    async fn test_health_check_fails_gracefully() {
        let c = CapeClient::new("http://localhost:19998", None);
        let r = c.health_check().await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_submit_oversized_file() {
        let c = CapeClient::new("http://localhost:19998", None);
        let big = vec![0u8; (MAX_FILE_SIZE_MB + 1) as usize * 1_048_576];
        let r = c.submit_file_bytes(big, "huge.bin", None, None).await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("too large"));
    }
}
