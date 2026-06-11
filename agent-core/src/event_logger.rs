//! Thor Firewall — Event Logger
//! يُسجّل الأحداث إلى ClickHouse (تحليلات) و Redis (pub/sub + cache لحظي)
//! الاستخدام: let logger = EventLogger::new("http://clickhouse:8123", "redis://redis:6379").await?;

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use std::sync::Arc;

// ── هياكل الأحداث ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_u8(&self) -> u8 {
        match self {
            Severity::Low      => 1,
            Severity::Medium   => 2,
            Severity::High     => 3,
            Severity::Critical => 4,
        }
    }
    pub fn from_threat_score(score: f32) -> Self {
        match score as u8 {
            0..=3   => Severity::Low,
            4..=6   => Severity::Medium,
            7..=8   => Severity::High,
            _       => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    pub timestamp:    u64,   // Unix epoch ms
    pub src_ip:       String,
    pub dst_ip:       String,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub protocol:     String,
    pub action:       String, // BLOCK / ALLOW / THROTTLE
    pub threat_score: f32,
    pub threat_class: String,
    pub confidence:   f32,
    pub bytes_in:     u64,
    pub bytes_out:    u64,
    pub duration_ms:  u64,
    pub agent_id:     String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub timestamp:   u64,
    pub alert_id:    String,
    pub src_ip:      String,
    pub dst_ip:      String,
    pub rule_id:     String,
    pub description: String,
    pub severity:    u8,
    pub category:    String,
    pub payload_hex: Option<String>,
    pub agent_id:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetric {
    pub timestamp:   u64,
    pub agent_id:    String,
    pub cpu_pct:     f32,
    pub mem_pct:     f32,
    pub pps_in:      u64,   // packets per second inbound
    pub pps_out:     u64,
    pub bps_in:      u64,   // bytes per second inbound
    pub bps_out:     u64,
    pub active_conns: u32,
    pub blocked_ips:  u32,
}

enum LogEntry {
    Flow(FlowEvent),
    Alert(AlertEvent),
    Metric(SystemMetric),
}

// ── EventLogger ───────────────────────────────────────────────────────────────

pub struct EventLogger {
    ch_url:    String,
    ch_db:     String,
    redis_url: String,
    agent_id:  String,
    http:      reqwest::Client,
    tx:        mpsc::Sender<LogEntry>,
}

impl EventLogger {
    /// تهيئة logger مع قناة داخلية لإرسال الأحداث بشكل غير متزامن
    pub async fn new(
        clickhouse_url: &str,
        redis_url: &str,
        agent_id: &str,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let (tx, rx) = mpsc::channel::<LogEntry>(8192);

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        let logger = Arc::new(Self {
            ch_url:    clickhouse_url.trim_end_matches('/').to_string(),
            ch_db:     "thor".to_string(),
            redis_url: redis_url.to_string(),
            agent_id:  agent_id.to_string(),
            http,
            tx,
        });

        // تشغيل worker في الخلفية
        let logger_clone = Arc::clone(&logger);
        tokio::spawn(async move {
            logger_clone.background_worker(rx).await;
        });

        Ok(logger)
    }

    /// تسجيل حدث تدفق
    pub async fn log_flow(&self, event: FlowEvent) {
        let _ = self.tx.send(LogEntry::Flow(event)).await;
    }

    /// تسجيل تنبيه أمني
    pub async fn log_alert(&self, event: AlertEvent) {
        let _ = self.tx.send(LogEntry::Alert(event)).await;
    }

    /// تسجيل مقياس نظام
    pub async fn log_metric(&self, metric: SystemMetric) {
        let _ = self.tx.send(LogEntry::Metric(metric)).await;
    }

    /// الـ worker يُرسل الأحداث دفعات إلى ClickHouse + Redis
    async fn background_worker(&self, mut rx: mpsc::Receiver<LogEntry>) {
        let mut flow_batch:   Vec<FlowEvent>    = Vec::with_capacity(512);
        let mut alert_batch:  Vec<AlertEvent>   = Vec::with_capacity(64);
        let mut metric_batch: Vec<SystemMetric> = Vec::with_capacity(64);

        let mut interval = tokio::time::interval(
            std::time::Duration::from_millis(500)
        );

        loop {
            tokio::select! {
                Some(entry) = rx.recv() => {
                    match entry {
                        LogEntry::Flow(e)   => flow_batch.push(e),
                        LogEntry::Alert(e)  => alert_batch.push(e),
                        LogEntry::Metric(m) => metric_batch.push(m),
                    }
                    // فلاش فوري عند تجاوز الحد
                    if flow_batch.len() >= 500 {
                        self.flush_flows(&mut flow_batch).await;
                    }
                }
                _ = interval.tick() => {
                    // فلاش دوري كل 500ms
                    if !flow_batch.is_empty() {
                        self.flush_flows(&mut flow_batch).await;
                    }
                    if !alert_batch.is_empty() {
                        self.flush_alerts(&mut alert_batch).await;
                    }
                    if !metric_batch.is_empty() {
                        self.flush_metrics(&mut metric_batch).await;
                    }
                }
            }
        }
    }

    /// إرسال دفعة تدفقات إلى ClickHouse
    async fn flush_flows(&self, batch: &mut Vec<FlowEvent>) {
        if batch.is_empty() { return; }
        let rows: Vec<String> = batch.drain(..)
            .map(|e| format!(
                "({ts},{src_ip:?},{dst_ip:?},{src_p},{dst_p},{proto:?},{action:?},{ts_f:.4},{tc:?},{conf:.4},{bi},{bo},{dur},{aid:?})",
                ts=e.timestamp, src_ip=e.src_ip, dst_ip=e.dst_ip,
                src_p=e.src_port, dst_p=e.dst_port, proto=e.protocol,
                action=e.action, ts_f=e.threat_score, tc=e.threat_class,
                conf=e.confidence, bi=e.bytes_in, bo=e.bytes_out,
                dur=e.duration_ms, aid=e.agent_id,
            ))
            .collect();

        let insert_sql = format!(
            "INSERT INTO {}.flow_events \
            (timestamp,src_ip,dst_ip,src_port,dst_port,protocol,\
            action,threat_score,threat_class,confidence,\
            bytes_in,bytes_out,duration_ms,agent_id) VALUES {}",
            self.ch_db,
            rows.join(",")
        );

        let url = format!("{}/", self.ch_url);
        if let Err(e) = self.http.post(&url)
            .body(insert_sql)
            .send().await
        {
            log::error!("ClickHouse flow insert failed: {e}");
        }
    }

    /// إرسال دفعة تنبيهات إلى ClickHouse + نشر على Redis channel
    async fn flush_alerts(&self, batch: &mut Vec<AlertEvent>) {
        if batch.is_empty() { return; }

        for alert in batch.drain(..) {
            // نشر فوري عبر Redis pub/sub للـ real-time dashboard
            let payload = serde_json::to_string(&alert)
                .unwrap_or_default();
            self.redis_publish("thor:alerts", &payload).await;

            // أيضاً إرسال إلى ClickHouse للتحليل التاريخي
            let sql = format!(
                "INSERT INTO {}.alerts \
                (timestamp,alert_id,src_ip,dst_ip,rule_id,description,severity,category,agent_id) \
                VALUES ({},{:?},{:?},{:?},{:?},{:?},{},{:?},{:?})",
                self.ch_db,
                alert.timestamp, alert.alert_id, alert.src_ip, alert.dst_ip,
                alert.rule_id, alert.description, alert.severity,
                alert.category, alert.agent_id,
            );
            let url = format!("{}/", self.ch_url);
            if let Err(e) = self.http.post(&url).body(sql).send().await {
                log::error!("ClickHouse alert insert failed: {e}");
            }
        }
    }

    async fn flush_metrics(&self, batch: &mut Vec<SystemMetric>) {
        if batch.is_empty() { return; }
        let rows: Vec<String> = batch.drain(..)
            .map(|m| serde_json::to_string(&m).unwrap_or_default())
            .collect();
        // إرسال إلى Redis stream للـ time-series
        for row in &rows {
            self.redis_publish("thor:metrics", row).await;
        }
    }

    /// نشر رسالة على Redis channel (PUBLISH)
    async fn redis_publish(&self, channel: &str, message: &str) {
        let url = format!("{}/publish/{}/{}", self.redis_url, channel,
            urlencoding::encode(message));
        // ملاحظة: في الإنتاج استخدم redis crate مباشرة
        // هنا نستخدم HTTP للبساطة في المثال
        let _ = self.http.post(&url).send().await;
    }

    /// وقت Unix الحالي بالميلي ثانية
    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// ── اختبارات ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_score() {
        assert!(matches!(Severity::from_threat_score(2.0), Severity::Low));
        assert!(matches!(Severity::from_threat_score(5.0), Severity::Medium));
        assert!(matches!(Severity::from_threat_score(7.5), Severity::High));
        assert!(matches!(Severity::from_threat_score(9.9), Severity::Critical));
    }

    #[test]
    fn test_severity_as_u8() {
        assert_eq!(Severity::Low.as_u8(),      1);
        assert_eq!(Severity::Medium.as_u8(),   2);
        assert_eq!(Severity::High.as_u8(),     3);
        assert_eq!(Severity::Critical.as_u8(), 4);
    }

    #[test]
    fn test_now_ms_nonzero() {
        assert!(EventLogger::now_ms() > 0);
    }

    #[test]
    fn test_flow_event_serializes() {
        let ev = FlowEvent {
            timestamp: 1_700_000_000_000,
            src_ip: "192.168.1.1".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            src_port: 12345, dst_port: 443,
            protocol: "TCP".to_string(),
            action: "BLOCK".to_string(),
            threat_score: 8.5, threat_class: "syn_flood".to_string(),
            confidence: 0.92, bytes_in: 1024, bytes_out: 256,
            duration_ms: 100,
            agent_id: "thor-agent-01".to_string(),
        };
        let json = serde_json::to_string(&ev).expect("Serialization failed");
        assert!(json.contains("BLOCK"));
        assert!(json.contains("syn_flood"));
    }
}
