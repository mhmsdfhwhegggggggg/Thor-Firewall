//! Thor Firewall — Wazuh Integration (Complete)
//! يدمج wazuh-client-rs بالكامل داخل Thor:
//!   • إدارة العملاء (agents): قائمة، إضافة، حذف، إيقاف، مزامنة
//!   • فحص الثغرات (vulnerability): جلب CVEs لكل عميل حسب الخطورة
//!   • الاستجابة النشطة (active_response): تشغيل أوامر حجب فورية
//!   • السجلات (logs): جلب أحدث سجلات Wazuh manager
//!   • القواعد (rules): تحميل وتصفية قواعد الكشف
//!   • الكلاستر (cluster): مراقبة حالة النودات
//!   • الإحصائيات (stats): عدد الأحداث، الحزم، التنبيهات
//!
//! الاستخدام:
//!   let wazuh = WazuhIntegration::connect("https://wazuh-manager:55000", "wazuh", "pass").await?;
//!   let agents = wazuh.list_agents().await?;
//!   wazuh.block_ip_on_all_agents("1.2.3.4").await?;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use serde::{Deserialize, Serialize};
use wazuh_client::{
    WazuhClientFactory, WazuhClients,
    Agent, AgentSummary, AgentAddBody,
    Vulnerability, VulnerabilitySeverity,
    ActiveResponseExecution,
    LogEntry,
    Rule,
    ClusterStatus, ManagerStatus,
};

// ── هياكل Thor-Wazuh ──────────────────────────────────────────────────────────

/// ملخص حالة Wazuh للعرض في Thor dashboard
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WazuhStatus {
    pub manager_version:      String,
    pub manager_status:       String,
    pub cluster_enabled:      bool,
    pub cluster_nodes:        u32,
    pub agents_total:         u32,
    pub agents_active:        u32,
    pub agents_disconnected:  u32,
    pub agents_never_connected: u32,
    pub last_sync_epoch:      u64,
}

/// ثغرة مُجمَّعة مع معلومات العميل
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVulnerability {
    pub agent_id:    String,
    pub agent_name:  String,
    pub agent_ip:    String,
    pub cve:         String,
    pub severity:    String,
    pub package:     String,
    pub version:     String,
    pub description: String,
    pub cvss3_score: Option<f32>,
    pub published:   Option<String>,
}

/// نتيجة تنفيذ أمر Active Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveResponseResult {
    pub agent_id:  String,
    pub command:   String,
    pub success:   bool,
    pub message:   String,
}

/// إحصائيات مباشرة من Wazuh
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WazuhStats {
    pub total_events_today:   u64,
    pub alerts_today:         u64,
    pub critical_alerts:      u32,
    pub high_alerts:          u32,
    pub active_agents:        u32,
    pub rules_loaded:         u32,
    pub decoders_loaded:      u32,
}

// ── WazuhIntegration ─────────────────────────────────────────────────────────

pub struct WazuhIntegration {
    clients:    WazuhClients,
    status:     Arc<RwLock<WazuhStatus>>,
    stats:      Arc<RwLock<WazuhStats>>,
    manager_url: String,
}

impl WazuhIntegration {
    /// الاتصال بـ Wazuh manager وتهيئة جميع العملاء
    pub async fn connect(
        manager_url: &str,
        username: &str,
        password: &str,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Connecting to Wazuh at {}...", manager_url);

        // إنشاء factory يتعامل مع JWT token تلقائياً
        let factory = WazuhClientFactory::new(manager_url, username, password)
            .map_err(|e| format!("Wazuh factory error: {e}"))?;

        let clients = factory.create_clients().await
            .map_err(|e| format!("Wazuh connect error: {e}"))?;

        let integration = Arc::new(Self {
            clients,
            status: Arc::new(RwLock::new(WazuhStatus::default())),
            stats:  Arc::new(RwLock::new(WazuhStats::default())),
            manager_url: manager_url.to_string(),
        });

        // جلب الحالة الأولية
        integration.refresh_status().await?;
        log::info!("✓ Wazuh integration connected to {}", manager_url);

        Ok(integration)
    }

    // ── إدارة العملاء (Agents) ───────────────────────────────────────────────

    /// جلب قائمة جميع العملاء
    pub async fn list_agents(&self) -> Result<Vec<Agent>, Box<dyn std::error::Error + Send + Sync>> {
        let agents = self.clients.agents_client
            .lock().await
            .get_all_agents(None, None, Some(500))
            .await
            .map_err(|e| format!("list_agents error: {e}"))?;
        log::debug!("Wazuh: {} agents retrieved", agents.len());
        Ok(agents)
    }

    /// جلب العملاء النشطين فقط
    pub async fn list_active_agents(&self) -> Result<Vec<Agent>, Box<dyn std::error::Error + Send + Sync>> {
        let all = self.list_agents().await?;
        Ok(all.into_iter().filter(|a| a.status == "active").collect())
    }

    /// جلب ملخص حالة العملاء
    pub async fn agent_summary(&self) -> Result<AgentSummary, Box<dyn std::error::Error + Send + Sync>> {
        self.clients.agents_client
            .lock().await
            .get_agents_summary_status()
            .await
            .map_err(|e| format!("agent_summary error: {e}").into())
    }

    /// إضافة عميل جديد
    pub async fn add_agent(
        &self,
        name: &str,
        ip: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let body = AgentAddBody {
            name: name.to_string(),
            ip: ip.map(|s| s.to_string()),
        };
        let key = self.clients.agents_client
            .lock().await
            .add_agent(&body)
            .await
            .map_err(|e| format!("add_agent error: {e}"))?;
        log::info!("Wazuh: agent '{}' added, id={}", name, key.id);
        Ok(key.id)
    }

    /// حذف عميل
    pub async fn delete_agent(
        &self,
        agent_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.clients.agents_client
            .lock().await
            .delete_agents(&[agent_id.to_string()], true)
            .await
            .map_err(|e| format!("delete_agent error: {e}").into())
    }

    /// إعادة تشغيل عميل
    pub async fn restart_agent(
        &self,
        agent_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.clients.agents_client
            .lock().await
            .restart_agent(agent_id)
            .await
            .map_err(|e| format!("restart_agent error: {e}").into())
    }

    // ── فحص الثغرات (Vulnerability) ─────────────────────────────────────────

    /// جلب جميع الثغرات لعميل معين
    pub async fn get_agent_vulnerabilities(
        &self,
        agent_id: &str,
        severity: Option<VulnerabilitySeverity>,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
        self.clients.vulnerability_client
            .lock().await
            .get_agent_vulnerabilities(agent_id, severity, None, None, Some(1000))
            .await
            .map_err(|e| format!("get_vulnerabilities error: {e}").into())
    }

    /// جلب الثغرات الحرجة (Critical + High) لجميع العملاء
    pub async fn get_critical_vulnerabilities(&self)
        -> Result<Vec<AgentVulnerability>, Box<dyn std::error::Error + Send + Sync>>
    {
        let agents = self.list_active_agents().await?;
        let mut results = Vec::new();

        for agent in &agents {
            // جلب Critical
            for sev in [VulnerabilitySeverity::Critical, VulnerabilitySeverity::High] {
                match self.get_agent_vulnerabilities(&agent.id, Some(sev)).await {
                    Ok(vulns) => {
                        for v in vulns {
                            results.push(AgentVulnerability {
                                agent_id:    agent.id.clone(),
                                agent_name:  agent.name.clone(),
                                agent_ip:    agent.ip.clone().unwrap_or_default(),
                                cve:         v.cve.clone().unwrap_or_default(),
                                severity:    format!("{:?}", sev),
                                package:     v.name.clone().unwrap_or_default(),
                                version:     v.version.clone().unwrap_or_default(),
                                description: v.title.clone().unwrap_or_default(),
                                cvss3_score: v.cvss3_score.and_then(|s| s.parse().ok()),
                                published:   v.published.clone(),
                            });
                        }
                    }
                    Err(e) => log::warn!("Vuln fetch failed for agent {}: {e}", agent.id),
                }
            }
        }

        log::info!("Wazuh: {} critical/high vulnerabilities found across {} agents",
            results.len(), agents.len());
        Ok(results)
    }

    // ── الاستجابة النشطة (Active Response) ──────────────────────────────────

    /// تشغيل أمر Active Response على عميل محدد
    pub async fn run_active_response(
        &self,
        agent_id: &str,
        command: &str,
        arguments: Vec<String>,
    ) -> Result<ActiveResponseResult, Box<dyn std::error::Error + Send + Sync>> {
        let execution = ActiveResponseExecution {
            command:   command.to_string(),
            arguments: arguments.clone(),
            alert:     None,
            custom:    Some(false),
        };

        let res = self.clients.active_response_client
            .lock().await
            .execute_command_on_agent(agent_id, command, Some(arguments), Some(false), None)
            .await;

        match res {
            Ok(_) => {
                log::info!("Active response '{}' executed on agent {}", command, agent_id);
                Ok(ActiveResponseResult {
                    agent_id:  agent_id.to_string(),
                    command:   command.to_string(),
                    success:   true,
                    message:   "Command executed successfully".to_string(),
                })
            }
            Err(e) => {
                log::error!("Active response failed on agent {}: {e}", agent_id);
                Ok(ActiveResponseResult {
                    agent_id:  agent_id.to_string(),
                    command:   command.to_string(),
                    success:   false,
                    message:   e.to_string(),
                })
            }
        }
    }

    /// حجب IP على جميع العملاء النشطين فوراً (firewall-drop)
    pub async fn block_ip_on_all_agents(
        &self,
        ip: &str,
    ) -> Result<Vec<ActiveResponseResult>, Box<dyn std::error::Error + Send + Sync>> {
        let agents = self.list_active_agents().await?;
        let mut results = Vec::new();

        log::warn!("🚨 Blocking IP {} on {} active agents via Wazuh Active Response", ip, agents.len());

        for agent in &agents {
            let result = self.run_active_response(
                &agent.id,
                "firewall-drop",
                vec!["-A".to_string(), ip.to_string()],
            ).await?;
            results.push(result);
        }

        let success_count = results.iter().filter(|r| r.success).count();
        log::info!("IP {} blocked on {}/{} agents", ip, success_count, agents.len());
        Ok(results)
    }

    /// رفع حجب IP
    pub async fn unblock_ip_on_all_agents(
        &self,
        ip: &str,
    ) -> Result<Vec<ActiveResponseResult>, Box<dyn std::error::Error + Send + Sync>> {
        let agents = self.list_active_agents().await?;
        let mut results = Vec::new();

        for agent in &agents {
            let result = self.run_active_response(
                &agent.id,
                "firewall-drop",
                vec!["-D".to_string(), ip.to_string()],
            ).await?;
            results.push(result);
        }
        Ok(results)
    }

    // ── السجلات (Logs) ───────────────────────────────────────────────────────

    /// جلب آخر N سجل من Wazuh manager
    pub async fn get_manager_logs(
        &self,
        limit: usize,
        level: Option<&str>,
    ) -> Result<Vec<LogEntry>, Box<dyn std::error::Error + Send + Sync>> {
        self.clients.logs_client
            .lock().await
            .get_logs(level, None, Some(limit as u32))
            .await
            .map_err(|e| format!("get_logs error: {e}").into())
    }

    // ── القواعد (Rules) ──────────────────────────────────────────────────────

    /// جلب قواعد الكشف مرتبة حسب المستوى
    pub async fn get_rules(
        &self,
        min_level: Option<u32>,
        limit: usize,
    ) -> Result<Vec<Rule>, Box<dyn std::error::Error + Send + Sync>> {
        let rules = self.clients.rules_client
            .lock().await
            .get_rules(None, None, Some(limit as u32))
            .await
            .map_err(|e| format!("get_rules error: {e}"))?;

        if let Some(min_lvl) = min_level {
            Ok(rules.into_iter()
                .filter(|r| r.level.unwrap_or(0) >= min_lvl)
                .collect())
        } else {
            Ok(rules)
        }
    }

    /// جلب القواعد ذات الأولوية العالية (مستوى >= 12)
    pub async fn get_high_priority_rules(&self) -> Result<Vec<Rule>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_rules(Some(12), 200).await
    }

    // ── الكلاستر (Cluster) ───────────────────────────────────────────────────

    /// جلب حالة الكلاستر
    pub async fn get_cluster_status(&self) -> Result<ClusterStatus, Box<dyn std::error::Error + Send + Sync>> {
        self.clients.cluster_client
            .lock().await
            .get_cluster_status()
            .await
            .map_err(|e| format!("cluster_status error: {e}").into())
    }

    /// جلب حالة الـ manager
    pub async fn get_manager_status(&self) -> Result<ManagerStatus, Box<dyn std::error::Error + Send + Sync>> {
        self.clients.cluster_client
            .lock().await
            .get_manager_status()
            .await
            .map_err(|e| format!("manager_status error: {e}").into())
    }

    // ── تحديث الحالة الداخلية ────────────────────────────────────────────────

    /// تحديث WazuhStatus من API
    pub async fn refresh_status(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // حالة الـ manager
        let manager_info = self.clients.cluster_client
            .lock().await
            .get_manager_info()
            .await
            .ok();

        // ملخص العملاء
        let summary = self.agent_summary().await.ok();

        let mut status = self.status.write().await;
        if let Some(info) = manager_info {
            status.manager_version = info.version.unwrap_or_default();
            status.manager_status  = "running".to_string();
        }
        if let Some(s) = summary {
            status.agents_total         = s.connection.total;
            status.agents_active        = s.connection.active;
            status.agents_disconnected  = s.connection.disconnected;
            status.agents_never_connected = s.connection.never_connected;
        }
        status.last_sync_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();

        Ok(())
    }

    /// جلب الحالة المخزّنة (بدون API call)
    pub async fn status(&self) -> WazuhStatus {
        self.status.read().await.clone()
    }

    // ── خلفية: تحديث تلقائي كل 60 ثانية ─────────────────────────────────────

    /// تشغيل worker خلفي يجلب الحالة والثغرات الحرجة دورياً
    pub fn start_background_sync(self: Arc<Self>) {
        let wazuh = Arc::clone(&self);
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                if let Err(e) = wazuh.refresh_status().await {
                    log::warn!("Wazuh status refresh failed: {e}");
                }
            }
        });

        // مزامنة الثغرات الحرجة كل 15 دقيقة
        let wazuh2 = Arc::clone(&self);
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(900));
            loop {
                ticker.tick().await;
                match wazuh2.get_critical_vulnerabilities().await {
                    Ok(vulns) => {
                        let mut stats = wazuh2.stats.write().await;
                        stats.critical_alerts = vulns.iter()
                            .filter(|v| v.severity == "Critical").count() as u32;
                        stats.high_alerts = vulns.iter()
                            .filter(|v| v.severity == "High").count() as u32;
                        log::info!("Wazuh vuln sync: {} critical, {} high",
                            stats.critical_alerts, stats.high_alerts);
                    }
                    Err(e) => log::warn!("Wazuh vuln sync failed: {e}"),
                }
            }
        });
    }
}

// ── اختبارات ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_vulnerability_serializes() {
        let v = AgentVulnerability {
            agent_id: "001".to_string(), agent_name: "server1".to_string(),
            agent_ip: "10.0.0.1".to_string(), cve: "CVE-2024-1234".to_string(),
            severity: "Critical".to_string(), package: "openssl".to_string(),
            version: "1.1.1t".to_string(),
            description: "Remote code execution".to_string(),
            cvss3_score: Some(9.8), published: Some("2024-01-15".to_string()),
        };
        let j = serde_json::to_string(&v).unwrap();
        assert!(j.contains("CVE-2024-1234"));
        assert!(j.contains("Critical"));
    }

    #[test]
    fn test_wazuh_status_default() {
        let s = WazuhStatus::default();
        assert_eq!(s.agents_active, 0);
        assert_eq!(s.cluster_nodes, 0);
    }

    #[test]
    fn test_active_response_result() {
        let r = ActiveResponseResult {
            agent_id: "001".to_string(),
            command: "firewall-drop".to_string(),
            success: true,
            message: "OK".to_string(),
        };
        assert!(r.success);
        assert_eq!(r.command, "firewall-drop");
    }

    #[tokio::test]
    async fn test_connect_fails_gracefully_on_bad_url() {
        let result = WazuhIntegration::connect(
            "https://localhost:19999", "admin", "wrong"
        ).await;
        assert!(result.is_err(), "Should fail with wrong URL");
    }
}
