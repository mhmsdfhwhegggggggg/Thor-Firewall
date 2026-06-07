// Thor Firewall — Configuration Management
// إدارة الإعدادات مع Hot-Reload

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use config::{Config, ConfigError, File, FileFormat};
use serde::Deserialize;
use tokio::sync::{watch, RwLock};
use tracing::{info, warn};

use crate::flow_manager::FlowConfig;
use crate::rl_core::RLConfig;
use crate::packet_parser::ParserConfig;

#[cfg(target_os = "linux")]
use crate::linux::xdp_loader::LinuxConfig;

#[cfg(target_os = "windows")]
use crate::windows::wfp_io::WindowsConfig;

/// إعدادات gRPC
#[derive(Debug, Clone, Deserialize)]
pub struct GrpcConfig {
    pub host: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub ca_cert_path: Option<String>,
    /// حجم الـ buffer للرسائل (bytes)
    pub max_message_size: usize,
    /// مهلة الاتصال (ثوانٍ)
    pub connect_timeout_secs: u64,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 50051,
            tls_enabled: false,
            cert_path: None,
            key_path: None,
            ca_cert_path: None,
            max_message_size: 16 * 1024 * 1024,  // 16MB
            connect_timeout_secs: 30,
        }
    }
}

/// إعدادات Metrics
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    pub port: u16,
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            port: 9090,
            path: "/metrics".to_string(),
        }
    }
}

/// إعدادات Telemetry (OpenTelemetry)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TelemetryConfig {
    /// OTLP gRPC endpoint (فارغ = تعطيل)
    pub otlp_endpoint: String,
    pub service_name: String,
    pub service_version: String,
    /// معدل أخذ العينات (1.0 = كل شيء، 0.01 = 1%)
    pub trace_sample_rate: f64,
}

/// الإعداد الكامل للعميل
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// وضع التشغيل
    pub mode: AgentMode,
    pub instance_id: String,

    pub grpc: GrpcConfig,
    pub metrics: MetricsConfig,
    pub telemetry: TelemetryConfig,
    pub parser: ParserConfig,
    pub flow: FlowConfig,
    pub rl: RLConfig,

    #[cfg(target_os = "linux")]
    pub linux: LinuxConfig,

    #[cfg(target_os = "windows")]
    pub windows: WindowsConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum AgentMode {
    #[serde(rename = "enforcement")]
    Enforcement,
    #[serde(rename = "dry_run")]
    DryRun,
    #[serde(rename = "monitor")]
    Monitor,
}

/// تحميل الإعدادات من ملف TOML
pub fn load(path: &str) -> Result<AgentConfig> {
    let cfg = Config::builder()
        .add_source(File::new(path, FileFormat::Toml))
        // المتغيرات البيئية تُلغي ملف الإعداد
        .add_source(config::Environment::with_prefix("THOR").separator("__"))
        .build()
        .map_err(|e| anyhow::anyhow!("Configuration error: {}", e))?;

    let agent_cfg: AgentConfig = cfg.try_deserialize()
        .map_err(|e| anyhow::anyhow!("Configuration deserialization error: {}", e))?;

    info!(
        instance_id = %agent_cfg.instance_id,
        mode = ?agent_cfg.mode,
        "Configuration loaded successfully"
    );

    Ok(agent_cfg)
}

/// مراقب إعدادات مع Hot-Reload
pub struct ConfigWatcher {
    config_path: PathBuf,
    tx: watch::Sender<AgentConfig>,
    pub rx: watch::Receiver<AgentConfig>,
}

impl ConfigWatcher {
    pub fn new(config_path: &str, initial: AgentConfig) -> Self {
        let (tx, rx) = watch::channel(initial);
        Self {
            config_path: PathBuf::from(config_path),
            tx,
            rx,
        }
    }

    /// بدء مراقبة الملف لإعادة التحميل التلقائية
    pub async fn watch(self) {
        let path = self.config_path.clone();
        let tx = self.tx;

        tokio::spawn(async move {
            let mut last_modified = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok());

            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                let current_modified = std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok());

                if current_modified != last_modified {
                    info!("Configuration file changed, reloading...");
                    match load(path.to_str().unwrap_or("")) {
                        Ok(new_cfg) => {
                            let _ = tx.send(new_cfg);
                            info!("Configuration reloaded successfully");
                            last_modified = current_modified;
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to reload configuration — keeping current");
                        }
                    }
                }
            }
        });
    }
}
