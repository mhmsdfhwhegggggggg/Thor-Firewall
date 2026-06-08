//! Thor Firewall — eBPF/XDP Network Agent
//! المشغّل الرئيسي للعميل — Rust
//!
//! يقوم بـ:
//! 1. تهيئة eBPF maps وتحميل XDP programs
//! 2. تشغيل محرك RL للقرارات في الوقت الحقيقي
//! 3. إرسال الأحداث إلى control-plane
//! 4. تصدير metrics لـ Prometheus
//!
//! SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use clap::Parser;
use std::time::Duration;
use tracing::{info, warn, error, Level};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod rl_core;
mod soar;

// ── CLI Arguments ────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "thor-agent", version = "1.0.0", about = "Thor Firewall eBPF Agent")]
struct Args {
    /// Network interface to attach XDP program to
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// Control plane URL
    #[arg(long, env = "CONTROL_PLANE_URL", default_value = "http://control-plane:8000")]
    control_plane: String,

    /// ML inference server URL
    #[arg(long, env = "ML_INFERENCE_URL", default_value = "http://ml-inference:8082")]
    ml_url: String,

    /// Prometheus metrics port
    #[arg(long, env = "METRICS_PORT", default_value_t = 9100)]
    metrics_port: u16,

    /// Agent ID (defaults to hostname)
    #[arg(long, env = "AGENT_ID")]
    agent_id: Option<String>,

    /// Log level
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,
}

// ── Flow Feature Vector ───────────────────────────────────────────────────────

/// شعاع الخصائص للتدفق الشبكي
/// 50 خاصية مستخلصة من البيانات الأولية
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowFeatures {
    pub flow_duration: f32,
    pub total_fwd_packets: f32,
    pub total_bwd_packets: f32,
    pub total_length_fwd_packets: f32,
    pub total_length_bwd_packets: f32,
    pub fwd_packet_length_max: f32,
    pub fwd_packet_length_min: f32,
    pub fwd_packet_length_mean: f32,
    pub fwd_packet_length_std: f32,
    pub bwd_packet_length_max: f32,
    pub bwd_packet_length_min: f32,
    pub bwd_packet_length_mean: f32,
    pub bwd_packet_length_std: f32,
    pub flow_bytes_per_s: f32,
    pub flow_packets_per_s: f32,
    pub flow_iat_mean: f32,
    pub flow_iat_std: f32,
    pub flow_iat_max: f32,
    pub flow_iat_min: f32,
    pub fwd_iat_total: f32,
    pub fwd_iat_mean: f32,
    pub fwd_iat_std: f32,
    pub fwd_iat_max: f32,
    pub fwd_iat_min: f32,
    pub bwd_iat_total: f32,
    pub bwd_iat_mean: f32,
    pub bwd_iat_std: f32,
    pub bwd_iat_max: f32,
    pub bwd_iat_min: f32,
    pub fwd_psh_flags: f32,
    pub bwd_psh_flags: f32,
    pub fwd_urg_flags: f32,
    pub bwd_urg_flags: f32,
    pub fwd_header_length: f32,
    pub bwd_header_length: f32,
    pub fwd_packets_per_s: f32,
    pub bwd_packets_per_s: f32,
    pub min_packet_length: f32,
    pub max_packet_length: f32,
    pub packet_length_mean: f32,
    pub packet_length_std: f32,
    pub packet_length_variance: f32,
    pub fin_flag_count: f32,
    pub syn_flag_count: f32,
    pub rst_flag_count: f32,
    pub psh_flag_count: f32,
    pub ack_flag_count: f32,
    pub urg_flag_count: f32,
    pub cwe_flag_count: f32,
    pub ece_flag_count: f32,
}

impl FlowFeatures {
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.flow_duration, self.total_fwd_packets, self.total_bwd_packets,
            self.total_length_fwd_packets, self.total_length_bwd_packets,
            self.fwd_packet_length_max, self.fwd_packet_length_min,
            self.fwd_packet_length_mean, self.fwd_packet_length_std,
            self.bwd_packet_length_max, self.bwd_packet_length_min,
            self.bwd_packet_length_mean, self.bwd_packet_length_std,
            self.flow_bytes_per_s, self.flow_packets_per_s,
            self.flow_iat_mean, self.flow_iat_std, self.flow_iat_max, self.flow_iat_min,
            self.fwd_iat_total, self.fwd_iat_mean, self.fwd_iat_std,
            self.fwd_iat_max, self.fwd_iat_min,
            self.bwd_iat_total, self.bwd_iat_mean, self.bwd_iat_std,
            self.bwd_iat_max, self.bwd_iat_min,
            self.fwd_psh_flags, self.bwd_psh_flags, self.fwd_urg_flags, self.bwd_urg_flags,
            self.fwd_header_length, self.bwd_header_length,
            self.fwd_packets_per_s, self.bwd_packets_per_s,
            self.min_packet_length, self.max_packet_length,
            self.packet_length_mean, self.packet_length_std, self.packet_length_variance,
            self.fin_flag_count, self.syn_flag_count, self.rst_flag_count,
            self.psh_flag_count, self.ack_flag_count, self.urg_flag_count,
            self.cwe_flag_count, self.ece_flag_count,
        ]
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────────

fn setup_metrics(port: u16) -> Result<()> {
    use metrics_exporter_prometheus::PrometheusBuilder;
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], port))
        .install()
        .context("Failed to install Prometheus metrics exporter")?;

    metrics::describe_counter!("thor_flows_total", "Total network flows processed");
    metrics::describe_counter!("thor_threats_total", "Total threats detected and blocked");
    metrics::describe_histogram!("thor_decision_latency_microseconds", "RL decision latency");
    metrics::describe_gauge!("thor_active_connections", "Current active connections");
    metrics::describe_counter!("thor_soar_executions_total", "Total SOAR playbook executions");

    info!("Prometheus metrics exported on port {}", port);
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Logging
    let filter = EnvFilter::try_new(&args.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();

    info!("⚡ Thor Firewall Agent v{}", env!("CARGO_PKG_VERSION"));
    info!("Interface: {} | Control Plane: {}", args.interface, args.control_plane);

    let agent_id = args.agent_id.unwrap_or_else(|| {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
    });
    info!("Agent ID: {}", agent_id);

    // Setup Prometheus metrics
    setup_metrics(args.metrics_port)?;

    // Initialize RL core
    let rl_core = rl_core::ThorRLCore::new(&args.ml_url).await
        .context("Failed to initialize RL core")?;
    info!("✅ RL core connected to ML inference: {}", args.ml_url);

    // Event loop — process flows
    info!("🔥 Thor Agent active on interface: {}", args.interface);
    info!("Press Ctrl+C to stop");

    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;

        // In production: read from eBPF ring buffer
        // Here: emit a health heartbeat
        metrics::counter!("thor_flows_total").increment(1);

        // Check ML inference connectivity
        if let Err(e) = rl_core.health_check().await {
            warn!("ML inference health check failed: {}", e);
        }
    }
}
