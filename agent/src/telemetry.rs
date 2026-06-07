// Thor Firewall — Telemetry (OpenTelemetry + Prometheus)
// نظام المراقبة والقياس

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use prometheus::{
    register_counter, register_gauge, register_histogram,
    Counter, Gauge, Histogram, HistogramOpts, Registry,
};
use std::sync::OnceLock;

// ============================================================================
// Prometheus Metrics
// ============================================================================

pub struct ThorMetrics {
    // حزم
    pub packets_total: Counter,
    pub packets_dropped: Counter,
    pub packets_per_second: Gauge,

    // تدفقات
    pub flows_active: Gauge,
    pub flows_total: Counter,
    pub flows_blocked: Counter,
    pub flows_suspicious: Gauge,

    // ML
    pub ml_inference_duration: Histogram,
    pub ml_accuracy_gauge: Gauge,
    pub ml_false_positives: Counter,
    pub ml_false_negatives: Counter,

    // نظام
    pub ebpf_map_utilization: Gauge,
    pub agent_memory_bytes: Gauge,
    pub grpc_requests_total: Counter,
    pub grpc_errors_total: Counter,
}

static METRICS: OnceLock<ThorMetrics> = OnceLock::new();

pub fn metrics() -> &'static ThorMetrics {
    METRICS.get_or_init(|| {
        ThorMetrics {
            packets_total: register_counter!(
                "thor_packets_total",
                "Total packets processed by Thor Firewall"
            ).unwrap(),

            packets_dropped: register_counter!(
                "thor_packets_dropped_total",
                "Total packets dropped by Thor Firewall"
            ).unwrap(),

            packets_per_second: register_gauge!(
                "thor_packets_per_second",
                "Current packet processing rate"
            ).unwrap(),

            flows_active: register_gauge!(
                "thor_flows_active",
                "Number of active tracked flows"
            ).unwrap(),

            flows_total: register_counter!(
                "thor_flows_total",
                "Total flows seen since agent start"
            ).unwrap(),

            flows_blocked: register_counter!(
                "thor_flows_blocked_total",
                "Total flows blocked by AI decision"
            ).unwrap(),

            flows_suspicious: register_gauge!(
                "thor_flows_suspicious",
                "Flows currently under enhanced monitoring"
            ).unwrap(),

            ml_inference_duration: register_histogram!(
                HistogramOpts::new(
                    "thor_ml_inference_duration_seconds",
                    "ML inference duration in seconds"
                ).buckets(vec![0.0001, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5])
            ).unwrap(),

            ml_accuracy_gauge: register_gauge!(
                "thor_ml_accuracy",
                "Current ML model accuracy (rolling 1000 decisions)"
            ).unwrap(),

            ml_false_positives: register_counter!(
                "thor_ml_false_positives_total",
                "ML decisions that were incorrect (legitimate traffic blocked)"
            ).unwrap(),

            ml_false_negatives: register_counter!(
                "thor_ml_false_negatives_total",
                "ML decisions that missed attacks"
            ).unwrap(),

            ebpf_map_utilization: register_gauge!(
                "thor_ebpf_map_utilization",
                "BPF flow table utilization [0.0, 1.0]"
            ).unwrap(),

            agent_memory_bytes: register_gauge!(
                "thor_agent_memory_bytes",
                "Agent process memory usage in bytes"
            ).unwrap(),

            grpc_requests_total: register_counter!(
                "thor_grpc_requests_total",
                "Total gRPC requests received by agent"
            ).unwrap(),

            grpc_errors_total: register_counter!(
                "thor_grpc_errors_total",
                "Total gRPC request errors"
            ).unwrap(),
        }
    })
}

// ============================================================================
// Tracing Initialization
// ============================================================================

/// تهيئة نظام التسجيل والتتبع
pub fn init(verbosity: &u8) -> Result<()> {
    let log_level = match verbosity {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!(
            "thor_agent={},warn",
            log_level
        )));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true)
                .with_thread_ids(true)
        )
        .init();

    Ok(())
}

// ============================================================================
// Metrics HTTP Server
// ============================================================================

pub mod metrics_server {
    use anyhow::Result;
    use prometheus::TextEncoder;
    use tokio::net::TcpListener;
    use tracing::info;

    pub async fn start_server(port: u16) -> Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        info!(port = port, "Prometheus metrics server started");

        loop {
            let (mut stream, _) = listener.accept().await?;

            tokio::spawn(async move {
                let encoder = TextEncoder::new();
                let metric_families = prometheus::gather();
                let body = encoder.encode_to_string(&metric_families)
                    .unwrap_or_default();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );

                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    }
}
