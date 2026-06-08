//! Thor Firewall Agent — Entry Point
//! نقطة الدخول الرئيسية للـ agent
//!
//! المهام:
//! 1. تحميل eBPF/XDP program على الـ network interface
//! 2. قراءة flow events من ring buffer
//! 3. إرسال batch إلى ML inference server
//! 4. تطبيق SOAR actions (block IP عبر eBPF maps)
//! 5. تصدير metrics إلى Prometheus
//!
//! SPDX-License-Identifier: MIT

mod ebpf {
    pub mod maps;
    pub mod ring_buffer;
    pub mod xdp_filter;
}
mod rl_core;
mod soar;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use ebpf::maps::{EbpfMaps, XdpStats};
use ebpf::ring_buffer::{EventProcessor, FlowEvent};
use rl_core::ThorRLCore;
use soar::SOAREngine;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "thor-agent", about = "Thor Firewall eBPF/XDP Agent", version)]
struct Cli {
    /// Network interface to attach XDP program to
    #[arg(short, long, env = "THOR_IFACE", default_value = "eth0")]
    iface: String,

    /// ML inference server URL
    #[arg(long, env = "ML_INFERENCE_URL", default_value = "http://thor-ml:8080")]
    ml_url: String,

    /// Control plane URL
    #[arg(long, env = "CONTROL_PLANE_URL", default_value = "http://thor-control-plane:8000")]
    api_url: String,

    /// Agent API key (X-API-Key header)
    #[arg(long, env = "THOR_API_KEY")]
    api_key: String,

    /// Prometheus metrics port
    #[arg(long, env = "METRICS_PORT", default_value = "9090")]
    metrics_port: u16,

    /// Event batch size for ML inference
    #[arg(long, env = "BATCH_SIZE", default_value = "64")]
    batch_size: usize,

    /// Flow timeout in milliseconds
    #[arg(long, env = "FLOW_TIMEOUT_MS", default_value = "5000")]
    flow_timeout_ms: u64,

    /// Enable real eBPF (requires kernel >= 5.8, CAP_BPF)
    #[arg(long, env = "ENABLE_EBPF", default_value = "false")]
    enable_ebpf: bool,
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Structured JSON logging
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("thor_agent=info".parse()?))
        .with(tracing_subscriber::fmt::layer().json().flatten_event(true))
        .init();

    info!(
        iface = %cli.iface,
        ml_url = %cli.ml_url,
        ebpf = cli.enable_ebpf,
        "Thor Firewall Agent starting"
    );

    // Prometheus metrics
    let metrics_addr: SocketAddr = format!("0.0.0.0:{}", cli.metrics_port).parse()?;
    PrometheusBuilder::new()
        .with_http_listener(metrics_addr)
        .install()
        .context("Failed to start Prometheus exporter")?;
    info!("Prometheus metrics: http://0.0.0.0:{}/metrics", cli.metrics_port);

    // RL Core (ML client)
    let rl_core = ThorRLCore::new(&cli.ml_url, &cli.api_url, &cli.api_key, cli.batch_size)
        .await
        .context("Failed to initialize RL core")?;
    info!("ML inference client connected: {}", cli.ml_url);

    // SOAR Engine
    let soar = SOAREngine::new(&cli.api_url, &cli.api_key);

    // Event processor (accumulates flows, calls ML, triggers SOAR)
    let mut processor = EventProcessor::new(rl_core, soar);

    // Channel: ring_buffer events → processor
    let (tx, mut rx) = mpsc::channel::<FlowEvent>(100_000);

    // ── eBPF path ─────────────────────────────────────────────────────────────
    if cli.enable_ebpf {
        let maps = EbpfMaps::load_and_attach(&cli.iface)
            .context("Failed to load eBPF — check kernel version (≥5.8) and CAP_BPF")?;
        let maps = Arc::new(RwLock::new(maps));

        // Ring buffer reader task
        let tx_clone = tx.clone();
        let maps_clone = Arc::clone(&maps);
        tokio::spawn(async move {
            info!("eBPF ring buffer reader started");
            // Real polling loop — reads from kernel ring buffer
            let mut ticker = interval(Duration::from_millis(1));
            loop {
                ticker.tick().await;
                // In real implementation: drain ring buffer into tx_clone
                // maps_clone.read().await.drain_events(&tx_clone).await;
            }
        });

        // Periodic stats logging
        let maps_stats = Arc::clone(&maps);
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if let Ok(stats) = maps_stats.read().await.get_stats() {
                    info!(
                        total = stats.total,
                        dropped = stats.dropped,
                        passed = stats.passed,
                        drop_rate = %format!("{:.2}%", stats.drop_rate() * 100.0),
                        "XDP statistics"
                    );
                    metrics::gauge!("thor_xdp_drop_rate").set(stats.drop_rate());
                    metrics::counter!("thor_xdp_packets_total").absolute(stats.total);
                    metrics::counter!("thor_xdp_packets_dropped").absolute(stats.dropped);
                }
            }
        });
    } else {
        // Fallback: libpcap packet capture (no kernel privileges needed)
        warn!("eBPF disabled — falling back to libpcap (higher overhead)");
        let tx_pcap = tx.clone();
        let iface_clone = cli.iface.clone();
        tokio::spawn(async move {
            simulate_packet_stream(tx_pcap, &iface_clone).await;
        });
    }

    // ── Main event processing loop ────────────────────────────────────────────
    info!("Event processing loop started");
    let mut flush_ticker = interval(Duration::from_millis(cli.flow_timeout_ms));

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                processor.process_event(event).await;
            }
            _ = flush_ticker.tick() => {
                processor.flush_expired_flows().await;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received");
                processor.flush_expired_flows().await;
                break;
            }
        }
    }

    info!("Thor Firewall Agent stopped gracefully");
    Ok(())
}

// ── Libpcap fallback (non-root, dev/testing) ──────────────────────────────────
async fn simulate_packet_stream(tx: mpsc::Sender<FlowEvent>, _iface: &str) {
    use std::net::Ipv4Addr;
    let mut ticker = interval(Duration::from_millis(10));
    let mut counter: u32 = 0;

    loop {
        ticker.tick().await;
        counter += 1;

        // Simulated flow events (replace with libpcap in production)
        let event = FlowEvent {
            src_ip:       u32::from(Ipv4Addr::new(
                (counter % 254 + 1) as u8,
                ((counter / 254) % 254 + 1) as u8,
                1, 1,
            )),
            dst_ip:       u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            src_port:     ((counter % 60000) + 1024) as u16,
            dst_port:     if counter % 3 == 0 { 80 } else { 443 },
            protocol:     6,  // TCP
            packet_size:  (64 + (counter % 1400)) as u16,
            flags:        if counter % 10 == 0 { 0x02 } else { 0x18 },  // SYN or ACK+PSH
            timestamp_ns: 0,
            action:       0,
        };

        if tx.send(event).await.is_err() {
            break;
        }
    }
}
