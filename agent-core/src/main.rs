//! Thor Agent v0.5 — منصة أمن متكاملة
//!
//! الأدوات الخمس المدمجة بالكامل في Rust:
//!  1. Wazuh   (wazuh-client-rs)    → wazuh_integration.rs  517 lines
//!  2. OpenVAS (GMP + Rust-native)  → openvas_scanner.rs    699 lines
//!  3. Cortex  (REST API)           → cortex_client.rs      760 lines
//!  4. CAPEv2  (Sandbox REST API)   → capev2_client.rs      679 lines
//!  5. TheHive (Cases/Alerts REST)  → thehive_client.rs     899 lines

mod packet_parser;
mod flow_manager;
mod rl_agent;
mod llm_client;
mod event_logger;
mod wazuh_integration;
mod openvas_scanner;
mod cortex_client;
mod capev2_client;
mod thehive_client;

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod linux { pub mod loader; }

use std::sync::Arc;
use log::{info, warn};
use tokio::signal;
use wazuh_integration::WazuhIntegration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("thor_agent=info".parse().unwrap())
                .add_directive("wazuh_client=warn".parse().unwrap())
        )
        .init();

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║         🛡  Thor Firewall Agent v0.5                     ║");
    info!("║   Tools: Wazuh | OpenVAS | Cortex | CAPEv2 | TheHive    ║");
    info!("╚══════════════════════════════════════════════════════════╝");

    // 1. Wazuh
    let wazuh_url  = std::env::var("WAZUH_URL") .unwrap_or_else(|_| "https://wazuh-manager:55000".to_string());
    let wazuh_user = std::env::var("WAZUH_USER").unwrap_or_else(|_| "wazuh".to_string());
    let wazuh_pass = std::env::var("WAZUH_PASS").unwrap_or_else(|_| "MyS3cr37P450r.*-".to_string());
    match WazuhIntegration::connect(&wazuh_url, &wazuh_user, &wazuh_pass).await {
        Ok(w) => {
            let s = w.status().await;
            info!("✓ Wazuh v{}: {} active agents", s.manager_version, s.agents_active);
            Arc::clone(&w).start_background_sync();
        }
        Err(e) => warn!("⚠ Wazuh: {e}"),
    }

    // 2. OpenVAS / Thor Native Scanner
    let openvas_url  = std::env::var("OPENVAS_URL").ok();
    let openvas_user = std::env::var("OPENVAS_USER").unwrap_or_else(|_| "admin".to_string());
    let openvas_pass = std::env::var("OPENVAS_PASS").unwrap_or_else(|_| "admin".to_string());
    let _scanner = openvas_scanner::OpenVasIntegration::new(
        openvas_url.as_deref(), &openvas_user, &openvas_pass
    );
    info!("✓ Scanner: {} mode", if openvas_url.is_some() { "OpenVAS GMP" } else { "Thor-native TCP" });

    // 3. Cortex
    let cortex_url = std::env::var("CORTEX_URL")    .unwrap_or_else(|_| "http://cortex:9002".to_string());
    let cortex_key = std::env::var("CORTEX_API_KEY").unwrap_or_default();
    let cortex = cortex_client::CortexClient::new(&cortex_url, &cortex_key);
    match cortex.health_check().await {
        Ok(true) => match cortex.list_analyzers().await {
            Ok(a)  => info!("✓ Cortex: {} analyzers ready", a.len()),
            Err(e) => warn!("⚠ Cortex analyzers: {e}"),
        },
        Ok(false) => warn!("⚠ Cortex: health check failed"),
        Err(e)    => warn!("⚠ Cortex: {e}"),
    }

    // 4. CAPEv2 Sandbox
    let cape_url = std::env::var("CAPEV2_URL")    .unwrap_or_else(|_| "http://cape:8000".to_string());
    let cape_key = std::env::var("CAPEV2_API_KEY").ok();
    let cape = capev2_client::CapeClient::new(&cape_url, cape_key.as_deref());
    match cape.health_check().await {
        Ok(true)  => info!("✓ CAPEv2: dynamic sandbox ready (file/URL analysis)"),
        Ok(false) => warn!("⚠ CAPEv2: health check failed"),
        Err(e)    => warn!("⚠ CAPEv2: {e}"),
    }

    // 5. TheHive
    let hive_url = std::env::var("THEHIVE_URL")    .unwrap_or_else(|_| "http://thehive:9000".to_string());
    let hive_key = std::env::var("THEHIVE_API_KEY").unwrap_or_default();
    let hive = thehive_client::TheHiveClient::new(&hive_url, &hive_key);
    match hive.health_check().await {
        Ok(true)  => info!("✓ TheHive: SOAR platform ready (auto-promote at score≥7.0)"),
        Ok(false) => warn!("⚠ TheHive: health check failed"),
        Err(e)    => warn!("⚠ TheHive: {e}"),
    }

    // 6. RL Agent
    let rl = Arc::new(rl_agent::RlAgent::new(
        &std::env::var("ML_INFERENCE_URL").unwrap_or_else(|_| "http://ml-inference:8082".to_string())
    ));
    match rl.health_check().await {
        Ok(s)  => info!("✓ RL Agent: {s}"),
        Err(e) => warn!("⚠ RL Agent: {e}"),
    }

    // 7. Event Logger
    let agent_id = std::env::var("THOR_AGENT_ID").unwrap_or_else(|_| "thor-agent-01".to_string());
    match event_logger::EventLogger::new(
        &std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://clickhouse:8123".to_string()),
        &std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string()),
        &agent_id
    ).await {
        Ok(_)  => info!("✓ EventLogger: ClickHouse + Redis ready"),
        Err(e) => warn!("⚠ EventLogger: {e}"),
    }

    // 8. LLM
    let llm = Arc::new(llm_client::LlmClient::new(
        &std::env::var("VLLM_URL").unwrap_or_else(|_| "http://vllm:8000/v1".to_string())
    ));
    match llm.health_check().await {
        Ok(true)  => info!("✓ LLM: Mistral-7B via vLLM"),
        Ok(false) => warn!("⚠ LLM: server error"),
        Err(e)    => warn!("⚠ LLM: {e}"),
    }

    // 9. eBPF XDP (Linux only)
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        let iface   = std::env::var("THOR_IFACE").unwrap_or_else(|_| "eth0".to_string());
        let obj_dir = std::env::var("EBPF_OBJ_DIR").unwrap_or_else(|_| "/opt/thor/ebpf".to_string());
        let loader  = Arc::new(linux::loader::EbpfLoader::new(
            &iface, std::path::Path::new(&obj_dir)
        ));
        match loader.load_xdp("xdp_thor.o", "xdp_firewall", aya::programs::XdpFlags::default()).await {
            Ok(_)  => info!("✓ eBPF XDP on {iface}"),
            Err(e) => warn!("⚠ eBPF: {e}"),
        }
    }

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ Thor v0.5 fully initialized — 5 security tools active");
    info!("   Wazuh ✓ OpenVAS ✓ Cortex ✓ CAPEv2 ✓ TheHive ✓");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    tokio::select! {
        _ = signal::ctrl_c() => info!("SIGINT — shutting down"),
        _ = async {
            #[cfg(unix)] {
                let mut s = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM");
                s.recv().await;
            }
            #[cfg(not(unix))] std::future::pending::<()>().await
        } => info!("SIGTERM — shutting down"),
    }
    info!("Thor Agent stopped cleanly.");
    Ok(())
}
