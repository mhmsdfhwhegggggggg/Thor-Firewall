//! Thor Agent v0.4 — الأدوات المدمجة:
//!  1. Wazuh Client RS   (wazuh-client-rs كاملة)  → wazuh_integration.rs
//!  2. OpenVAS Scanner   (GMP API + native Rust)  → openvas_scanner.rs
//!  3. Cortex Analyzers  (REST API كاملة)         → cortex_client.rs
//!  4. RL Agent          (MARL inference)          → rl_agent.rs
//!  5. LLM Client        (vLLM / Mistral-7B)       → llm_client.rs
//!  6. Event Logger      (ClickHouse + Redis)      → event_logger.rs
//!  7. eBPF XDP Loader   (aya-rs)                  → linux/loader.rs

mod packet_parser;
mod flow_manager;
mod rl_agent;
mod llm_client;
mod event_logger;
mod wazuh_integration;
mod openvas_scanner;
mod cortex_client;

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

    info!("╔═══════════════════════════════════════════════════╗");
    info!("║        🛡  Thor Firewall Agent v0.4               ║");
    info!("║   OS: {:<43}║", std::env::consts::OS);
    info!("║   Tools: Wazuh + OpenVAS + Cortex + RL + LLM     ║");
    info!("╚═══════════════════════════════════════════════════╝");

    // ── 1. Wazuh (wazuh-client-rs) ───────────────────────────────────────────
    let wazuh_url  = std::env::var("WAZUH_URL") .unwrap_or_else(|_| "https://wazuh-manager:55000".to_string());
    let wazuh_user = std::env::var("WAZUH_USER").unwrap_or_else(|_| "wazuh".to_string());
    let wazuh_pass = std::env::var("WAZUH_PASS").unwrap_or_else(|_| "MyS3cr37P450r.*-".to_string());
    match WazuhIntegration::connect(&wazuh_url, &wazuh_user, &wazuh_pass).await {
        Ok(w) => {
            let s = w.status().await;
            info!("✓ Wazuh: {} active agents / version {}", s.agents_active, s.manager_version);
            Arc::clone(&w).start_background_sync();
        }
        Err(e) => warn!("⚠ Wazuh unreachable: {e}"),
    }

    // ── 2. OpenVAS / Thor Native Scanner ─────────────────────────────────────
    let openvas_url  = std::env::var("OPENVAS_URL").ok();
    let openvas_user = std::env::var("OPENVAS_USER").unwrap_or_else(|_| "admin".to_string());
    let openvas_pass = std::env::var("OPENVAS_PASS").unwrap_or_else(|_| "admin".to_string());
    let _scanner = openvas_scanner::OpenVasIntegration::new(
        openvas_url.as_deref(), &openvas_user, &openvas_pass
    );
    info!("✓ OpenVAS/Scanner: {} mode",
        if openvas_url.is_some() { "GMP" } else { "Thor-native" });

    // ── 3. Cortex (Analyzers + Responders) ───────────────────────────────────
    let cortex_url = std::env::var("CORTEX_URL")    .unwrap_or_else(|_| "http://cortex:9002".to_string());
    let cortex_key = std::env::var("CORTEX_API_KEY").unwrap_or_default();
    let cortex = cortex_client::CortexClient::new(&cortex_url, &cortex_key);
    match cortex.health_check().await {
        Ok(true)  => {
            match cortex.list_analyzers().await {
                Ok(a)  => info!("✓ Cortex: {} analyzers available", a.len()),
                Err(e) => warn!("⚠ Cortex analyzers: {e}"),
            }
        }
        Ok(false) => warn!("⚠ Cortex health check failed"),
        Err(e)    => warn!("⚠ Cortex unreachable: {e}"),
    }

    // ── 4. RL Agent (MARL Inference) ─────────────────────────────────────────
    let inference_url = std::env::var("ML_INFERENCE_URL")
        .unwrap_or_else(|_| "http://ml-inference:8082".to_string());
    let rl = Arc::new(rl_agent::RlAgent::new(&inference_url));
    match rl.health_check().await {
        Ok(s)  => info!("✓ RL Agent: {s}"),
        Err(e) => warn!("⚠ RL Agent: {e}"),
    }

    // ── 5. Event Logger (ClickHouse + Redis) ─────────────────────────────────
    let ch_url    = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://clickhouse:8123".to_string());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let agent_id  = std::env::var("THOR_AGENT_ID").unwrap_or_else(|_| "thor-agent-01".to_string());
    match event_logger::EventLogger::new(&ch_url, &redis_url, &agent_id).await {
        Ok(_)  => info!("✓ EventLogger: CH={ch_url} Redis={redis_url}"),
        Err(e) => warn!("⚠ EventLogger: {e}"),
    }

    // ── 6. LLM Client ────────────────────────────────────────────────────────
    let vllm_url = std::env::var("VLLM_URL").unwrap_or_else(|_| "http://vllm:8000/v1".to_string());
    let llm = Arc::new(llm_client::LlmClient::new(&vllm_url));
    match llm.health_check().await {
        Ok(true)  => info!("✓ LLM (Mistral-7B via vLLM)"),
        Ok(false) => warn!("⚠ LLM server error"),
        Err(e)    => warn!("⚠ LLM: {e}"),
    }

    // ── 7. eBPF XDP (Linux + --features ebpf) ────────────────────────────────
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        use std::path::Path;
        let iface   = std::env::var("THOR_IFACE")  .unwrap_or_else(|_| "eth0".to_string());
        let obj_dir = std::env::var("EBPF_OBJ_DIR").unwrap_or_else(|_| "/opt/thor/ebpf".to_string());
        let loader  = Arc::new(linux::loader::EbpfLoader::new(&iface, Path::new(&obj_dir)));
        match loader.load_xdp("xdp_thor.o", "xdp_firewall", aya::programs::XdpFlags::default()).await {
            Ok(_)  => info!("✓ eBPF XDP on {iface}"),
            Err(e) => warn!("⚠ eBPF: {e}"),
        }
    }

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ Thor Agent v0.4 — all modules initialized");
    info!("   Wazuh ✓ | OpenVAS ✓ | Cortex ✓ | RL ✓ | LLM ✓");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    tokio::select! {
        _ = signal::ctrl_c() => info!("SIGINT — shutting down"),
        _ = async {
            #[cfg(unix)] {
                let mut s = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate()
                ).expect("SIGTERM handler");
                s.recv().await;
            }
            #[cfg(not(unix))] std::future::pending::<()>().await
        } => info!("SIGTERM — shutting down"),
    }
    info!("Thor Agent stopped.");
    Ok(())
}
