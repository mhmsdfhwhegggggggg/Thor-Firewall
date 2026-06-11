//! Thor Agent — نقطة دخول موحدة v0.3
//! يُهيئ: Wazuh + OpenVAS Scanner + RL Agent + LLM + Event Logger
//! الأدوات المدموجة: wazuh-client-rs (كاملة) + openvas_scanner (GMP+native)

mod packet_parser;
mod flow_manager;
mod rl_agent;
mod llm_client;
mod event_logger;
mod wazuh_integration;
mod openvas_scanner;

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

    info!("╔══════════════════════════════════════════╗");
    info!("║      🛡  Thor Firewall Agent v0.3         ║");
    info!("║   OS: {:<34}║", std::env::consts::OS);
    info!("╚══════════════════════════════════════════╝");

    // ── 1. Wazuh Integration (wazuh-client-rs كاملة) ─────────────────────────
    let wazuh_url  = std::env::var("WAZUH_URL").unwrap_or_else(|_| "https://wazuh-manager:55000".to_string());
    let wazuh_user = std::env::var("WAZUH_USER").unwrap_or_else(|_| "wazuh".to_string());
    let wazuh_pass = std::env::var("WAZUH_PASS").unwrap_or_else(|_| "MyS3cr37P450r.*-".to_string());
    let wazuh: Option<Arc<WazuhIntegration>> = match WazuhIntegration::connect(
        &wazuh_url, &wazuh_user, &wazuh_pass
    ).await {
        Ok(w) => {
            let s = w.status().await;
            info!("✓ Wazuh: {} agents active ({})", s.agents_active, s.manager_version);
            Arc::clone(&w).start_background_sync();
            Some(w)
        }
        Err(e) => { warn!("⚠ Wazuh: {e}"); None }
    };

    // ── 2. OpenVAS / Thor Native Scanner ─────────────────────────────────────
    let openvas_url  = std::env::var("OPENVAS_URL").ok();
    let openvas_user = std::env::var("OPENVAS_USER").unwrap_or_else(|_| "admin".to_string());
    let openvas_pass = std::env::var("OPENVAS_PASS").unwrap_or_else(|_| "admin".to_string());
    let scanner = openvas_scanner::OpenVasIntegration::new(
        openvas_url.as_deref(), &openvas_user, &openvas_pass
    );
    match openvas_url {
        Some(ref u) => info!("✓ OpenVAS GMP: {}", u),
        None        => info!("⚡ Thor Native Scanner ready (OpenVAS_URL not set — native TCP mode)"),
    }

    // ── 3. ML Inference (RL Agent) ───────────────────────────────────────────
    let inference_url = std::env::var("ML_INFERENCE_URL")
        .unwrap_or_else(|_| "http://ml-inference:8082".to_string());
    let rl = Arc::new(rl_agent::RlAgent::new(&inference_url));
    match rl.health_check().await {
        Ok(s)  => info!("✓ ML Inference: {s}"),
        Err(e) => warn!("⚠ ML Inference: {e}"),
    }

    // ── 4. Event Logger (ClickHouse + Redis) ─────────────────────────────────
    let ch_url    = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://clickhouse:8123".to_string());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let agent_id  = std::env::var("THOR_AGENT_ID").unwrap_or_else(|_| "thor-agent-01".to_string());
    match event_logger::EventLogger::new(&ch_url, &redis_url, &agent_id).await {
        Ok(_)  => info!("✓ Event Logger: CH={} Redis={}", ch_url, redis_url),
        Err(e) => warn!("⚠ Event Logger: {e}"),
    }

    // ── 5. LLM Client (Mistral-7B via vLLM) ─────────────────────────────────
    let vllm_url = std::env::var("VLLM_URL")
        .unwrap_or_else(|_| "http://vllm:8000/v1".to_string());
    let llm = Arc::new(llm_client::LlmClient::new(&vllm_url));
    match llm.health_check().await {
        Ok(true)  => info!("✓ LLM (vLLM/Mistral-7B) ready"),
        Ok(false) => warn!("⚠ LLM server error"),
        Err(e)    => warn!("⚠ LLM: {e}"),
    }

    // ── 6. eBPF XDP (Linux + --features ebpf) ────────────────────────────────
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        use std::path::Path;
        let iface   = std::env::var("THOR_IFACE").unwrap_or_else(|_| "eth0".to_string());
        let obj_dir = std::env::var("EBPF_OBJ_DIR").unwrap_or_else(|_| "/opt/thor/ebpf".to_string());
        let loader  = Arc::new(linux::loader::EbpfLoader::new(&iface, Path::new(&obj_dir)));
        match loader.load_xdp("xdp_thor.o", "xdp_firewall",
                               aya::programs::XdpFlags::default()).await {
            Ok(_)  => info!("✓ eBPF XDP on {}", iface),
            Err(e) => warn!("⚠ eBPF: {e}"),
        }
    }

    info!("✅ Thor Agent v0.3 — all modules initialized and ready");
    info!("   Modules: Wazuh + OpenVAS/Scanner + RL + LLM + EventLogger + eBPF");

    tokio::select! {
        _ = signal::ctrl_c() => info!("SIGINT — shutting down"),
        _ = async {
            #[cfg(unix)] {
                let mut s = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate()
                ).expect("SIGTERM handler failed");
                s.recv().await;
            }
            #[cfg(not(unix))] std::future::pending::<()>().await
        } => info!("SIGTERM — shutting down"),
    }
    info!("Thor Agent stopped.");
    Ok(())
}
