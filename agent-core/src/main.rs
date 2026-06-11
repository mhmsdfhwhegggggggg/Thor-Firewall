//! Thor Agent — نقطة دخول موحدة
//! يُهيئ: Wazuh Integration + RL Agent + LLM Client + eBPF Capture
//!
//! التشغيل: cargo run --release
//! مع Wazuh: WAZUH_URL=https://wazuh:55000 WAZUH_USER=wazuh WAZUH_PASS=secret cargo run

mod packet_parser;
mod flow_manager;
mod rl_agent;
mod llm_client;
mod event_logger;
mod wazuh_integration;

#[cfg(feature = "ebpf")]
#[cfg(target_os = "linux")]
mod linux { pub mod loader; }

use std::sync::Arc;
use log::{info, warn, error};
use tokio::signal;
use wazuh_integration::WazuhIntegration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // تهيئة السجلات
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("thor_agent=info".parse().unwrap())
                .add_directive("wazuh_client=warn".parse().unwrap())
        )
        .init();

    info!("╔══════════════════════════════════════════╗");
    info!("║       🛡  Thor Firewall Agent v0.2        ║");
    info!("║   OS: {:<34}║", std::env::consts::OS);
    info!("╚══════════════════════════════════════════╝");

    // ── 1. Wazuh Integration (أول مكوّن يُشغَّل) ────────────────────────────
    let wazuh_url  = std::env::var("WAZUH_URL").unwrap_or_else(|_| "https://wazuh-manager:55000".to_string());
    let wazuh_user = std::env::var("WAZUH_USER").unwrap_or_else(|_| "wazuh".to_string());
    let wazuh_pass = std::env::var("WAZUH_PASS").unwrap_or_else(|_| "MyS3cr37P450r.*-".to_string());

    let wazuh: Option<Arc<WazuhIntegration>> = match WazuhIntegration::connect(
        &wazuh_url, &wazuh_user, &wazuh_pass
    ).await {
        Ok(w) => {
            let status = w.status().await;
            info!("✓ Wazuh: {} agents active ({})",
                status.agents_active, status.manager_version);
            // تشغيل مزامنة خلفية تلقائية كل 60 ثانية
            Arc::clone(&w).start_background_sync();
            Some(w)
        }
        Err(e) => {
            warn!("⚠ Wazuh not reachable: {e} — continuing without Wazuh");
            None
        }
    };

    // ── 2. RL Agent (inference_server) ──────────────────────────────────────
    let inference_url = std::env::var("ML_INFERENCE_URL")
        .unwrap_or_else(|_| "http://ml-inference:8082".to_string());
    info!("ML Inference URL: {}", inference_url);
    let rl = Arc::new(rl_agent::RlAgent::new(&inference_url));

    // فحص صحة inference server
    match rl.health_check().await {
        Ok(s) => info!("✓ ML Inference: {s}"),
        Err(e) => warn!("⚠ ML Inference not ready: {e}"),
    }

    // ── 3. Event Logger (ClickHouse + Redis) ─────────────────────────────────
    let ch_url    = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://clickhouse:8123".to_string());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    let agent_id  = std::env::var("THOR_AGENT_ID").unwrap_or_else(|_| "thor-agent-01".to_string());

    let logger = match event_logger::EventLogger::new(&ch_url, &redis_url, &agent_id).await {
        Ok(l) => { info!("✓ Event Logger ready"); Some(l) }
        Err(e) => { warn!("⚠ Event Logger: {e}"); None }
    };

    // ── 4. LLM Client (Mistral-7B via vLLM) ─────────────────────────────────
    let vllm_url = std::env::var("VLLM_URL")
        .unwrap_or_else(|_| "http://vllm:8000/v1".to_string());
    let llm = Arc::new(llm_client::LlmClient::new(&vllm_url));
    match llm.health_check().await {
        Ok(true)  => info!("✓ LLM (vLLM/Mistral-7B) ready"),
        Ok(false) => warn!("⚠ LLM server returned error status"),
        Err(e)    => warn!("⚠ LLM not reachable: {e}"),
    }

    // ── 5. eBPF Capture (Linux only, requires --features ebpf) ──────────────
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        use std::path::Path;
        let iface    = std::env::var("THOR_IFACE").unwrap_or_else(|_| "eth0".to_string());
        let obj_dir  = std::env::var("EBPF_OBJ_DIR").unwrap_or_else(|_| "/opt/thor/ebpf".to_string());
        let loader   = Arc::new(linux::loader::EbpfLoader::new(&iface, Path::new(&obj_dir)));
        match loader.load_xdp("xdp_thor.o", "xdp_firewall", aya::programs::XdpFlags::default()).await {
            Ok(_)  => info!("✓ eBPF XDP loaded on {}", iface),
            Err(e) => warn!("⚠ eBPF: {e} (run as root with --features ebpf)"),
        }
    }

    info!("✅ Thor Agent fully operational — waiting for events...");

    // ── معالج الإشارات: Ctrl+C أو SIGTERM ───────────────────────────────────
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("SIGINT received — shutting down");
        }
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate()
                ).expect("Failed to register SIGTERM handler");
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            std::future::pending::<()>().await
        } => {
            info!("SIGTERM received — shutting down");
        }
    }

    info!("Thor Agent stopped.");
    Ok(())
}
