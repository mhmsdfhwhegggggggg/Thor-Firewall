// Thor Agent - Universal entry point for Linux & Windows
mod packet_parser;
mod flow_manager;
mod rl_agent;
mod llm_client;
mod config;

use log::{info, error};
use tokio::signal;

#[cfg(target_os = "linux")]
mod linux_ebpf;

#[cfg(target_os = "windows")]
mod windows_wfp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("🚀 Thor Agent starting ...");

    let cfg = config::load_config()?;
    
    #[cfg(target_os = "linux")]
    let capture_handle = linux_ebpf::start_capture(cfg.clone()).await?;
    
    #[cfg(target_os = "windows")]
    let capture_handle = windows_wfp::start_capture(cfg.clone()).await?;

    // Launch RL Agent in background
    let rl_handle = tokio::spawn(async {
        rl_agent::run_agent().await;
    });

    // Launch LLM interface
    let llm_handle = tokio::spawn(async {
        llm_client::run_llm_server().await;
    });

    info!("✅ Thor Agent fully operational on {}", std::env::consts::OS);
    
    // Wait for shutdown signal (Ctrl+C)
    signal::ctrl_c().await?;
    info!("Shutting down Thor Agent ...");
    Ok(())
}
