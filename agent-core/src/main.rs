// Thor Agent - Universal entry point for Linux & Windows
mod packet_parser;
mod flow_manager;
mod rl_agent;
mod llm_client;
mod config;

use log::{info, error};
use tokio::signal;

// Placeholder modules to satisfy imports in main
mod rl_agent_impl {
    pub async fn run_agent() {
        log::info!("RL Agent background task started");
    }
}

mod llm_client_impl {
    pub async fn run_llm_server() {
        log::info!("LLM Interface server started");
    }
}

// Re-export or use internal placeholders
use rl_agent_impl as rl_agent;
use llm_client_impl as llm_client;

#[cfg(target_os = "linux")]
mod linux_ebpf {
    pub async fn start_capture(_cfg: crate::config::Config) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Linux eBPF capture started");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows_wfp {
    pub async fn start_capture(_cfg: crate::config::Config) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Windows WFP capture started");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("🚀 Thor Agent starting ...");

    let cfg = config::load_config()?;
    
    #[cfg(target_os = "linux")]
    linux_ebpf::start_capture(cfg.clone()).await?;
    
    #[cfg(target_os = "windows")]
    windows_wfp::start_capture(cfg.clone()).await?;

    // Launch RL Agent in background
    let _rl_handle = tokio::spawn(async {
        rl_agent::run_agent().await;
    });

    // Launch LLM interface
    let _llm_handle = tokio::spawn(async {
        llm_client::run_llm_server().await;
    });

    info!("✅ Thor Agent fully operational on {}", std::env::consts::OS);
    
    // Wait for shutdown signal (Ctrl+C)
    signal::ctrl_c().await?;
    info!("Shutting down Thor Agent ...");
    Ok(())
}
