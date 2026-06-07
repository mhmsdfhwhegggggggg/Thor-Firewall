// Thor Firewall Agent — Entry Point
// نقطة الدخول الرئيسية للعميل
//
// يقوم بتهيئة جميع مكونات النظام:
// 1. تحميل الإعدادات
// 2. إعداد نظام التسجيل والتتبع
// 3. تحميل برامج eBPF (Linux) أو WFP (Windows)
// 4. تشغيل محرك التعلم المعزز
// 5. بدء الاستماع على gRPC

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn, error};

mod config;
mod telemetry;
mod server;

use thor_agent::{
    flow_manager::FlowManager,
    rl_core::RLCore,
    packet_parser::PacketParser,
};

/// Thor Firewall Agent CLI
#[derive(Parser, Debug)]
#[command(
    name = "thor-agent",
    version = env!("CARGO_PKG_VERSION"),
    about = "Thor Firewall Agent — Next-Generation Firewall powered by eBPF and AI",
    long_about = None
)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/thor/agent.toml")]
    config: String,

    /// Override network interface (Linux only)
    #[arg(short, long)]
    interface: Option<String>,

    /// Run in dry-run mode (log decisions without enforcing)
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Verbosity level (0=error, 1=warn, 2=info, 3=debug, 4=trace)
    #[arg(short, long, default_value_t = 2)]
    verbosity: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize telemetry (tracing + metrics)
    telemetry::init(&args.verbosity)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %args.config,
        dry_run = args.dry_run,
        "⚡ Thor Firewall Agent starting"
    );

    // Load configuration
    let cfg = config::load(&args.config).map_err(|e| {
        error!(error = %e, "Failed to load configuration");
        e
    })?;

    info!(
        grpc_port = cfg.grpc.port,
        metrics_port = cfg.metrics.port,
        "Configuration loaded successfully"
    );

    // Initialize core components
    let packet_parser = PacketParser::new(cfg.parser.clone());
    let flow_manager = FlowManager::new(cfg.flow.clone()).await?;
    let rl_core = RLCore::new(cfg.rl.clone()).await?;

    info!("Core components initialized");

    // Platform-specific kernel module loading
    #[cfg(target_os = "linux")]
    {
        use thor_agent::linux::xdp_loader::XDPLoader;
        let interface = args.interface
            .unwrap_or_else(|| cfg.linux.interface.clone());

        info!(interface = %interface, "Loading eBPF/XDP program");
        let xdp_loader = XDPLoader::new(&interface, &cfg.linux).await?;
        xdp_loader.load().await?;
        info!("eBPF/XDP program loaded and attached successfully");
    }

    #[cfg(target_os = "windows")]
    {
        use thor_agent::windows::wfp_io::WFPInterface;
        info!("Connecting to WFP callout driver");
        let wfp = WFPInterface::new(&cfg.windows).await?;
        wfp.connect().await?;
        info!("WFP driver connection established");
    }

    // Start gRPC server for control plane communication
    let grpc_server = server::GrpcServer::new(
        cfg.grpc.clone(),
        flow_manager.clone(),
        rl_core.clone(),
    );

    // Start metrics server
    let metrics_server = telemetry::metrics::start_server(cfg.metrics.port);

    info!("Thor Firewall Agent fully operational");
    warn!(
        dry_run = args.dry_run,
        "{}",
        if args.dry_run {
            "⚠️  DRY RUN MODE — No packets will be dropped"
        } else {
            "🛡️  ENFORCEMENT MODE — Active packet filtering enabled"
        }
    );

    // Run all tasks concurrently
    tokio::select! {
        result = grpc_server.run() => {
            error!("gRPC server exited: {:?}", result);
        }
        result = metrics_server => {
            error!("Metrics server exited: {:?}", result);
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT, shutting down gracefully...");
        }
    }

    // Graceful shutdown
    info!("Thor Firewall Agent shutting down");
    Ok(())
}
