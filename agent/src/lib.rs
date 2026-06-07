// Thor Firewall Agent — Library Root
// المكتبة الرئيسية للعميل

pub mod packet_parser;
pub mod flow_manager;
pub mod rl_core;
pub mod error;
pub mod proto;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// Thor Agent version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum flows tracked simultaneously (per CPU core)
pub const MAX_FLOWS_PER_CORE: usize = 1_000_000;

/// BPF map size for flow state (must be power of 2)
pub const BPF_FLOW_MAP_SIZE: u32 = 1 << 20; // 1M entries

/// Maximum SYN rate per IP before triggering throttle (per second)
pub const DEFAULT_SYN_RATE_LIMIT: u32 = 1_000;

/// Sample rate for sending packets to userspace for ML analysis
/// 1 in N packets (higher = less overhead, lower = better ML accuracy)
pub const SAMPLE_RATE: u32 = 100;
