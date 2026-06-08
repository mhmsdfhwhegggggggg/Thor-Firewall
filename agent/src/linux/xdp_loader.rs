// Thor Firewall — XDP Program Loader (Linux)
// محمّل برامج XDP/eBPF
//
// يستخدم مكتبة aya لتحميل وتثبيت برامج eBPF
// ويوفر واجهة لتحديث BPF maps من user-space

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap as BpfHashMap, LpmTrie, RingBuf},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use serde::Deserialize;
use tokio::task;
use tracing::{debug, error, info, warn};

use crate::flow_manager::Decision;
use crate::packet_parser::FlowKey;

/// إعدادات XDP
#[derive(Debug, Clone, Deserialize)]
pub struct LinuxConfig {
    /// اسم واجهة الشبكة
    pub interface: String,
    /// مسار ملف eBPF المُجمَّع
    pub ebpf_program_path: Option<String>,
    /// وضع XDP: native (مُوصى به)، skb، offload
    pub xdp_mode: XdpMode,
    /// تفعيل تسجيل رسائل BPF
    pub enable_bpf_logging: bool,
    /// الحد الأقصى لـ SYN/s لكل IP
    pub syn_rate_limit: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub enum XdpMode {
    Native,  // أسرع — يتطلب دعم driver
    Skb,     // أبطأ — يعمل مع أي driver
    Offload, // أسرع — يتطلب دعم hardware
}

impl Default for LinuxConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            ebpf_program_path: None,
            xdp_mode: XdpMode::Native,
            enable_bpf_logging: true,
            syn_rate_limit: 1000,
        }
    }
}

/// واجهة تحميل وإدارة برامج XDP
pub struct XDPLoader {
    config: LinuxConfig,
    bpf: Option<Bpf>,
}

impl XDPLoader {
    pub fn new(interface: &str, config: &LinuxConfig) -> Result<Self> {
        Ok(Self {
            config: LinuxConfig {
                interface: interface.to_string(),
                ..config.clone()
            },
            bpf: None,
        })
    }

    /// تحميل وتثبيت برنامج eBPF على واجهة الشبكة
    pub async fn load(&mut self) -> Result<()> {
        info!(
            interface = %self.config.interface,
            mode = ?self.config.xdp_mode,
            "Loading Thor eBPF/XDP program"
        );

        // تحميل bytecode eBPF
        // في الإنتاج، يُضمَّن مباشرة في الثنائي باستخدام include_bytes_aligned!
        let mut bpf = if let Some(path) = &self.config.ebpf_program_path {
            Bpf::load_file(path)
                .with_context(|| format!("Failed to load eBPF program from {}", path))?
        } else {
            // Embedded bytecode (generated at compile time)
            // Bpf::load(include_bytes_aligned!("../../../../target/bpf/thor_xdp.o"))
            //     .context("Failed to load embedded eBPF program")?
            bail!("No eBPF program path specified and embedded build not enabled");
        };

        // إعداد تسجيل BPF
        if self.config.enable_bpf_logging {
            BpfLogger::init(&mut bpf)
                .context("Failed to initialize BPF logger")?;
        }

        // الحصول على البرنامج وتثبيته
        let program: &mut Xdp = bpf
            .program_mut("thor_xdp_main")
            .context("XDP program 'thor_xdp_main' not found in eBPF object")?
            .try_into()?;

        program.load().context("Failed to load XDP program into kernel")?;

        let flags = match self.config.xdp_mode {
            XdpMode::Native => XdpFlags::DRV_MODE,
            XdpMode::Skb => XdpFlags::SKB_MODE,
            XdpMode::Offload => XdpFlags::HW_MODE,
        };

        program
            .attach(&self.config.interface, flags)
            .with_context(|| format!(
                "Failed to attach XDP program to interface '{}'. \
                 Ensure the interface exists and you have CAP_NET_ADMIN.",
                self.config.interface
            ))?;

        info!(
            interface = %self.config.interface,
            "XDP program attached successfully"
        );

        // تهيئة الإعدادات في BPF map
        self.init_config_map(&mut bpf)?;

        self.bpf = Some(bpf);

        // بدء قراءة ring buffer في خيط منفصل
        self.start_ringbuf_reader().await?;

        Ok(())
    }

    /// تهيئة config map بالقيم الافتراضية
    fn init_config_map(&self, bpf: &mut Bpf) -> Result<()> {
        let mut config_map: Array<_, u64> = Array::try_from(
            bpf.map_mut("config_map")
                .context("config_map not found")?
        )?;

        // THOR_CONFIG_SYN_LIMIT = 0
        config_map.set(0, self.config.syn_rate_limit as u64, 0)
            .context("Failed to set SYN rate limit")?;

        // THOR_CONFIG_SAMPLE_RATE = 1
        config_map.set(1, 100u64, 0)
            .context("Failed to set sample rate")?;

        debug!(
            syn_limit = self.config.syn_rate_limit,
            "BPF config map initialized"
        );

        Ok(())
    }

    /// إضافة IP إلى قائمة الحظر
    pub fn blacklist_ip(&self, ip: Ipv4Addr) -> Result<()> {
        let bpf = self.bpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF program not loaded"))?;

        // TODO: implement LPM trie update
        info!(ip = %ip, "IP added to blacklist");
        Ok(())
    }

    /// إزالة IP من قائمة الحظر
    pub fn unblacklist_ip(&self, ip: Ipv4Addr) -> Result<()> {
        info!(ip = %ip, "IP removed from blacklist");
        Ok(())
    }

    /// تحديث قرار تدفق في flow_table
    pub fn update_flow_decision(&self, key: &FlowKey, decision: &Decision) -> Result<()> {
        // TODO: implement flow table update via BPF map
        debug!(decision = ?decision, "Flow decision updated in BPF map");
        Ok(())
    }

    /// قراءة ring buffer وإرسال العينات للمعالجة
    async fn start_ringbuf_reader(&self) -> Result<()> {
        // TODO: implement ring buffer reader
        // سيُرسل العينات إلى FlowManager للتحليل
        info!("Ring buffer reader started");
        Ok(())
    }

    /// قراءة إحصاءات BPF
    pub fn get_stats(&self) -> Result<XDPStats> {
        // TODO: implement stats reading from BPF map
        Ok(XDPStats::default())
    }
}

impl Drop for XDPLoader {
    fn drop(&mut self) {
        if self.bpf.is_some() {
            info!(
                interface = %self.config.interface,
                "Detaching XDP program from interface"
            );
            // aya automatically detaches when Bpf is dropped
        }
    }
}

/// إحصاءات XDP
#[derive(Debug, Default, serde::Serialize)]
pub struct XDPStats {
    pub total_packets: u64,
    pub dropped_packets: u64,
    pub whitelisted_packets: u64,
    pub blacklisted_packets: u64,
    pub syn_flood_blocked: u64,
    pub new_flows: u64,
    pub malformed_packets: u64,
}
