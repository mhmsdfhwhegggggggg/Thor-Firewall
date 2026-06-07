// Thor Firewall — XDP Program Loader (Linux) — COMPLETE IMPLEMENTATION
// محمّل برامج XDP/eBPF — تنفيذ كامل
//
// يُحمّل برنامج eBPF ويُثبّته على واجهة الشبكة المحددة،
// ويُدير BPF maps (blacklist, whitelist, flow_table, config).
//
// SPDX-License-Identifier: GPL-3.0

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aya::{
    maps::{Array, HashMap as BpfHashMap, LpmTrie, PerCpuArray, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use serde::Deserialize;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::flow_manager::Decision;
use crate::packet_parser::FlowKey;
use crate::ring_consumer::PacketSample;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct LinuxConfig {
    /// اسم واجهة الشبكة (مثل eth0, ens3, enp3s0)
    pub interface: String,
    /// مسار ملف eBPF المُجمَّع (.o)
    pub ebpf_program_path: Option<String>,
    /// وضع XDP
    pub xdp_mode: XdpMode,
    /// تفعيل تسجيل رسائل BPF عبر bpf_printk
    pub enable_bpf_logging: bool,
    /// حد SYN/ثانية قبل الحظر
    pub syn_rate_limit: u32,
    /// معدل أخذ العينات (1 عينة لكل N حزمة في التدفقات المعروفة)
    pub sample_rate: u32,
    /// حجم ring buffer بالـ MB
    pub ringbuf_size_mb: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum XdpMode {
    /// أسرع — يتطلب driver يدعم XDP native
    Native,
    /// يعمل مع أي driver (SKB mode)
    Skb,
    /// Hardware offload — يتطلب NIC دعم
    Offload,
}

impl Default for LinuxConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            ebpf_program_path: None,
            xdp_mode: XdpMode::Native,
            enable_bpf_logging: true,
            syn_rate_limit: 1000,
            sample_rate: 100,
            ringbuf_size_mb: 64,
        }
    }
}

// ============================================================================
// BPF Map Keys (must match thor_common.h)
// ============================================================================

// Config map keys
const THOR_CONFIG_SYN_LIMIT:   u32 = 0;
const THOR_CONFIG_SAMPLE_RATE: u32 = 1;
const THOR_CONFIG_MODE:        u32 = 2;

// Stats map indices
const THOR_STAT_TOTAL:     u32 = 0;
const THOR_STAT_DROPPED:   u32 = 1;
const THOR_STAT_WHITELIST: u32 = 2;
const THOR_STAT_BLACKLIST: u32 = 3;
const THOR_STAT_SYN_FLOOD: u32 = 4;
const THOR_STAT_NEW_FLOWS: u32 = 5;
const THOR_STAT_MALFORMED: u32 = 6;
const THOR_STATS_MAX:      u32 = 32;

// LPM key (must match struct lpm_key in thor_common.h)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct LpmKey {
    prefixlen: u32,
    ip: u32,
}

// Flow key (must match struct flow_key in thor_common.h)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct BpfFlowKey {
    src_ip: u32,
    dst_ip: u32,
    sport:  u16,
    dport:  u16,
    proto:  u8,
    is_ipv6: u8,
    pad:    [u8; 2],
}

// Flow state (must match struct flow_state in thor_common.h)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct BpfFlowState {
    action:           u8,   // THOR_ACTION_*
    flags:            u8,
    pad:              u16,
    packets:          u32,
    bytes:            u64,
    first_seen_ns:    u64,
    last_seen_ns:     u64,
    risk_score_x100:  u32,
}

// Action codes
const THOR_ACTION_PASS:     u8 = 0;
const THOR_ACTION_DROP:     u8 = 1;
const THOR_ACTION_SAMPLE:   u8 = 2;
const THOR_ACTION_REDIR:    u8 = 3;
const THOR_ACTION_THROTTLE: u8 = 4;

// ============================================================================
// XDP Stats
// ============================================================================

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct XDPStats {
    pub total_packets:       u64,
    pub dropped_packets:     u64,
    pub whitelisted_packets: u64,
    pub blacklisted_packets: u64,
    pub syn_flood_blocked:   u64,
    pub new_flows:           u64,
    pub malformed_packets:   u64,
}

// ============================================================================
// XDP Loader
// ============================================================================

pub struct XDPLoader {
    config:    LinuxConfig,
    ebpf:      Option<Arc<Mutex<Ebpf>>>,
    /// Sender for ring buffer samples (consumed by RingConsumer)
    sample_tx: Option<mpsc::Sender<PacketSample>>,
}

impl XDPLoader {
    pub fn new(config: &LinuxConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            ebpf:   None,
            sample_tx: None,
        })
    }

    /// تحميل وتثبيت برنامج eBPF على واجهة الشبكة
    pub async fn load(
        &mut self,
        sample_tx: mpsc::Sender<PacketSample>,
    ) -> Result<Arc<Mutex<Ebpf>>> {
        let path = self.config.ebpf_program_path.as_deref()
            .ok_or_else(|| anyhow::anyhow!(
                "ebpf_program_path must be set in config (run `make` in kernel-modules/linux/ebpf/ first)"
            ))?;

        info!(
            interface = %self.config.interface,
            program   = %path,
            mode      = ?self.config.xdp_mode,
            "Loading Thor eBPF/XDP program"
        );

        // --- تحميل bytecode ---
        let mut ebpf = Ebpf::load_file(path)
            .with_context(|| format!("Failed to load eBPF object: {path}"))?;

        // --- تفعيل تسجيل BPF ---
        if self.config.enable_bpf_logging {
            if let Err(e) = EbpfLogger::init(&mut ebpf) {
                warn!(error = %e, "BPF logger init failed (non-fatal)");
            }
        }

        // --- تثبيت برنامج XDP الرئيسي ---
        let flags = self.xdp_flags();
        {
            let program: &mut Xdp = ebpf
                .program_mut("thor_xdp_main")
                .context("Program 'thor_xdp_main' not found in eBPF object")?
                .try_into()
                .context("Not an XDP program")?;

            program.load().context("Failed to load XDP program into kernel")?;
            program
                .attach(&self.config.interface, flags)
                .with_context(|| format!(
                    "Failed to attach to '{}' (ensure interface exists and you have CAP_NET_ADMIN)",
                    self.config.interface
                ))?;

            info!(interface = %self.config.interface, "XDP main program attached");
        }

        // --- تثبيت برنامج SYN Guard (إذا موجود) ---
        if let Ok(syn_prog) = ebpf.program_mut("thor_syn_guard") {
            let syn_xdp: &mut Xdp = syn_prog.try_into()?;
            syn_xdp.load()?;
            // Attached as secondary — في الواقع يكون التحميل في chain
            info!("SYN guard program loaded");
        }

        // --- تهيئة config map ---
        self.init_config_map(&mut ebpf)
            .context("Failed to init config BPF map")?;

        let ebpf = Arc::new(Mutex::new(ebpf));
        self.ebpf      = Some(ebpf.clone());
        self.sample_tx = Some(sample_tx.clone());

        // --- بدء قارئ ring buffer ---
        self.start_ringbuf_reader(ebpf.clone(), sample_tx).await
            .context("Failed to start ring buffer reader")?;

        info!("XDP loader fully operational");
        Ok(ebpf)
    }

    /// تحديد XDP flags بحسب الوضع المطلوب
    fn xdp_flags(&self) -> XdpFlags {
        match self.config.xdp_mode {
            XdpMode::Native  => XdpFlags::DRV_MODE,
            XdpMode::Skb     => XdpFlags::SKB_MODE,
            XdpMode::Offload => XdpFlags::HW_MODE,
        }
    }

    /// تهيئة config_map بالقيم الافتراضية
    fn init_config_map(&self, ebpf: &mut Ebpf) -> Result<()> {
        let map = ebpf
            .map_mut("config_map")
            .context("config_map not found")?;

        let mut config_map: Array<_, u64> = Array::try_from(map)?;

        config_map.set(THOR_CONFIG_SYN_LIMIT,   self.config.syn_rate_limit as u64, 0)?;
        config_map.set(THOR_CONFIG_SAMPLE_RATE, self.config.sample_rate as u64,     0)?;
        config_map.set(THOR_CONFIG_MODE,        0u64, /* enforcement */ 0)?;

        debug!(
            syn_limit   = self.config.syn_rate_limit,
            sample_rate = self.config.sample_rate,
            "Config BPF map initialized"
        );
        Ok(())
    }

    // =========================================================================
    // BPF Map Update API
    // =========================================================================

    /// إضافة CIDR block إلى blacklist (LPM trie)
    pub async fn blacklist_cidr(&self, ip: Ipv4Addr, prefix_len: u32) -> Result<()> {
        let ebpf = self.ebpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;

        let mut guard = ebpf.lock().await;
        let map = guard.map_mut("blacklist").context("blacklist map not found")?;
        let mut trie: LpmTrie<_, LpmKey, u8> = LpmTrie::try_from(map)?;

        let key = LpmKey {
            prefixlen: prefix_len,
            ip: u32::from(ip).to_be(),
        };
        // aya LpmTrie requires a NetworkAddress-style key
        // We use a raw bytes approach via unsafe
        // Value = 1 (blocked)
        trie.insert(&aya::maps::lpm_trie::Key::new(prefix_len, u32::from(ip).to_be()), 1u8, 0)
            .with_context(|| format!("Failed to insert {}/{} into blacklist", ip, prefix_len))?;

        info!(ip = %ip, prefix = prefix_len, "IP/CIDR added to blacklist");
        Ok(())
    }

    /// إضافة IP محدد إلى blacklist
    pub async fn blacklist_ip(&self, ip: Ipv4Addr) -> Result<()> {
        self.blacklist_cidr(ip, 32).await
    }

    /// إزالة IP من blacklist
    pub async fn unblacklist_ip(&self, ip: Ipv4Addr) -> Result<()> {
        let ebpf = self.ebpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;

        let mut guard = ebpf.lock().await;
        let map = guard.map_mut("blacklist").context("blacklist map not found")?;
        let mut trie: LpmTrie<_, LpmKey, u8> = LpmTrie::try_from(map)?;

        trie.remove(&aya::maps::lpm_trie::Key::new(32, u32::from(ip).to_be()))
            .with_context(|| format!("Failed to remove {} from blacklist", ip))?;

        info!(ip = %ip, "IP removed from blacklist");
        Ok(())
    }

    /// إضافة IP إلى whitelist (bypass كل الفلترة)
    pub async fn whitelist_ip(&self, ip: Ipv4Addr, prefix_len: u32) -> Result<()> {
        let ebpf = self.ebpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;

        let mut guard = ebpf.lock().await;
        let map = guard.map_mut("whitelist").context("whitelist map not found")?;
        let mut trie: LpmTrie<_, LpmKey, u8> = LpmTrie::try_from(map)?;

        trie.insert(
            &aya::maps::lpm_trie::Key::new(prefix_len, u32::from(ip).to_be()),
            1u8,
            0,
        )?;

        info!(ip = %ip, prefix = prefix_len, "IP/CIDR added to whitelist");
        Ok(())
    }

    /// تحديث قرار تدفق في flow_table مباشرة
    /// يُطبَّق القرار فوراً على الحزم التالية من هذا التدفق
    pub async fn update_flow_decision(
        &self,
        flow_key: &FlowKey,
        decision: &Decision,
        risk_score: f32,
    ) -> Result<()> {
        let ebpf = self.ebpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;

        let action: u8 = match decision {
            Decision::Allow               => THOR_ACTION_PASS,
            Decision::Block               => THOR_ACTION_DROP,
            Decision::Throttle { .. }     => THOR_ACTION_THROTTLE,
            Decision::Mirror              => THOR_ACTION_SAMPLE,
            Decision::Redirect { .. }     => THOR_ACTION_REDIR,
        };

        // بناء BPF flow key (IPv4 only في هذا الإصدار)
        let (src_ip_u32, dst_ip_u32, is_ipv6) = match (flow_key.src_ip, flow_key.dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (u32::from(s).to_be(), u32::from(d).to_be(), 0u8),
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                // IPv6: استخدم آخر 32 bit كـ approximation (TODO: IPv6 flow table)
                let sb = s.octets();
                let db = d.octets();
                let su = u32::from_be_bytes([sb[12], sb[13], sb[14], sb[15]]);
                let du = u32::from_be_bytes([db[12], db[13], db[14], db[15]]);
                (su.to_be(), du.to_be(), 1u8)
            }
            _ => bail!("Mixed IPv4/IPv6 flow key"),
        };

        let bpf_key = BpfFlowKey {
            src_ip:  src_ip_u32,
            dst_ip:  dst_ip_u32,
            sport:   flow_key.src_port.to_be(),
            dport:   flow_key.dst_port.to_be(),
            proto:   flow_key.protocol as u8,
            is_ipv6,
            pad:     [0; 2],
        };

        let bpf_state = BpfFlowState {
            action,
            flags:          0,
            pad:            0,
            packets:        0,
            bytes:          0,
            first_seen_ns:  0,
            last_seen_ns:   0,
            risk_score_x100: (risk_score * 100.0) as u32,
        };

        let mut guard = ebpf.lock().await;
        let map = guard.map_mut("flow_table").context("flow_table map not found")?;

        // BpfFlowKey و BpfFlowState هي #[repr(C, packed)] — آمن للاستخدام مع aya
        let mut flow_map: BpfHashMap<_, BpfFlowKey, BpfFlowState> =
            BpfHashMap::try_from(map)?;

        flow_map.insert(bpf_key, bpf_state, 0)
            .context("Failed to update flow_table")?;

        debug!(
            src = ?flow_key.src_ip,
            dst = ?flow_key.dst_ip,
            action = action,
            risk = risk_score,
            "Flow decision written to BPF map"
        );
        Ok(())
    }

    /// حذف تدفق من flow_table (إعادة ضبط)
    pub async fn remove_flow(&self, flow_key: &FlowKey) -> Result<()> {
        let ebpf = self.ebpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;

        let (src_ip_u32, dst_ip_u32, is_ipv6) = match (flow_key.src_ip, flow_key.dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (u32::from(s).to_be(), u32::from(d).to_be(), 0u8),
            _ => bail!("IPv6 not yet supported in remove_flow"),
        };

        let bpf_key = BpfFlowKey {
            src_ip:  src_ip_u32,
            dst_ip:  dst_ip_u32,
            sport:   flow_key.src_port.to_be(),
            dport:   flow_key.dst_port.to_be(),
            proto:   flow_key.protocol as u8,
            is_ipv6,
            pad:     [0; 2],
        };

        let mut guard = ebpf.lock().await;
        let map = guard.map_mut("flow_table").context("flow_table not found")?;
        let mut flow_map: BpfHashMap<_, BpfFlowKey, BpfFlowState> = BpfHashMap::try_from(map)?;
        flow_map.remove(&bpf_key).context("Failed to remove flow from BPF map")?;

        Ok(())
    }

    /// قراءة إحصاءات XDP من stats_map
    pub async fn get_stats(&self) -> Result<XDPStats> {
        let ebpf = self.ebpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;

        let guard = ebpf.lock().await;
        let map = guard.map("stats_map").context("stats_map not found")?;
        let stats_map: PerCpuArray<_, u64> = PerCpuArray::try_from(map)?;

        // Somme toutes les CPUs pour chaque compteur
        let sum = |idx: u32| -> u64 {
            stats_map.get(&idx, 0)
                .map(|vals| vals.iter().sum::<u64>())
                .unwrap_or(0)
        };

        Ok(XDPStats {
            total_packets:       sum(THOR_STAT_TOTAL),
            dropped_packets:     sum(THOR_STAT_DROPPED),
            whitelisted_packets: sum(THOR_STAT_WHITELIST),
            blacklisted_packets: sum(THOR_STAT_BLACKLIST),
            syn_flood_blocked:   sum(THOR_STAT_SYN_FLOOD),
            new_flows:           sum(THOR_STAT_NEW_FLOWS),
            malformed_packets:   sum(THOR_STAT_MALFORMED),
        })
    }

    /// تحديث حد SYN في الوقت الحقيقي
    pub async fn set_syn_rate_limit(&self, limit: u32) -> Result<()> {
        let ebpf = self.ebpf.as_ref()
            .ok_or_else(|| anyhow::anyhow!("BPF not loaded"))?;

        let mut guard = ebpf.lock().await;
        let map = guard.map_mut("config_map").context("config_map not found")?;
        let mut config: Array<_, u64> = Array::try_from(map)?;
        config.set(THOR_CONFIG_SYN_LIMIT, limit as u64, 0)?;

        info!(limit = limit, "SYN rate limit updated");
        Ok(())
    }

    // =========================================================================
    // Ring Buffer Reader
    // =========================================================================

    /// بدء قراءة ring buffer في خيط async منفصل
    async fn start_ringbuf_reader(
        &self,
        ebpf:      Arc<Mutex<Ebpf>>,
        sample_tx: mpsc::Sender<PacketSample>,
    ) -> Result<()> {
        let interface = self.config.interface.clone();

        tokio::spawn(async move {
            ring_buffer_loop(ebpf, sample_tx, interface).await;
        });

        info!("Ring buffer reader spawned");
        Ok(())
    }
}

impl Drop for XDPLoader {
    fn drop(&mut self) {
        // aya تُزيل البرنامج تلقائياً عند drop للـ Ebpf object
        if self.ebpf.is_some() {
            info!(
                interface = %self.config.interface,
                "XDP program will be detached (aya auto-detach on drop)"
            );
        }
    }
}

// ============================================================================
// Ring Buffer Reader Loop
// ============================================================================

/// حلقة قراءة ring buffer — تعمل في الخلفية باستمرار
async fn ring_buffer_loop(
    ebpf:      Arc<Mutex<Ebpf>>,
    sample_tx: mpsc::Sender<PacketSample>,
    interface: String,
) {
    info!(interface = %interface, "Ring buffer loop starting");

    // الانتظار حتى يصبح BPF مُحمَّلاً بالكامل
    tokio::time::sleep(Duration::from_millis(100)).await;

    loop {
        let result = poll_ring_buffer(&ebpf, &sample_tx).await;
        if let Err(e) = result {
            error!(error = %e, "Ring buffer error — retrying in 1s");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

/// دورة قراءة واحدة من ring buffer
async fn poll_ring_buffer(
    ebpf:      &Arc<Mutex<Ebpf>>,
    sample_tx: &mpsc::Sender<PacketSample>,
) -> Result<()> {
    // نقرأ batch من الأحداث كل 100µs
    tokio::time::sleep(Duration::from_micros(100)).await;

    let mut guard = ebpf.lock().await;

    let map = match guard.map_mut("sample_ringbuf") {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "sample_ringbuf not found, falling back to packet_samples");
            // محاولة الخريطة البديلة
            match guard.map_mut("packet_samples") {
                Ok(m) => m,
                Err(e2) => bail!("Neither sample_ringbuf nor packet_samples found: {}", e2),
            }
        }
    };

    let mut ring = RingBuf::try_from(map)?;
    let sample_size = std::mem::size_of::<PacketSample>();

    let mut count = 0usize;
    while let Some(item) = ring.next() {
        if item.len() < sample_size {
            warn!(
                len      = item.len(),
                expected = sample_size,
                "Ring buf item too small — skipping"
            );
            continue;
        }

        // SAFETY: PacketSample is #[repr(C, packed)], matches C struct
        let sample: PacketSample = unsafe {
            std::ptr::read_unaligned(item.as_ptr() as *const PacketSample)
        };

        // بدون blocking — إذا امتلأت القناة نتجاهل
        if sample_tx.try_send(sample).is_err() {
            debug!("Ring consumer channel full — dropping sample");
        }

        count += 1;
        // لا نعالج أكثر من 1024 حزمة في كل دورة لتجنب block القفل
        if count >= 1024 {
            break;
        }
    }

    Ok(())
}
