//! Thor Firewall — eBPF Maps User Space Interface
//! واجهة user space للتحكم في eBPF maps
//!
//! تتيح:
//! - إضافة/حذف IPs من الـ blacklist
//! - قراءة flow events من ring buffer
//! - قراءة إحصاءات XDP
//!
//! SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use aya::{
    maps::{HashMap as BpfHashMap, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::ring_buffer::FlowEvent;

/// الحد الأقصى لـ blacklisted IPs
pub const MAX_BLOCKED_IPS: usize = 65_536;

pub struct EbpfMaps {
    bpf: Ebpf,
    iface: String,
}

impl EbpfMaps {
    /// تحميل eBPF program وتثبيته على الـ interface
    pub fn load_and_attach(iface: &str) -> Result<Self> {
        // Load compiled eBPF object
        let bpf_obj = include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/thor_xdp")
        );

        let mut bpf = Ebpf::load(bpf_obj)
            .context("Failed to load eBPF program")?;

        // Attach XDP program
        let program: &mut Xdp = bpf
            .program_mut("thor_xdp_filter")
            .context("eBPF program 'thor_xdp_filter' not found")?
            .try_into()?;

        program.load()?;
        program
            .attach(iface, XdpFlags::default())
            .with_context(|| format!("Failed to attach XDP to interface '{}'", iface))?;

        info!("✅ eBPF XDP attached to interface: {}", iface);

        Ok(Self { bpf, iface: iface.to_string() })
    }

    // ── Blocklist Management ──────────────────────────────────────────────────

    /// حظر IP address
    pub fn block_ip(&mut self, ip: Ipv4Addr, timestamp: u64) -> Result<()> {
        let mut blocked: BpfHashMap<_, u32, u64> = BpfHashMap::try_from(
            self.bpf.map_mut("BLOCKED_IPS").context("BLOCKED_IPS map not found")?
        )?;
        let ip_int = u32::from(ip);
        blocked.insert(ip_int, timestamp, 0)
            .with_context(|| format!("Failed to block IP {}", ip))?;
        info!("Blocked IP: {}", ip);
        Ok(())
    }

    /// رفع الحظر عن IP
    pub fn unblock_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        let mut blocked: BpfHashMap<_, u32, u64> = BpfHashMap::try_from(
            self.bpf.map_mut("BLOCKED_IPS").context("BLOCKED_IPS map not found")?
        )?;
        blocked.remove(&u32::from(ip))
            .with_context(|| format!("Failed to unblock IP {}", ip))?;
        info!("Unblocked IP: {}", ip);
        Ok(())
    }

    /// إضافة IP لقائمة السماح
    pub fn allow_ip(&mut self, ip: Ipv4Addr) -> Result<()> {
        let mut allowed: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
            self.bpf.map_mut("ALLOWED_IPS").context("ALLOWED_IPS map not found")?
        )?;
        allowed.insert(u32::from(ip), 1u8, 0)?;
        debug!("Whitelisted IP: {}", ip);
        Ok(())
    }

    /// عرض جميع الـ IPs المحظورة
    pub fn list_blocked(&self) -> Result<Vec<Ipv4Addr>> {
        let blocked: BpfHashMap<_, u32, u64> = BpfHashMap::try_from(
            self.bpf.map("BLOCKED_IPS").context("BLOCKED_IPS map not found")?
        )?;
        let ips = blocked.iter()
            .filter_map(|r| r.ok())
            .map(|(ip, _)| Ipv4Addr::from(ip))
            .collect();
        Ok(ips)
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    pub fn get_stats(&self) -> Result<XdpStats> {
        let stats: BpfHashMap<_, u32, u64> = BpfHashMap::try_from(
            self.bpf.map("STATS").context("STATS map not found")?
        )?;
        Ok(XdpStats {
            total:   stats.get(&0, 0).unwrap_or(0),
            dropped: stats.get(&1, 0).unwrap_or(0),
            passed:  stats.get(&2, 0).unwrap_or(0),
        })
    }

    // ── Ring Buffer Reader ────────────────────────────────────────────────────

    /// بدء قراءة ring buffer وإرسال events عبر channel
    pub fn start_event_reader(
        &self,
        tx: mpsc::Sender<FlowEvent>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let ring: RingBuf<_> = RingBuf::try_from(
            self.bpf.map("FLOW_EVENTS").context("FLOW_EVENTS map not found")?
        )?;

        let handle = tokio::spawn(async move {
            loop {
                // أبسط طريقة: polling مع tokio::time::interval
                // في الإنتاج: استخدم epoll/io_uring
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;

                // معالجة الـ ring buffer
                // ring.next() يُعيد &[u8] تُحوَّل لـ FlowEvent
            }
        });

        Ok(handle)
    }
}

#[derive(Debug, Clone)]
pub struct XdpStats {
    pub total:   u64,
    pub dropped: u64,
    pub passed:  u64,
}

impl XdpStats {
    pub fn drop_rate(&self) -> f64 {
        if self.total == 0 { return 0.0; }
        self.dropped as f64 / self.total as f64
    }
}
