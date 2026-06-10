// Thor Firewall — Real Aya XDP Loader
//
// REAL CODE SOURCE: https://github.com/aya-rs/aya (Apache-2.0 / MIT)
// Adapted from: https://github.com/aya-rs/book/tree/main/examples/xdp-drop
//   Copyright 2021 The Aya Authors
//
// This loader attaches the compiled thor_integrated.bpf.o XDP program
// to a network interface and consumes the ring buffer events for the ML pipeline.

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap as AyaHashMap, LpmTrie, MapData, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya::maps::lpm_trie::Key;
use aya_log::EbpfLogger;
use tokio::{io::unix::AsyncFd, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::flow_manager::FlowSample;

/// Real Aya XDP program loader — attaches thor_integrated.bpf.o
pub struct ThorXdpLoader {
    ebpf: Option<Ebpf>,
    iface: String,
    mode: XdpFlags,
    sample_tx: mpsc::Sender<FlowSample>,
}

/// LPM trie key (must match BPF struct)
#[repr(C)]
struct LpmKey {
    prefix_len: u32,
    addr: u32,
}

/// Ring buffer sample (must match BPF struct thor_sample)
#[repr(C, packed)]
struct ThorSample {
    timestamp_ns: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _flags: u8,
    src_port2: u16, // ports high
    dst_port2: u16, // ports low
    _proto2: u8,
    _flags2: u8,
    _pad: [u8; 2],
    bytes: u32,
    risk_score: u32,
    verdict: u8,
    _pad2: [u8; 3],
}

impl ThorXdpLoader {
    pub fn new(
        iface: impl Into<String>,
        native_mode: bool,
        sample_tx: mpsc::Sender<FlowSample>,
    ) -> Self {
        Self {
            ebpf: None,
            iface: iface.into(),
            mode: if native_mode { XdpFlags::DRV_MODE } else { XdpFlags::SKB_MODE },
            sample_tx,
        }
    }

    /// Load the compiled eBPF object and attach to interface.
    ///
    /// In production the .o is embedded at compile time:
    ///   include_bytes_aligned!(concat!(env!("OUT_DIR"), "/thor_integrated.bpf.o"))
    /// During dev you can load from disk.
    pub async fn load(&mut self, bpf_path: Option<&str>) -> Result<()> {
        let mut ebpf = match bpf_path {
            Some(p) => Ebpf::load_file(p)
                .with_context(|| format!("Failed to load eBPF object from {p}"))?,
            None => bail!(
                "Embedded eBPF build not enabled. \
                 Pass --bpf-path or build with `cargo xtask build-ebpf`."
            ),
        };

        // Initialise BPF logger (maps bpf_printk → tracing)
        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            warn!("BPF logger not available: {e}");
        }

        // Attach XDP program
        let program: &mut Xdp = ebpf
            .program_mut("thor_xdp_main")
            .context("Program 'thor_xdp_main' not found in object")?
            .try_into()?;

        program.load().context("Kernel rejected XDP program")?;
        program
            .attach(&self.iface, self.mode)
            .with_context(|| {
                format!(
                    "attach to '{}' failed — need CAP_NET_ADMIN and \
                     XDP-capable driver for DRV_MODE (use SKB_MODE if unsure)",
                    self.iface
                )
            })?;

        info!(iface = %self.iface, mode = ?self.mode, "XDP program attached");

        // Seed config map: index 0 = SYN rate limit, index 1 = sample rate
        {
            let mut cfg: Array<_, u64> = Array::try_from(
                ebpf.map_mut("config_map").context("config_map missing")?,
            )?;
            cfg.set(0, 500u64, 0).context("set SYN limit")?;  // 500 SYN/s
            cfg.set(1, 100u64, 0).context("set sample rate")?; // 1-in-100
        }

        // Spawn ring buffer consumer (real Aya AsyncFd pattern)
        let ring_map = ebpf
            .take_map("sample_ringbuf")
            .context("sample_ringbuf missing")?;
        let mut ring_buf = RingBuf::try_from(ring_map)?;
        let tx = self.sample_tx.clone();

        tokio::spawn(async move {
            let async_fd = AsyncFd::new(ring_buf).expect("AsyncFd ring");
            loop {
                let mut guard = match async_fd.readable_mut().await {
                    Ok(g) => g,
                    Err(e) => { error!("ring buf readable: {e}"); break; }
                };
                // Drain all available items
                loop {
                    match guard.get_inner_mut().next() {
                        Some(item) => {
                            let bytes = item.len();
                            if bytes < std::mem::size_of::<ThorSample>() {
                                debug!("short ring buf item: {bytes}");
                                continue;
                            }
                            let sample = unsafe {
                                &*(item.as_ptr() as *const ThorSample)
                            };
                            let flow = FlowSample {
                                timestamp_ns: sample.timestamp_ns,
                                src_ip:    Ipv4Addr::from(u32::from_be(sample.src_ip)),
                                dst_ip:    Ipv4Addr::from(u32::from_be(sample.dst_ip)),
                                src_port:  u16::from_be(sample.src_port),
                                dst_port:  u16::from_be(sample.dst_port),
                                protocol:  sample.protocol,
                                bytes:     sample.bytes,
                                risk_score: sample.risk_score,
                                verdict:   sample.verdict,
                            };
                            if tx.try_send(flow).is_err() {
                                debug!("sample channel full, dropping");
                            }
                        }
                        None => break, // ring buf drained
                    }
                }
                guard.clear_ready();
            }
        });

        info!("Ring buffer consumer started");
        self.ebpf = Some(ebpf);
        Ok(())
    }

    /// Add IPv4 address to BPF blacklist LPM trie.
    pub fn blacklist_ip(&self, ip: Ipv4Addr, prefix_len: u32) -> Result<()> {
        let ebpf = self.ebpf.as_ref().context("XDP not loaded")?;
        let mut trie: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(ebpf.map("blacklist_v4").context("blacklist_v4 missing")?)?;
        let key = Key::new(prefix_len, ip.octets());
        trie.insert(&key, 1u8, 0).context("blacklist insert")?;
        info!(ip = %ip, prefix = prefix_len, "IP blacklisted in BPF");
        Ok(())
    }

    /// Remove IPv4 address from BPF blacklist.
    pub fn unblacklist_ip(&self, ip: Ipv4Addr, prefix_len: u32) -> Result<()> {
        let ebpf = self.ebpf.as_ref().context("XDP not loaded")?;
        let mut trie: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(ebpf.map("blacklist_v4").context("blacklist_v4 missing")?)?;
        let key = Key::new(prefix_len, ip.octets());
        trie.remove(&key).context("blacklist remove")?;
        info!(ip = %ip, "IP removed from BPF blacklist");
        Ok(())
    }

    /// Update ML risk score in BPF map (called from ML pipeline callback).
    pub fn update_ml_decision(
        &self, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16,
        proto: u8, score: u32,
    ) -> Result<()> {
        let ebpf = self.ebpf.as_ref().context("XDP not loaded")?;
        let mut map: AyaHashMap<_, [u8; 13], u32> =
            AyaHashMap::try_from(ebpf.map("ml_decisions").context("ml_decisions missing")?)?;

        let mut fk = [0u8; 13];
        fk[0..4].copy_from_slice(&src.octets());
        fk[4..8].copy_from_slice(&dst.octets());
        fk[8..10].copy_from_slice(&sport.to_be_bytes());
        fk[10..12].copy_from_slice(&dport.to_be_bytes());
        fk[12] = proto;

        map.insert(&fk, score, 0).context("ml_decisions insert")?;
        Ok(())
    }
}

impl Drop for ThorXdpLoader {
    fn drop(&mut self) {
        if self.ebpf.is_some() {
            info!(iface = %self.iface, "Detaching XDP program (Aya RAII)");
            // Aya automatically detaches when Ebpf is dropped
        }
    }
}
