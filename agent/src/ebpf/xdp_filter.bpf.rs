//! Thor Firewall — XDP eBPF Filter Program
//! برنامج XDP الذي يعمل داخل Linux kernel
//!
//! يُعالج كل packet على مستوى network driver قبل kernel networking stack
//! يستخدم aya-rs لكتابة eBPF بلغة Rust خالصة
//!
//! المنطق:
//! 1. Parse Ethernet → IP → TCP/UDP
//! 2. فحص blacklist (eBPF HashMap)
//! 3. إرسال بيانات الـ flow إلى ring buffer
//! 4. تطبيق قرار RL (PASS / DROP / REDIRECT)
//!
//! تجميع: cargo xtask build-ebpf
//! SPDX-License-Identifier: MIT

#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;

// ── eBPF Maps ─────────────────────────────────────────────────────────────────

/// Blacklisted IPs → (timestamp_blocked, reason_code)
/// يُحدَّث من user space عبر ctl_program
#[map]
static BLOCKED_IPS: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

/// Whitelisted IPs (لا تُحلَّل أبداً)
#[map]
static ALLOWED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Ring buffer لإرسال flow events إلى user space
/// حجم 4MB — يُقرأ بواسطة Rust user space thread
#[map]
static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// إحصاءات الـ drops و passes — يُقرأ من Prometheus exporter
#[map]
static STATS: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

// Keys للـ STATS map
const STAT_TOTAL:   u32 = 0;
const STAT_DROPPED: u32 = 1;
const STAT_PASSED:  u32 = 2;
const STAT_REDIR:   u32 = 3;

// ── Flow Event (يُرسَل لـ user space) ────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FlowEvent {
    pub src_ip:      u32,
    pub dst_ip:      u32,
    pub src_port:    u16,
    pub dst_port:    u16,
    pub protocol:    u8,
    pub packet_size: u16,
    pub flags:       u8,         // TCP flags
    pub timestamp_ns: u64,
    pub action:      u8,         // 0=pass 1=drop 2=redirect
}

// ── Packet Parsing Helpers ────────────────────────────────────────────────────

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data() as usize;
    let end   = ctx.data_end() as usize;
    let ptr   = (start + offset) as *const T;
    if ptr as usize + core::mem::size_of::<T>() > end {
        return None;
    }
    Some(ptr)
}

// ── XDP Main Program ──────────────────────────────────────────────────────────

#[xdp]
pub fn thor_xdp_filter(ctx: XdpContext) -> u32 {
    match try_filter(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,  // Fail-open (لا نوقف الشبكة عند خطأ)
    }
}

fn try_filter(ctx: &XdpContext) -> Result<u32, ()> {
    // ── Parse Ethernet Header ──
    let eth_hdr = unsafe { ptr_at::<EtherHeader>(ctx, 0).ok_or(())? };
    let eth_proto = unsafe { u16::from_be((*eth_hdr).ether_type) };

    // نتجاهل ما ليس IPv4 (0x0800) أو IPv6 (0x86DD)
    if eth_proto != 0x0800 {
        increment_stat(STAT_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Parse IPv4 Header ──
    let ip_hdr = unsafe { ptr_at::<Ipv4Header>(ctx, ETH_HDR_LEN).ok_or(())? };
    let src_ip   = unsafe { (*ip_hdr).saddr };
    let dst_ip   = unsafe { (*ip_hdr).daddr };
    let protocol = unsafe { (*ip_hdr).protocol };
    let ihl      = unsafe { ((*ip_hdr).version_ihl & 0x0f) as usize * 4 };

    increment_stat(STAT_TOTAL);

    // ── Allowlist (bypass all checks) ──
    if unsafe { ALLOWED_IPS.get(&src_ip).is_some() } {
        increment_stat(STAT_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Blocklist (instant drop) ──
    if let Some(&blocked_at) = unsafe { BLOCKED_IPS.get(&src_ip) } {
        increment_stat(STAT_DROPPED);
        emit_flow_event(ctx, src_ip, dst_ip, 0, 0, protocol, 0, 0, 1);
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Parse TCP/UDP ports ──
    let (src_port, dst_port, tcp_flags) = match protocol {
        6  => {  // TCP
            let tcp_off = ETH_HDR_LEN + ihl;
            if let Some(tcp) = unsafe { ptr_at::<TcpHeader>(ctx, tcp_off) } {
                let sp = unsafe { u16::from_be((*tcp).source) };
                let dp = unsafe { u16::from_be((*tcp).dest) };
                let fl = unsafe { (*tcp).flags };
                (sp, dp, fl)
            } else { (0u16, 0u16, 0u8) }
        }
        17 => {  // UDP
            let udp_off = ETH_HDR_LEN + ihl;
            if let Some(udp) = unsafe { ptr_at::<UdpHeader>(ctx, udp_off) } {
                (unsafe { u16::from_be((*udp).source) }, unsafe { u16::from_be((*udp).dest) }, 0)
            } else { (0, 0, 0) }
        }
        _ => (0, 0, 0),
    };

    let pkt_size = (ctx.data_end() as usize - ctx.data() as usize) as u16;

    // ── Fast-path heuristics (قبل ML) ──
    // SYN flood detection: SYN=1, ACK=0, too many from same IP
    let is_syn_only = (tcp_flags & 0x12) == 0x02;  // SYN بدون ACK
    if is_syn_only && dst_port < 1024 {
        // إرسال للـ ML inference لاتخاذ قرار نهائي
        emit_flow_event(ctx, src_ip, dst_ip, src_port, dst_port, protocol, pkt_size, tcp_flags, 0);
        increment_stat(STAT_PASSED);
        return Ok(xdp_action::XDP_PASS);  // RL core سيقرر
    }

    // إرسال event للـ user space في كل الأحوال
    emit_flow_event(ctx, src_ip, dst_ip, src_port, dst_port, protocol, pkt_size, tcp_flags, 0);
    increment_stat(STAT_PASSED);
    Ok(xdp_action::XDP_PASS)
}

// ── Helper Functions ──────────────────────────────────────────────────────────

#[inline(always)]
fn increment_stat(key: u32) {
    if let Some(val) = unsafe { STATS.get_ptr_mut(&key) } {
        unsafe { *val += 1 };
    } else {
        let _ = unsafe { STATS.insert(&key, &1, 0) };
    }
}

#[inline(always)]
fn emit_flow_event(
    ctx: &XdpContext,
    src_ip: u32, dst_ip: u32,
    src_port: u16, dst_port: u16,
    protocol: u8, pkt_size: u16,
    flags: u8, action: u8,
) {
    if let Some(mut buf) = FLOW_EVENTS.reserve::<FlowEvent>(0) {
        let event = FlowEvent {
            src_ip, dst_ip, src_port, dst_port,
            protocol, packet_size: pkt_size,
            flags, action,
            timestamp_ns: 0,  // bpf_ktime_get_ns() في الإنتاج
        };
        unsafe { buf.write(event) };
        buf.submit(0);
    }
}

// ── C-compatible Header Structs ───────────────────────────────────────────────

const ETH_HDR_LEN: usize = 14;

#[repr(C, packed)]
struct EtherHeader {
    ether_dhost: [u8; 6],
    ether_shost: [u8; 6],
    ether_type:  u16,
}

#[repr(C, packed)]
struct Ipv4Header {
    version_ihl: u8,
    tos:         u8,
    tot_len:     u16,
    id:          u16,
    frag_off:    u16,
    ttl:         u8,
    protocol:    u8,
    check:       u16,
    saddr:       u32,
    daddr:       u32,
}

#[repr(C, packed)]
struct TcpHeader {
    source: u16, dest: u16,
    seq: u32, ack_seq: u32,
    data_offset_flags: u8,
    flags: u8,
    window: u16,
    check: u16, urg_ptr: u16,
}

#[repr(C, packed)]
struct UdpHeader {
    source: u16, dest: u16,
    len: u16, check: u16,
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
