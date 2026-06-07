// Thor Firewall — Windows WFP Callout Driver Interface
// واجهة كاملة مع Windows Filtering Platform (WFP)
//
// البنية المعمارية:
//   User Space (thor-agent)
//     ↕ Named Pipe (control channel — JSON commands)
//     ↕ Shared Memory Ring Buffer (high-speed packet data)
//     ↕ Event Kernel Object (للإشعار بوجود حزم جديدة)
//   Kernel Space (ThorCallout.sys — WFP callout driver)
//     ↕ WFP Classify callbacks
//     ↕ BFE (Base Filtering Engine)
//
// أداء مستهدف:
//   - قراءة الحزم: < 1µs latency (من shared memory)
//   - إرسال verdict: < 2µs (Named Pipe async)
//   - Throughput: > 1M packets/sec على CPU واحد
//
// SPDX-License-Identifier: GPL-3.0

#![allow(dead_code)] // كثير من الثوابت مستخدمة شرطياً على Windows فقط

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ============================================================================
// Configuration
// ============================================================================

/// إعدادات WFP
#[derive(Debug, Clone, Deserialize)]
pub struct WindowsConfig {
    /// اسم Named Pipe للتواصل مع kernel driver
    pub pipe_name: String,
    /// اسم Shared Memory section
    pub shared_mem_name: String,
    /// حجم Shared Memory buffer بالبايت
    pub shared_mem_size: usize,
    /// اسم Event Object للإشعار
    pub event_name: String,
    /// الحد الأقصى للحزم في ring buffer
    pub ring_capacity: usize,
    /// مهلة الاتصال (ms)
    pub connect_timeout_ms: u32,
    /// تفعيل logging مفصل لكل حزمة (debug فقط)
    pub packet_trace: bool,
}

impl Default for WindowsConfig {
    fn default() -> Self {
        Self {
            pipe_name: r"\\.\pipe\ThorAgent".to_string(),
            shared_mem_name: r"Global\ThorSharedMem".to_string(),
            shared_mem_size: 64 * 1024 * 1024, // 64 MB
            event_name: r"Global\ThorPacketEvent".to_string(),
            ring_capacity: 65_536,
            connect_timeout_ms: 5_000,
            packet_trace: false,
        }
    }
}

// ============================================================================
// Shared Memory Ring Buffer Layout
//
// يتطابق بالضبط مع بنية thor_ring_buffer_t في ThorCallout.sys
//
// Header (64 bytes):
//   [0..4]   magic: u32 = 0x54484f52 ("THOR")
//   [4..8]   version: u32
//   [8..12]  capacity: u32 (entries)
//   [12..16] head: u32 (كاتب — kernel يُحدّثه)
//   [16..20] tail: u32 (قارئ — user space يُحدّثه)
//   [20..24] packet_size: u32 (حجم كل entry بالبايت)
//   [24..32] drops: u64 (حزم أُسقطت لامتلاء البافر)
//   [32..64] padding: [u8; 32]
//
// Entries (من offset 64):
//   هيكل WfpPacketEntry × capacity
// ============================================================================

const RING_MAGIC: u32 = 0x54484f52; // "THOR"
const RING_HEADER_SIZE: usize = 64;

/// حزمة مُلتقطة من WFP callout
/// تتطابق مع thor_packet_entry_t في kernel
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct WfpPacketEntry {
    /// Timestamp بالـ 100-nanosecond intervals منذ 1601-01-01 (Windows FILETIME)
    pub timestamp_filetime: u64,
    /// طول الحزمة الكاملة
    pub packet_len: u32,
    /// offset بداية payload داخل buffer
    pub payload_offset: u16,
    /// طول payload
    pub payload_len: u16,
    /// IP Header: protocol
    pub ip_protocol: u8,
    /// TCP flags (0 لغير TCP)
    pub tcp_flags: u8,
    /// IP TTL
    pub ttl: u8,
    /// padding
    pub _pad: u8,
    /// src IP (IPv4 — MSB أولاً)
    pub src_ip: [u8; 4],
    /// dst IP
    pub dst_ip: [u8; 4],
    /// src port (big-endian)
    pub src_port: u16,
    /// dst port (big-endian)
    pub dst_port: u16,
    /// معرف التدفق داخل WFP
    pub flow_handle: u64,
    /// WFP layer ID
    pub layer_id: u16,
    /// اتجاه: 0=inbound, 1=outbound
    pub direction: u8,
    /// هل هي حزمة إعادة تجميع (reassembled)؟
    pub is_reassembled: u8,
    /// Padding لمحاذاة 64 بايت
    pub _pad2: [u8; 8],
    /// بيانات الحزمة الخام (حتى 1408 بايت)
    pub data: [u8; 1408],
}

const _: () = assert!(
    std::mem::size_of::<WfpPacketEntry>() == 64 + 1408,
    "WfpPacketEntry size mismatch"
);

// ============================================================================
// Control Commands (عبر Named Pipe)
// ============================================================================

/// أمر يُرسله User Space للـ Kernel Driver
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum DriverCommand {
    /// إرسال verdict لتدفق محدد
    Verdict {
        flow_handle: u64,
        allow: bool,
        /// تطبيق الحظر على كل حزم هذا الـ flow حتى انتهاء الاتصال
        persistent: bool,
    },
    /// إضافة CIDR للـ blacklist (kernel يحجب قبل وصول الحزمة لـ callout)
    AddBlacklist {
        ip: [u8; 4],
        prefix_len: u8,
        reason: String,
    },
    /// حذف CIDR من الـ blacklist
    RemoveBlacklist {
        ip: [u8; 4],
        prefix_len: u8,
    },
    /// تحديث sample rate (كل كم حزمة يُرسلها للـ user space)
    SetSampleRate {
        rate: u32,
    },
    /// طلب إحصاءات من kernel
    GetStats,
    /// إعادة تشغيل WFP callout filter
    ReloadFilter,
}

/// استجابة من الـ Kernel Driver
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "snake_case")]
pub enum DriverResponse {
    Ok,
    Error { message: String },
    Stats {
        total_packets: u64,
        total_bytes: u64,
        blocked_flows: u32,
        ring_drops: u64,
    },
}

// ============================================================================
// Windows API Types (cross-compile compatible)
// ============================================================================

#[cfg(target_os = "windows")]
mod win {
    // استيراد windows-rs للتواصل مع WinAPI
    use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle, BOOL};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, ReadFile,
        FILE_SHARE_NONE, FILE_ATTRIBUTE_NORMAL,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
        GENERIC_READ, GENERIC_WRITE,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::Win32::System::Memory::{
        OpenFileMappingW, MapViewOfFile, FILE_MAP_ALL_ACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenEventW, WaitForSingleObject, SYNCHRONIZE, WAIT_OBJECT_0,
    };
    use windows::core::PCWSTR;

    pub use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

    /// تحويل str إلى Wide String لـ WinAPI
    pub fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub struct WinHandle(pub HANDLE);

    impl Drop for WinHandle {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_invalid() {
                unsafe { CloseHandle(self.0); }
            }
        }
    }

    unsafe impl Send for WinHandle {}
    unsafe impl Sync for WinHandle {}
}

// ============================================================================
// WFP Interface
// ============================================================================

/// واجهة WFP الرئيسية
pub struct WFPInterface {
    config: WindowsConfig,
    /// حالة الاتصال
    connected: AtomicBool,
    /// عداد الحزم المستلمة
    packets_received: Arc<AtomicU32>,
    /// عداد الحزم المحجوبة
    packets_blocked: Arc<AtomicU32>,

    // ── Platform-specific handles ──────────────────────────────────────
    #[cfg(target_os = "windows")]
    pipe_handle: Arc<tokio::sync::Mutex<Option<win::WinHandle>>>,

    #[cfg(target_os = "windows")]
    shared_mem_ptr: Option<*mut u8>,

    #[cfg(target_os = "windows")]
    event_handle: Option<win::WinHandle>,
}

// SAFETY: على Windows، shared_mem_ptr محمية بـ ring buffer head/tail atomics
#[cfg(target_os = "windows")]
unsafe impl Send for WFPInterface {}
#[cfg(target_os = "windows")]
unsafe impl Sync for WFPInterface {}

impl WFPInterface {
    pub async fn new(config: &WindowsConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            connected: AtomicBool::new(false),
            packets_received: Arc::new(AtomicU32::new(0)),
            packets_blocked: Arc::new(AtomicU32::new(0)),
            #[cfg(target_os = "windows")]
            pipe_handle: Arc::new(tokio::sync::Mutex::new(None)),
            #[cfg(target_os = "windows")]
            shared_mem_ptr: None,
            #[cfg(target_os = "windows")]
            event_handle: None,
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // connect — Linux stub (ليس WFP متاحاً إلا على Windows)
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    pub async fn connect(&self) -> Result<()> {
        bail!("WFP is only available on Windows. On Linux use eBPF/XDP.");
    }

    // ─────────────────────────────────────────────────────────────────────
    // connect — Windows implementation
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    pub async fn connect(&mut self) -> Result<()> {
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::System::Memory::*;
        use windows::Win32::System::Threading::*;
        use windows::Win32::Foundation::*;

        let pipe_wide = win::to_wide(&self.config.pipe_name);
        let shm_wide  = win::to_wide(&self.config.shared_mem_name);
        let evt_wide  = win::to_wide(&self.config.event_name);

        info!(pipe = %self.config.pipe_name, "Connecting to WFP driver");

        // 1. انتظار Named Pipe حتى يصبح جاهزاً
        let wait_start = std::time::Instant::now();
        loop {
            let available = unsafe {
                WaitNamedPipeW(
                    PCWSTR(pipe_wide.as_ptr()),
                    self.config.connect_timeout_ms,
                )
            };
            if available.as_bool() {
                break;
            }
            if wait_start.elapsed().as_millis() > self.config.connect_timeout_ms as u128 {
                bail!("Timeout waiting for WFP pipe: {}", self.config.pipe_name);
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // 2. فتح Named Pipe
        let pipe = unsafe {
            CreateFileW(
                PCWSTR(pipe_wide.as_ptr()),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                HANDLE::default(),
            )
        }.context("CreateFileW for WFP pipe failed")?;

        if pipe == INVALID_HANDLE_VALUE {
            bail!("Failed to open WFP pipe: INVALID_HANDLE_VALUE");
        }
        info!(pipe = %self.config.pipe_name, "Named pipe opened");

        // 3. الاتصال بـ Shared Memory
        let shm = unsafe {
            OpenFileMappingW(
                FILE_MAP_ALL_ACCESS,
                BOOL(0),
                PCWSTR(shm_wide.as_ptr()),
            )
        }.context("OpenFileMappingW failed — is ThorCallout.sys loaded?")?;

        let shm_ptr = unsafe {
            MapViewOfFile(shm, FILE_MAP_ALL_ACCESS, 0, 0, 0)
        };

        if shm_ptr.is_null() {
            bail!("MapViewOfFile failed — shared memory size mismatch?");
        }

        // 4. التحقق من magic number
        let magic = unsafe { std::ptr::read_volatile(shm_ptr as *const u32) };
        if magic != RING_MAGIC {
            bail!("Shared memory magic mismatch: got 0x{:x}, expected 0x{:x}", magic, RING_MAGIC);
        }

        // 5. فتح Event Object
        let evt = unsafe {
            OpenEventW(SYNCHRONIZE, BOOL(0), PCWSTR(evt_wide.as_ptr()))
        }.context("OpenEventW failed")?;

        // 6. حفظ الـ handles
        *self.pipe_handle.lock().await = Some(win::WinHandle(pipe));
        self.shared_mem_ptr = Some(shm_ptr as *mut u8);
        self.event_handle = Some(win::WinHandle(evt));
        self.connected.store(true, Ordering::SeqCst);

        info!(
            shm = %self.config.shared_mem_name,
            shm_size_mb = self.config.shared_mem_size / 1024 / 1024,
            "WFP interface fully connected"
        );

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // read_packet — قراءة حزمة من ring buffer (non-blocking)
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    pub async fn read_packet(&self) -> Result<Option<WfpPacketEntry>> {
        bail!("WFP not available on this platform");
    }

    #[cfg(target_os = "windows")]
    pub async fn read_packet(&self) -> Result<Option<WfpPacketEntry>> {
        if !self.connected.load(Ordering::Relaxed) {
            bail!("WFP not connected");
        }

        let shm = self.shared_mem_ptr.unwrap();

        // قراءة head و tail من header
        let head = unsafe {
            std::ptr::read_volatile((shm as *const u32).add(3)) // offset 12
        };
        let tail = unsafe {
            std::ptr::read_volatile((shm as *const u32).add(4)) // offset 16
        };
        let capacity = unsafe {
            std::ptr::read_volatile((shm as *const u32).add(2)) // offset 8
        };

        if head == tail {
            return Ok(None); // ring buffer فارغ
        }

        // حساب offset العنصر التالي
        let entry_size = std::mem::size_of::<WfpPacketEntry>();
        let entry_offset = RING_HEADER_SIZE + (tail as usize % capacity as usize) * entry_size;

        // قراءة atomic من shared memory
        let entry = unsafe {
            std::ptr::read_volatile(shm.add(entry_offset) as *const WfpPacketEntry)
        };

        // تحديث tail (نُخبر kernel بأننا قرأنا العنصر)
        unsafe {
            std::ptr::write_volatile(
                (shm as *mut u32).add(4),
                tail.wrapping_add(1),
            );
        }

        self.packets_received.fetch_add(1, Ordering::Relaxed);

        if self.config.packet_trace {
            debug!(
                src_ip = ?entry.src_ip,
                dst_ip = ?entry.dst_ip,
                src_port = u16::from_be(entry.src_port),
                dst_port = u16::from_be(entry.dst_port),
                len = entry.packet_len,
                "WFP packet read"
            );
        }

        Ok(Some(entry))
    }

    // ─────────────────────────────────────────────────────────────────────
    // wait_for_packets — ينتظر إشعار kernel بوجود حزم جديدة
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    pub async fn wait_for_packets(&self, timeout_ms: u32) -> Result<bool> {
        bail!("WFP not available on this platform");
    }

    #[cfg(target_os = "windows")]
    pub async fn wait_for_packets(&self, timeout_ms: u32) -> Result<bool> {
        use windows::Win32::System::Threading::{WaitForSingleObject, WAIT_OBJECT_0};

        if !self.connected.load(Ordering::Relaxed) {
            bail!("WFP not connected");
        }

        let evt = self.event_handle.as_ref().unwrap().0;
        let result = unsafe { WaitForSingleObject(evt, timeout_ms) };

        Ok(result == WAIT_OBJECT_0)
    }

    // ─────────────────────────────────────────────────────────────────────
    // send_verdict — إرسال قرار حظر/سماح للـ kernel
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    pub async fn send_verdict(&self, flow_handle: u64, allow: bool, persistent: bool) -> Result<()> {
        bail!("WFP not available on this platform");
    }

    #[cfg(target_os = "windows")]
    pub async fn send_verdict(&self, flow_handle: u64, allow: bool, persistent: bool) -> Result<()> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        use windows::Win32::Foundation::BOOL;

        if !self.connected.load(Ordering::Relaxed) {
            bail!("WFP not connected");
        }

        let cmd = DriverCommand::Verdict { flow_handle, allow, persistent };
        let payload = serde_json::to_vec(&cmd).context("Serialize verdict failed")?;

        let pipe_guard = self.pipe_handle.lock().await;
        let pipe = pipe_guard.as_ref().unwrap().0;

        // كتابة المُعرِّف (4 bytes) ثم الـ payload
        let len_bytes = (payload.len() as u32).to_le_bytes();
        let mut written = 0u32;

        unsafe {
            WriteFile(pipe, Some(&len_bytes), Some(&mut written), None)
                .context("WriteFile length failed")?;
            WriteFile(pipe, Some(payload.as_slice()), Some(&mut written), None)
                .context("WriteFile payload failed")?;
        }

        if !allow {
            self.packets_blocked.fetch_add(1, Ordering::Relaxed);
        }

        debug!(flow = flow_handle, allow = allow, "Verdict sent to WFP driver");
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // update_blacklist — تحديث blacklist مباشرة في kernel
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    pub async fn update_blacklist(&self, ip: [u8; 4], prefix_len: u8, reason: &str, add: bool) -> Result<()> {
        let cmd = if add {
            DriverCommand::AddBlacklist { ip, prefix_len, reason: reason.to_string() }
        } else {
            DriverCommand::RemoveBlacklist { ip, prefix_len }
        };

        self.send_command(cmd).await
    }

    #[cfg(target_os = "windows")]
    async fn send_command(&self, cmd: DriverCommand) -> Result<()> {
        use windows::Win32::Storage::FileSystem::WriteFile;

        let payload = serde_json::to_vec(&cmd).context("Serialize command failed")?;
        let pipe_guard = self.pipe_handle.lock().await;
        let pipe = pipe_guard.as_ref().unwrap().0;

        let len_bytes = (payload.len() as u32).to_le_bytes();
        let mut written = 0u32;

        unsafe {
            WriteFile(pipe, Some(&len_bytes), Some(&mut written), None)?;
            WriteFile(pipe, Some(payload.as_slice()), Some(&mut written), None)?;
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // recv_response — استقبال استجابة من kernel
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    async fn recv_response(&self) -> Result<DriverResponse> {
        use windows::Win32::Storage::FileSystem::ReadFile;

        let pipe_guard = self.pipe_handle.lock().await;
        let pipe = pipe_guard.as_ref().unwrap().0;

        // قراءة الطول أولاً
        let mut len_buf = [0u8; 4];
        let mut read = 0u32;
        unsafe {
            ReadFile(pipe, Some(&mut len_buf), Some(&mut read), None)
                .context("ReadFile length failed")?;
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 65_536 {
            bail!("Invalid response length from WFP driver: {}", len);
        }

        let mut payload = vec![0u8; len];
        unsafe {
            ReadFile(pipe, Some(&mut payload), Some(&mut read), None)
                .context("ReadFile payload failed")?;
        }

        serde_json::from_slice(&payload).context("Deserialize driver response failed")
    }

    // ─────────────────────────────────────────────────────────────────────
    // get_stats — إحصاءات من kernel driver
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    pub async fn get_stats(&self) -> Result<DriverResponse> {
        self.send_command(DriverCommand::GetStats).await?;
        self.recv_response().await
    }

    // ─────────────────────────────────────────────────────────────────────
    // run_packet_loop — الحلقة الرئيسية لقراءة الحزم وإرسالها للـ RL
    // ─────────────────────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    pub async fn run_packet_loop(
        &self,
        packet_tx: tokio::sync::mpsc::Sender<WfpPacketEntry>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<()> {
        info!("WFP packet loop starting");

        while !shutdown.load(Ordering::Relaxed) {
            // انتظر إشعار kernel (أو timeout 10ms للتحقق من shutdown)
            match self.wait_for_packets(10).await {
                Ok(true) => {
                    // استنزف ring buffer
                    loop {
                        match self.read_packet().await {
                            Ok(Some(pkt)) => {
                                if packet_tx.send(pkt).await.is_err() {
                                    warn!("Packet channel closed, stopping WFP loop");
                                    return Ok(());
                                }
                            }
                            Ok(None) => break, // ring buffer فارغ
                            Err(e) => {
                                error!(error = %e, "WFP packet read error");
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                                break;
                            }
                        }
                    }
                }
                Ok(false) => {} // timeout — check shutdown
                Err(e) => {
                    error!(error = %e, "WFP wait error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }

        info!("WFP packet loop stopped");
        Ok(())
    }

    // Stats accessors
    pub fn packets_received(&self) -> u32 {
        self.packets_received.load(Ordering::Relaxed)
    }

    pub fn packets_blocked(&self) -> u32 {
        self.packets_blocked.load(Ordering::Relaxed)
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Conversion: WfpPacketEntry → ParsedPacket (لاستخدام نفس ML pipeline)
// ============================================================================

impl WfpPacketEntry {
    /// تحويل WFP packet entry إلى ParsedPacket للتحليل بنفس pipeline Linux
    pub fn to_parsed_packet(&self) -> crate::packet_parser::ParsedPacket {
        use std::net::{IpAddr, Ipv4Addr};
        use crate::packet_parser::{FlowKey, Protocol, TcpFlags, ParsedPacket};

        // تحويل FILETIME إلى nanoseconds منذ UNIX epoch
        // FILETIME: 100-ns intervals منذ 1601-01-01
        // الفرق بين 1601 و 1970 = 11644473600 ثانية
        let timestamp_ns = if self.timestamp_filetime > 116_444_736_000_000_000 {
            (self.timestamp_filetime - 116_444_736_000_000_000) * 100
        } else {
            0
        };

        let src_ip = IpAddr::V4(Ipv4Addr::from(self.src_ip));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(self.dst_ip));

        ParsedPacket {
            flow_key: FlowKey {
                src_ip,
                dst_ip,
                src_port: u16::from_be(self.src_port),
                dst_port: u16::from_be(self.dst_port),
                protocol: Protocol::from(self.ip_protocol),
            },
            timestamp_ns,
            packet_len: self.packet_len as u16,
            ttl: self.ttl,
            dscp: 0,
            tcp_flags: if self.ip_protocol == 6 {
                Some(TcpFlags(self.tcp_flags))
            } else {
                None
            },
            tcp_window: None,
            tcp_seq: None,
            payload_entropy: 0.0, // يُحسب لاحقاً إذا لزم
            payload_len: self.payload_len,
            is_tunneled: false,
            inbound: self.direction == 0,
        }
    }
}
