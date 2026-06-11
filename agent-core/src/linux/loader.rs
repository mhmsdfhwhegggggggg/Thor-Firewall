//! Thor Firewall — eBPF Loader (Linux)
//! يحمّل برامج XDP من ملفات .o إلى kernel ويقرأ إحصائياتها عبر aya-rs
//! الاستخدام: let loader = EbpfLoader::new("eth0"); loader.load("xdp_syn_flood.o").await?;

#![cfg(target_os = "linux")]

use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, PerCpuValues},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;

// ── الهياكل ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct XdpStats {
    pub blocked_packets:  u64,
    pub passed_packets:   u64,
    pub throttled_packets: u64,
    pub total_bytes:      u64,
    pub syn_flood_count:  u64,
    pub port_scan_count:  u64,
}

#[derive(Debug)]
pub struct LoadedProgram {
    pub name:      String,
    pub iface:     String,
    pub obj_path:  PathBuf,
    pub flags:     XdpFlags,
}

// ── EbpfLoader ────────────────────────────────────────────────────────────────

pub struct EbpfLoader {
    iface:    String,
    programs: Arc<RwLock<HashMap<String, LoadedProgram>>>,
    bpf:      Arc<RwLock<Option<Bpf>>>,
    obj_dir:  PathBuf,
}

impl EbpfLoader {
    /// إنشاء loader جديد
    /// `iface` — اسم الواجهة الشبكية (مثل "eth0")
    /// `obj_dir` — مسار مجلد ملفات .o المُجمَّعة
    pub fn new(iface: &str, obj_dir: &Path) -> Self {
        Self {
            iface: iface.to_string(),
            programs: Arc::new(RwLock::new(HashMap::new())),
            bpf: Arc::new(RwLock::new(None)),
            obj_dir: obj_dir.to_path_buf(),
        }
    }

    /// تحميل برنامج XDP من ملف .o وتعليقه على الواجهة الشبكية
    pub async fn load_xdp(
        &self,
        obj_filename: &str,
        program_name: &str,
        flags: XdpFlags,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let obj_path = self.obj_dir.join(obj_filename);

        if !obj_path.exists() {
            return Err(format!(
                "eBPF object file not found: {}. \
                Run 'make build-ebpf' to compile.",
                obj_path.display()
            ).into());
        }

        log::info!(
            "Loading eBPF program '{}' from {} onto {}...",
            program_name, obj_path.display(), self.iface
        );

        // تحميل ملف .o
        let bpf = Bpf::load_file(&obj_path)
            .map_err(|e| format!("Failed to load eBPF object: {e}"))?;

        // الحصول على برنامج XDP
        let program: &mut Xdp = bpf
            .program_mut(program_name)
            .ok_or_else(|| format!("Program '{program_name}' not found in {obj_filename}"))?
            .try_into()
            .map_err(|e| format!("Not an XDP program: {e}"))?;

        // تحميل البرنامج إلى الـ kernel
        program.load()
            .map_err(|e| format!("Failed to load XDP into kernel: {e}"))?;

        // تعليق البرنامج على الواجهة
        program.attach(&self.iface, flags)
            .map_err(|e| format!("Failed to attach XDP to {}: {e}", self.iface))?;

        log::info!(
            "✓ XDP program '{}' attached to {} (flags={:?})",
            program_name, self.iface, flags
        );

        // حفظ البرنامج
        let mut bpf_guard = self.bpf.write().await;
        *bpf_guard = Some(bpf);

        let mut progs = self.programs.write().await;
        progs.insert(program_name.to_string(), LoadedProgram {
            name:     program_name.to_string(),
            iface:    self.iface.clone(),
            obj_path: obj_path.to_path_buf(),
            flags,
        });

        Ok(())
    }

    /// قراءة إحصائيات XDP من eBPF maps
    pub async fn read_stats(&self) -> Result<XdpStats, Box<dyn std::error::Error>> {
        let bpf_guard = self.bpf.read().await;
        let bpf = bpf_guard.as_ref()
            .ok_or("No eBPF program loaded")?;

        // قراءة BLOCKED_PACKETS counter
        let blocked = self.read_percpu_counter(bpf, "BLOCKED_PACKETS").unwrap_or(0);
        let passed  = self.read_percpu_counter(bpf, "PASSED_PACKETS").unwrap_or(0);
        let throttled = self.read_percpu_counter(bpf, "THROTTLED_PACKETS").unwrap_or(0);
        let total_bytes = self.read_percpu_counter(bpf, "TOTAL_BYTES").unwrap_or(0);
        let syn_flood = self.read_percpu_counter(bpf, "SYN_FLOOD_COUNT").unwrap_or(0);
        let port_scan = self.read_percpu_counter(bpf, "PORT_SCAN_COUNT").unwrap_or(0);

        Ok(XdpStats {
            blocked_packets:   blocked,
            passed_packets:    passed,
            throttled_packets: throttled,
            total_bytes,
            syn_flood_count:   syn_flood,
            port_scan_count:   port_scan,
        })
    }

    /// قراءة قيمة per-CPU counter من eBPF map وجمع قيم كل CPU
    fn read_percpu_counter(&self, bpf: &Bpf, map_name: &str) -> Option<u64> {
        let map = bpf.map(map_name)?;
        // يُفترض أن الـ map من نوع PerCpuArray بمفتاح u32 وقيمة u64
        let typed_map: aya::maps::PerCpuArray<_, u64> =
            aya::maps::PerCpuArray::try_from(map).ok()?;
        let values: PerCpuValues<u64> = typed_map.get(&0u32, 0).ok()?;
        Some(values.iter().sum())
    }

    /// تحديث قائمة IPs المحظورة في eBPF map BLOCKED_IPS
    pub async fn update_blocked_ips(
        &self,
        ips: &[u32],
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut bpf_guard = self.bpf.write().await;
        let bpf = bpf_guard.as_mut()
            .ok_or("No eBPF program loaded")?;

        let mut map: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(bpf.map_mut("BLOCKED_IPS")
                .ok_or("Map 'BLOCKED_IPS' not found")?)?;

        let mut count = 0usize;
        for &ip in ips {
            if map.insert(ip, 1u8, 0).is_ok() {
                count += 1;
            }
        }

        log::info!("Updated BLOCKED_IPS map: {count} IPs inserted");
        Ok(count)
    }

    /// إزالة IP من قائمة الحظر
    pub async fn unblock_ip(&self, ip: u32) -> Result<(), Box<dyn std::error::Error>> {
        let mut bpf_guard = self.bpf.write().await;
        let bpf = bpf_guard.as_mut()
            .ok_or("No eBPF program loaded")?;

        let mut map: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(bpf.map_mut("BLOCKED_IPS")
                .ok_or("Map 'BLOCKED_IPS' not found")?)?;

        map.remove(&ip)?;
        log::info!("Unblocked IP: {}.{}.{}.{}",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF);
        Ok(())
    }

    /// قراءة دورية للإحصائيات كل N ثانية
    pub async fn start_stats_collector(
        self: Arc<Self>,
        interval_secs: u64,
        mut callback: impl FnMut(XdpStats) + Send + 'static,
    ) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(
                Duration::from_secs(interval_secs)
            );
            loop {
                ticker.tick().await;
                match self.read_stats().await {
                    Ok(stats) => callback(stats),
                    Err(e) => log::warn!("Failed to read XDP stats: {e}"),
                }
            }
        });
    }

    /// إلغاء تحميل جميع البرامج
    pub async fn unload_all(&self) {
        let mut bpf_guard = self.bpf.write().await;
        *bpf_guard = None;  // Drop → aya يُلغي تعليق البرامج تلقائياً
        let mut progs = self.programs.write().await;
        progs.clear();
        log::info!("All eBPF programs unloaded from {}", self.iface);
    }

    pub async fn loaded_programs(&self) -> Vec<String> {
        self.programs.read().await.keys().cloned().collect()
    }
}

// ── اختبارات ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_load_missing_file_returns_error() {
        let tmp = TempDir::new().unwrap();
        let loader = EbpfLoader::new("lo", tmp.path());
        let result = loader.load_xdp(
            "nonexistent.o", "xdp_prog", XdpFlags::default()
        ).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_read_stats_without_load_returns_error() {
        let tmp = TempDir::new().unwrap();
        let loader = EbpfLoader::new("lo", tmp.path());
        let result = loader.read_stats().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_loaded_programs_empty_initially() {
        let tmp = TempDir::new().unwrap();
        let loader = EbpfLoader::new("lo", tmp.path());
        assert!(loader.loaded_programs().await.is_empty());
    }
}
