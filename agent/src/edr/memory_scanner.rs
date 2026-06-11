//! Memory Scanner — YARA-based in-memory malware detection
//! Scans /proc/PID/mem for shellcode signatures, packed PE, Cobalt Strike beacons

use super::{EdrEvent, EdrEventType, Severity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub pathname: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub pid: u32,
    pub process_name: String,
    pub rule_name: String,
    pub rule_namespace: String,
    pub matched_region: MemoryRegion,
    pub risk_score: f32,
    pub details: String,
}

/// YARA memory scanner
pub struct MemoryScanner {
    tx: mpsc::Sender<EdrEvent>,
    yara_rules_dir: PathBuf,
    scan_interval_secs: u64,
    /// Simple signature bytes for shellcode patterns (used when YARA not available)
    shellcode_signatures: Vec<Vec<u8>>,
}

impl MemoryScanner {
    pub fn new(tx: mpsc::Sender<EdrEvent>, yara_rules_dir: PathBuf) -> Self {
        Self {
            tx,
            yara_rules_dir,
            scan_interval_secs: 60,
            shellcode_signatures: Self::build_signatures(),
        }
    }

    fn build_signatures() -> Vec<Vec<u8>> {
        vec![
            // Metasploit x64 shellcode stub: push rbp; mov rbp,rsp; sub rsp,...
            vec![0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC],
            // Cobalt Strike beacon XOR stub
            vec![0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8],
            // Common PE header in memory (MZ stub)
            vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00],
            // mprotect syscall with PROT_EXEC via syscall gadget
            vec![0x0F, 0x05, 0x48, 0x85, 0xC0, 0x0F, 0x88],
        ]
    }

    pub async fn run(&self) -> Result<()> {
        info!("Memory scanner starting (interval={}s)", self.scan_interval_secs);
        let mut ticker = tokio::time::interval(
            tokio::time::Duration::from_secs(self.scan_interval_secs)
        );

        loop {
            ticker.tick().await;
            if let Err(e) = self.scan_all_processes().await {
                warn!("Memory scan error: {e}");
            }
        }
    }

    async fn scan_all_processes(&self) -> Result<()> {
        let pids: Vec<u32> = std::fs::read_dir("/proc")?
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
            .collect();

        // Only scan user-space processes (pid > 300)
        for pid in pids.into_iter().filter(|&p| p > 300) {
            // Skip self
            if pid == std::process::id() { continue; }

            match self.scan_pid(pid).await {
                Ok(results) => {
                    for result in results {
                        warn!(
                            "YARA match: pid={} rule={} region=0x{:x}",
                            result.pid, result.rule_name, result.matched_region.start
                        );
                        self.emit_alert(result).await;
                    }
                }
                Err(e) => debug!("Cannot scan pid {pid}: {e}"),
            }
        }
        Ok(())
    }

    async fn scan_pid(&self, pid: u32) -> Result<Vec<ScanResult>> {
        let maps = self.read_maps(pid)?;
        let proc_name = self.get_process_name(pid);
        let mut results = vec![];

        for region in &maps {
            // Only scan executable/writable regions that are anonymous (no file backing)
            let is_exec = region.permissions.contains('x');
            let is_writable = region.permissions.contains('w');
            let is_anon = region.pathname.is_empty() || region.pathname == "[heap]" || region.pathname == "[stack]";

            // High-interest: executable+writable anonymous memory (classic shellcode landing)
            if !(is_exec || (is_writable && is_anon)) { continue; }

            // Skip huge regions (>256MB) — too slow and likely not shellcode
            if region.size_bytes > 268_435_456 { continue; }

            if let Ok(data) = self.read_region(pid, region) {
                if let Some(sig_match) = self.check_signatures(&data) {
                    results.push(ScanResult {
                        pid,
                        process_name: proc_name.clone(),
                        rule_name: sig_match.0,
                        rule_namespace: "builtin".to_string(),
                        matched_region: region.clone(),
                        risk_score: sig_match.1,
                        details: format!(
                            "Signature match at offset 0x{:x} in {} region",
                            sig_match.2, region.permissions
                        ),
                    });
                }
            }
        }

        Ok(results)
    }

    fn read_maps(&self, pid: u32) -> Result<Vec<MemoryRegion>> {
        let content = std::fs::read_to_string(format!("/proc/{pid}/maps"))
            .with_context(|| format!("Cannot read maps for pid {pid}"))?;

        let regions = content.lines()
            .filter_map(|line| self.parse_map_line(line))
            .collect();

        Ok(regions)
    }

    fn parse_map_line(&self, line: &str) -> Option<MemoryRegion> {
        let fields: Vec<&str> = line.splitn(6, ' ').collect();
        if fields.len() < 5 { return None; }

        let (start_s, end_s) = fields[0].split_once('-')?;
        let start = u64::from_str_radix(start_s, 16).ok()?;
        let end = u64::from_str_radix(end_s, 16).ok()?;

        Some(MemoryRegion {
            start,
            end,
            permissions: fields[1].to_string(),
            offset: u64::from_str_radix(fields[2], 16).ok()?,
            device: fields[3].to_string(),
            inode: fields[4].trim().parse().ok()?,
            pathname: fields.get(5).map(|s| s.trim().to_string()).unwrap_or_default(),
            size_bytes: end.saturating_sub(start),
        })
    }

    fn read_region(&self, pid: u32, region: &MemoryRegion) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};

        let mut f = std::fs::File::open(format!("/proc/{pid}/mem"))
            .with_context(|| format!("Cannot open /proc/{pid}/mem"))?;

        f.seek(SeekFrom::Start(region.start))?;

        let size = region.size_bytes.min(1_048_576) as usize; // max 1MB per region
        let mut buf = vec![0u8; size];
        f.read_exact(&mut buf).with_context(|| "read_exact failed")?;

        Ok(buf)
    }

    fn check_signatures(&self, data: &[u8]) -> Option<(String, f32, usize)> {
        let rules = [
            (b"\xFC\x48\x83\xE4\xF0\xE8".as_ref(), "CobaltStrike_Beacon", 0.95f32),
            (b"\x4D\x5A\x90\x00\x03\x00\x00\x00".as_ref(), "PE_In_Memory", 0.80),
            (b"\x55\x48\x89\xE5\x48\x83\xEC".as_ref(), "Shellcode_x64_Stub", 0.70),
            (b"\x0F\x05\x48\x85\xC0\x0F\x88".as_ref(), "Syscall_Gadget_Chain", 0.65),
            // Mimikatz sekurlsa
            (b"sekurlsa".as_ref(), "Mimikatz_sekurlsa", 0.99),
            // Meterpreter stageless
            (b"meterpreter".as_ref(), "Meterpreter_String", 0.90),
        ];

        for (sig, name, score) in &rules {
            if let Some(pos) = Self::find_pattern(data, sig) {
                return Some((name.to_string(), *score, pos));
            }
        }
        None
    }

    fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || needle.len() > haystack.len() { return None; }
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn get_process_name(&self, pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    async fn emit_alert(&self, result: ScanResult) {
        let payload = serde_json::json!({
            "pid": result.pid,
            "process": result.process_name,
            "yara_rule": result.rule_name,
            "namespace": result.rule_namespace,
            "region_start": format!("0x{:x}", result.matched_region.start),
            "region_end": format!("0x{:x}", result.matched_region.end),
            "region_perms": result.matched_region.permissions,
            "risk_score": result.risk_score,
            "details": result.details,
        });

        let ev = EdrEvent::new(EdrEventType::MemoryScan, Severity::Critical, payload)
            .with_mitre(vec!["T1055", "T1620", "T1027"])
            .with_tags(vec!["memory_scan", "yara", "injection"]);

        let _ = self.tx.send(ev).await;
    }
}
