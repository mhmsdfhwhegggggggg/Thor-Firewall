//! Linux EDR core — reads from eBPF ring buffer, enriches events, ships to control-plane
//! Uses /proc filesystem for process enrichment and fanotify for file monitoring fallback

use super::{EdrEvent, EdrEventType, Severity};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

const RING_BUF_PATH: &str = "/sys/fs/bpf/thor_events";
const PROC_BATCH_SIZE: usize = 64;
const FLUSH_INTERVAL_MS: u64 = 500;

/// Main Linux EDR runtime
pub struct LinuxEdr {
    tx: mpsc::Sender<EdrEvent>,
    process_cache: Arc<tokio::sync::RwLock<HashMap<u32, ProcessInfo>>>,
    config: EdrConfig,
}

#[derive(Debug, Clone)]
pub struct EdrConfig {
    pub control_plane_url: String,
    pub api_key: String,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub excluded_pids: Vec<u32>,
    pub excluded_paths: Vec<PathBuf>,
    pub enable_memory_scan: bool,
    pub yara_rules_dir: PathBuf,
}

impl Default for EdrConfig {
    fn default() -> Self {
        Self {
            control_plane_url: "https://thor-cp:8443".to_string(),
            api_key: String::new(),
            batch_size: PROC_BATCH_SIZE,
            flush_interval_ms: FLUSH_INTERVAL_MS,
            excluded_pids: vec![1, 2], // init, kthreadd
            excluded_paths: vec![
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
                PathBuf::from("/dev"),
            ],
            enable_memory_scan: true,
            yara_rules_dir: PathBuf::from("/etc/thor/yara"),
        }
    }
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    exe: PathBuf,
    cmdline: String,
    uid: u32,
    gid: u32,
    start_time: u64,
    container_id: Option<String>,
}

impl LinuxEdr {
    pub fn new(config: EdrConfig) -> (Self, mpsc::Receiver<EdrEvent>) {
        let (tx, rx) = mpsc::channel(4096);
        let edr = Self {
            tx,
            process_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            config,
        };
        (edr, rx)
    }

    /// Main run loop — spawns all telemetry collectors
    pub async fn run(self) -> Result<()> {
        info!("Thor Linux EDR starting");

        // Snapshot current processes
        self.snapshot_proc_tree().await?;

        // Spawn parallel collectors
        let process_tx = self.tx.clone();
        let file_tx = self.tx.clone();
        let net_tx = self.tx.clone();
        let cache = self.process_cache.clone();
        let config = self.config.clone();

        let h1 = tokio::spawn(async move {
            Self::poll_proc_events(process_tx, cache, config.excluded_pids).await
        });

        let h2 = tokio::spawn(async move {
            Self::poll_file_events(file_tx, config.excluded_paths).await
        });

        let h3 = tokio::spawn(async move {
            Self::poll_network_events(net_tx).await
        });

        tokio::try_join!(
            async { h1.await.map_err(|e| anyhow::anyhow!("{e}"))? },
            async { h2.await.map_err(|e| anyhow::anyhow!("{e}"))? },
            async { h3.await.map_err(|e| anyhow::anyhow!("{e}"))? },
        )?;

        Ok(())
    }

    /// Read /proc to build initial process tree
    async fn snapshot_proc_tree(&self) -> Result<()> {
        let mut cache = self.process_cache.write().await;

        let entries = std::fs::read_dir("/proc")
            .context("Cannot read /proc")?;

        for entry in entries.flatten() {
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            if let Ok(pid) = fname_str.parse::<u32>() {
                if let Ok(info) = Self::read_proc_info(pid) {
                    cache.insert(pid, info);
                }
            }
        }

        info!("Snapshotted {} processes from /proc", cache.len());
        Ok(())
    }

    fn read_proc_info(pid: u32) -> Result<ProcessInfo> {
        let base = format!("/proc/{pid}");

        let cmdline = std::fs::read_to_string(format!("{base}/cmdline"))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let status = std::fs::read_to_string(format!("{base}/status"))
            .unwrap_or_default();

        let mut ppid = 0u32;
        let mut name = String::new();
        let mut uid = 0u32;
        let mut gid = 0u32;

        for line in status.lines() {
            if line.starts_with("Name:") {
                name = line.split_whitespace().nth(1).unwrap_or("").to_string();
            } else if line.starts_with("PPid:") {
                ppid = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            } else if line.starts_with("Uid:") {
                uid = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            } else if line.starts_with("Gid:") {
                gid = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            }
        }

        let exe = std::fs::read_link(format!("{base}/exe"))
            .unwrap_or_else(|_| PathBuf::from("unknown"));

        let container_id = Self::detect_container(pid);

        Ok(ProcessInfo { pid, ppid, name, exe, cmdline, uid, gid, start_time: 0, container_id })
    }

    fn detect_container(pid: u32) -> Option<String> {
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        // Docker: 12 hex chars; containerd: similar pattern
        for line in cgroup.lines() {
            if let Some(idx) = line.rfind('/') {
                let id = &line[idx + 1..];
                if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id[..12].to_string());
                }
                // k8s pods
                if id.starts_with("docker-") || id.ends_with(".scope") {
                    return Some(id.to_string());
                }
            }
        }
        None
    }

    async fn poll_proc_events(
        tx: mpsc::Sender<EdrEvent>,
        cache: Arc<tokio::sync::RwLock<HashMap<u32, ProcessInfo>>>,
        excluded: Vec<u32>,
    ) -> Result<()> {
        // In production this reads from eBPF ring buffer at RING_BUF_PATH
        // Fallback: poll /proc every 100ms for new/gone PIDs
        let mut ticker = interval(Duration::from_millis(100));
        let mut known: HashMap<u32, ()> = HashMap::new();

        loop {
            ticker.tick().await;

            let current: Vec<u32> = std::fs::read_dir("/proc")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
                .collect();

            let current_set: HashMap<u32, ()> = current.iter().map(|p| (*p, ())).collect();

            // New processes
            for &pid in &current {
                if !known.contains_key(&pid) && !excluded.contains(&pid) {
                    if let Ok(info) = Self::read_proc_info(pid) {
                        let is_suspicious = Self::check_process_anomaly(&info);
                        let severity = if is_suspicious { Severity::High } else { Severity::Info };

                        let payload = serde_json::json!({
                            "pid": info.pid,
                            "ppid": info.ppid,
                            "name": info.name,
                            "exe": info.exe.to_string_lossy(),
                            "cmdline": info.cmdline,
                            "uid": info.uid,
                            "gid": info.gid,
                            "container_id": info.container_id,
                        });

                        let mut ev = EdrEvent::new(EdrEventType::ProcessCreate, severity, payload);

                        if is_suspicious {
                            ev = ev.with_mitre(vec!["T1059", "T1055"]);
                        }

                        cache.write().await.insert(pid, info);
                        let _ = tx.send(ev).await;
                    }
                    known.insert(pid, ());
                }
            }

            // Terminated processes
            known.retain(|pid, _| {
                if !current_set.contains_key(pid) {
                    // Process died — don't send event for every termination, only track
                    false
                } else {
                    true
                }
            });
        }
    }

    fn check_process_anomaly(info: &ProcessInfo) -> bool {
        // Suspicious indicators
        let suspicious_names = ["nc", "ncat", "netcat", "socat", "curl", "wget",
                                 "python", "python3", "perl", "ruby", "php",
                                 "bash", "sh", "zsh", "ksh"];

        let suspicious_paths = ["/tmp/", "/dev/shm/", "/run/", "/var/tmp/"];

        let exe_str = info.exe.to_string_lossy();

        // Shell or interpreter running from suspicious path
        if suspicious_names.iter().any(|n| info.name == *n) &&
           suspicious_paths.iter().any(|p| exe_str.contains(p)) {
            return true;
        }

        // Running as root with suspicious cmdline
        if info.uid == 0 && info.cmdline.contains("chmod 777") {
            return true;
        }

        // Process name doesn't match exe (masquerading)
        if let Some(exe_name) = info.exe.file_name() {
            let exe_str = exe_name.to_string_lossy();
            if !exe_str.is_empty() && info.name != exe_str && info.name.len() > 0 {
                // Known masquerading trick: sshd running from /tmp
                if info.exe.starts_with("/tmp") {
                    return true;
                }
            }
        }

        false
    }

    async fn poll_file_events(
        tx: mpsc::Sender<EdrEvent>,
        excluded: Vec<PathBuf>,
    ) -> Result<()> {
        // Production: use fanotify or inotify via /proc/self/fd
        // Here: monitor critical paths via inotify-style polling
        let critical_paths = vec![
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/crontab", "/etc/hosts", "/root/.ssh/authorized_keys",
        ];

        let mut mtimes: HashMap<String, u64> = HashMap::new();

        // Initialize baseline
        for path in &critical_paths {
            if let Ok(meta) = std::fs::metadata(path) {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                mtimes.insert(path.to_string(), mtime);
            }
        }

        let mut ticker = interval(Duration::from_secs(5));

        loop {
            ticker.tick().await;

            for path in &critical_paths {
                if let Ok(meta) = std::fs::metadata(path) {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    let old_mtime = mtimes.get(*path).copied().unwrap_or(0);

                    if mtime > old_mtime {
                        warn!("Critical file modified: {path}");

                        let payload = serde_json::json!({
                            "path": path,
                            "event": "modify",
                            "old_mtime": old_mtime,
                            "new_mtime": mtime,
                        });

                        let ev = EdrEvent::new(EdrEventType::FileModify, Severity::High, payload)
                            .with_mitre(vec!["T1098", "T1543"])
                            .with_tags(vec!["file_integrity", "critical_path"]);

                        let _ = tx.send(ev).await;
                        mtimes.insert(path.to_string(), mtime);
                    }
                }
            }
        }
    }

    async fn poll_network_events(tx: mpsc::Sender<EdrEvent>) -> Result<()> {
        // Read /proc/net/tcp and /proc/net/tcp6 for connection tracking
        let mut ticker = interval(Duration::from_secs(2));
        let mut known_connections: HashMap<String, ()> = HashMap::new();

        loop {
            ticker.tick().await;

            if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
                for line in tcp.lines().skip(1) {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() < 4 { continue; }

                    let state = fields[3];
                    // State 01 = ESTABLISHED
                    if state != "01" { continue; }

                    let local = Self::parse_hex_addr(fields[1]);
                    let remote = Self::parse_hex_addr(fields[2]);
                    let key = format!("{local}->{remote}");

                    if !known_connections.contains_key(&key) {
                        let (local_ip, local_port) = local.split_once(':').unwrap_or(("", "0"));
                        let (remote_ip, remote_port) = remote.split_once(':').unwrap_or(("", "0"));

                        let payload = serde_json::json!({
                            "local_addr": local_ip,
                            "local_port": local_port.parse::<u16>().unwrap_or(0),
                            "remote_addr": remote_ip,
                            "remote_port": remote_port.parse::<u16>().unwrap_or(0),
                            "protocol": "tcp",
                            "state": "established",
                        });

                        let ev = EdrEvent::new(EdrEventType::NetworkConnect, Severity::Info, payload);
                        let _ = tx.send(ev).await;
                        known_connections.insert(key, ());
                    }
                }

                // Cleanup closed connections
                known_connections.clear(); // Re-build each cycle
            }
        }
    }

    fn parse_hex_addr(hex: &str) -> String {
        let parts: Vec<&str> = hex.split(':').collect();
        if parts.len() != 2 { return hex.to_string(); }

        let addr_hex = parts[0];
        let port_hex = parts[1];

        // Little-endian hex to IP
        if addr_hex.len() == 8 {
            let addr_u32 = u32::from_str_radix(addr_hex, 16).unwrap_or(0);
            let b = addr_u32.to_le_bytes();
            let ip = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
            let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
            format!("{ip}:{port}")
        } else {
            hex.to_string()
        }
    }
}

use std::time::SystemTime;
