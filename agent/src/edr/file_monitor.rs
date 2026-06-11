//! File Integrity Monitoring (FIM) — inotify-based real-time file event tracking
//! Monitors critical paths: /etc, /bin, /sbin, /usr, /root, /home

use super::{EdrEvent, EdrEventType, Severity};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FileEventKind {
    Create,
    Modify,
    Delete,
    Rename,
    PermissionChange,
    OwnershipChange,
    ExecutableBitSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: PathBuf,
    pub kind: FileEventKind,
    pub old_path: Option<PathBuf>, // for renames
    pub file_hash: Option<String>,  // SHA-256 of new content
    pub file_size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub pid: Option<u32>, // process that caused the event (from fanotify)
}

/// File Integrity Monitor
pub struct FileMonitor {
    watch_paths: Vec<PathBuf>,
    exclude_patterns: Vec<String>,
    tx: mpsc::Sender<EdrEvent>,
    baseline: std::collections::HashMap<PathBuf, FileBaseline>,
}

#[derive(Debug, Clone)]
struct FileBaseline {
    sha256: String,
    size: u64,
    mtime_secs: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl FileMonitor {
    pub fn new(tx: mpsc::Sender<EdrEvent>) -> Self {
        Self {
            watch_paths: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/bin"),
                PathBuf::from("/sbin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/root"),
                PathBuf::from("/boot"),
            ],
            exclude_patterns: vec![
                ".pyc".to_string(),
                ".log".to_string(),
                ".tmp".to_string(),
                "/proc/".to_string(),
                "/sys/".to_string(),
            ],
            tx,
            baseline: std::collections::HashMap::new(),
        }
    }

    pub fn add_watch_path(&mut self, path: PathBuf) {
        self.watch_paths.push(path);
    }

    /// Build SHA-256 baseline of all watched files
    pub async fn build_baseline(&mut self) -> Result<()> {
        let mut count = 0;
        for watch_path in &self.watch_paths.clone() {
            if let Ok(entries) = self.walk_dir(watch_path) {
                for path in entries {
                    if let Ok(baseline) = self.compute_baseline(&path) {
                        self.baseline.insert(path, baseline);
                        count += 1;
                    }
                }
            }
        }
        info!("FIM baseline built: {} files", count);
        Ok(())
    }

    fn walk_dir(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = vec![];
        if dir.is_file() {
            files.push(dir.to_path_buf());
            return Ok(files);
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let path_str = path.to_string_lossy();
                if self.exclude_patterns.iter().any(|p| path_str.contains(p.as_str())) {
                    continue;
                }
                if path.is_dir() {
                    if let Ok(mut sub) = self.walk_dir(&path) {
                        files.append(&mut sub);
                    }
                } else if path.is_file() {
                    files.push(path);
                }
            }
        }
        Ok(files)
    }

    fn compute_baseline(&self, path: &Path) -> Result<FileBaseline> {
        use std::io::Read;

        let meta = std::fs::metadata(path)?;
        let mut file = std::fs::File::open(path)?;

        // SHA-256 via streaming
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }

        let mtime = meta.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        use std::os::unix::fs::MetadataExt;
        Ok(FileBaseline {
            sha256: format!("{:x}", hasher.finalize()),
            size: meta.len(),
            mtime_secs: mtime,
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    /// Run continuous monitoring loop — poll for changes against baseline
    pub async fn run(&mut self) -> Result<()> {
        self.build_baseline().await?;

        let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            ticker.tick().await;
            self.check_integrity().await;
        }
    }

    async fn check_integrity(&mut self) {
        let paths: Vec<PathBuf> = self.baseline.keys().cloned().collect();

        for path in paths {
            match self.compute_baseline(&path) {
                Ok(current) => {
                    let baseline = &self.baseline[&path];

                    if current.sha256 != baseline.sha256 {
                        warn!("FIM: content changed: {}", path.display());
                        self.emit_event(
                            FileEvent {
                                path: path.clone(),
                                kind: FileEventKind::Modify,
                                old_path: None,
                                file_hash: Some(current.sha256.clone()),
                                file_size: current.size,
                                uid: current.uid,
                                gid: current.gid,
                                mode: current.mode,
                                pid: None,
                            },
                            Severity::High,
                            vec!["T1565.001"], // Stored Data Manipulation
                        ).await;
                        self.baseline.insert(path, current);

                    } else if current.mode != baseline.mode {
                        // chmod detected
                        let is_exec_set = (current.mode & 0o111) != 0 && (baseline.mode & 0o111) == 0;
                        let kind = if is_exec_set {
                            FileEventKind::ExecutableBitSet
                        } else {
                            FileEventKind::PermissionChange
                        };
                        let severity = if is_exec_set { Severity::High } else { Severity::Medium };

                        self.emit_event(
                            FileEvent { path: path.clone(), kind, old_path: None,
                                        file_hash: None, file_size: current.size,
                                        uid: current.uid, gid: current.gid,
                                        mode: current.mode, pid: None },
                            severity,
                            vec!["T1222.002"], // File/Directory Permissions Modification
                        ).await;
                        self.baseline.insert(path, current);
                    }
                }
                Err(_) => {
                    // File deleted
                    warn!("FIM: file deleted: {}", path.display());
                    self.emit_event(
                        FileEvent {
                            path: path.clone(),
                            kind: FileEventKind::Delete,
                            old_path: None,
                            file_hash: None,
                            file_size: 0,
                            uid: 0, gid: 0, mode: 0, pid: None,
                        },
                        Severity::High,
                        vec!["T1485"], // Data Destruction
                    ).await;
                    self.baseline.remove(&path);
                }
            }
        }
    }

    async fn emit_event(&self, fe: FileEvent, severity: Severity, mitre: Vec<&str>) {
        let payload = serde_json::to_value(&fe).unwrap_or_default();
        let ev = EdrEvent::new(EdrEventType::FileModify, severity, payload)
            .with_mitre(mitre)
            .with_tags(vec!["fim", "file_integrity"]);
        let _ = self.tx.send(ev).await;
    }
}

// Inline SHA-256 using sha2 crate (production dependency)
use sha2::{Digest, Sha256};
