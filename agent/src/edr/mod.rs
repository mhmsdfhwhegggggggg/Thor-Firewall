//! EDR (Endpoint Detection & Response) module for Thor Firewall
//! Real kernel-level telemetry: process tree, file integrity, memory scanning

pub mod linux_edr;
pub mod process_tree;
pub mod file_monitor;
pub mod memory_scanner;

pub use linux_edr::LinuxEdr;
pub use process_tree::{ProcessTree, ProcessNode};
pub use file_monitor::{FileMonitor, FileEvent, FileEventKind};
pub use memory_scanner::{MemoryScanner, MemoryRegion, ScanResult};

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

/// Unified EDR event envelope sent to control-plane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrEvent {
    pub id: Uuid,
    pub timestamp: u64,
    pub hostname: String,
    pub agent_version: String,
    pub event_type: EdrEventType,
    pub severity: Severity,
    pub payload: serde_json::Value,
    pub mitre_techniques: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EdrEventType {
    ProcessCreate,
    ProcessTerminate,
    ProcessInjection,
    FileCreate,
    FileModify,
    FileDelete,
    FileRename,
    NetworkConnect,
    NetworkListen,
    RegistrySet,
    RegistryDelete,
    MemoryScan,
    YaraMatch,
    LsmDeny,
    EbpfAlert,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl EdrEvent {
    pub fn new(event_type: EdrEventType, severity: Severity, payload: serde_json::Value) -> Self {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id: Uuid::new_v4(),
            timestamp: ts,
            hostname: gethostname(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            event_type,
            severity,
            payload,
            mitre_techniques: vec![],
            tags: vec![],
        }
    }

    pub fn with_mitre(mut self, techniques: Vec<&str>) -> Self {
        self.mitre_techniques = techniques.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = tags.iter().map(|s| s.to_string()).collect();
        self
    }
}

fn gethostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}
