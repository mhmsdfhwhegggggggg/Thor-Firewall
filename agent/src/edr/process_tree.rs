//! Process tree builder — reconstructs full ancestry chains from /proc
//! Used for causality analysis: who spawned the attacker's shell?

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: String,
    pub cmdline: String,
    pub uid: u32,
    pub start_time_ms: u64,
    pub children: Vec<ProcessNode>,
    pub depth: u32,
    pub risk_score: f32,
    pub mitre_tags: Vec<String>,
}

pub struct ProcessTree {
    nodes: HashMap<u32, ProcessNode>,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self { nodes: HashMap::new() }
    }

    /// Build full process tree from /proc snapshot
    pub fn build_from_proc() -> Result<Self> {
        let mut tree = Self::new();

        for entry in std::fs::read_dir("/proc")?.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Ok(node) = Self::read_node(pid) {
                    tree.nodes.insert(pid, node);
                }
            }
        }

        tree.score_nodes();
        Ok(tree)
    }

    fn read_node(pid: u32) -> Result<ProcessNode> {
        let base = format!("/proc/{pid}");
        let status = std::fs::read_to_string(format!("{base}/status"))?;
        let cmdline = std::fs::read_to_string(format!("{base}/cmdline"))
            .unwrap_or_default()
            .replace('\0', " ");
        let exe = std::fs::read_link(format!("{base}/exe"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let mut name = String::new();
        let mut ppid = 0u32;
        let mut uid = 0u32;

        for line in status.lines() {
            if line.starts_with("Name:") {
                name = line.split_whitespace().nth(1).unwrap_or("").to_string();
            } else if line.starts_with("PPid:") {
                ppid = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            } else if line.starts_with("Uid:") {
                uid = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            }
        }

        Ok(ProcessNode {
            pid,
            ppid,
            name,
            exe,
            cmdline: cmdline.trim().to_string(),
            uid,
            start_time_ms: 0,
            children: vec![],
            depth: 0,
            risk_score: 0.0,
            mitre_tags: vec![],
        })
    }

    fn score_nodes(&mut self) {
        let pids: Vec<u32> = self.nodes.keys().copied().collect();
        for pid in pids {
            if let Some(node) = self.nodes.get_mut(&pid) {
                let mut score = 0.0f32;
                let mut tags = vec![];

                // Shell spawned by non-shell parent
                if matches!(node.name.as_str(), "bash"|"sh"|"zsh"|"dash") {
                    score += 0.3;
                    tags.push("T1059.004".to_string()); // Unix Shell
                }

                // Running as root
                if node.uid == 0 && !matches!(node.name.as_str(), "systemd"|"init"|"kernel") {
                    score += 0.2;
                }

                // Execution from suspicious dirs
                if node.exe.starts_with("/tmp") || node.exe.starts_with("/dev/shm") {
                    score += 0.5;
                    tags.push("T1036".to_string()); // Masquerading
                }

                // Network tools
                if matches!(node.name.as_str(), "nc"|"ncat"|"socat"|"curl"|"wget") {
                    score += 0.35;
                    tags.push("T1071".to_string()); // C2 communication
                }

                // Base64/python -c (inline execution)
                if node.cmdline.contains("base64 -d") || node.cmdline.contains("python -c") {
                    score += 0.4;
                    tags.push("T1027".to_string()); // Obfuscated Files
                }

                node.risk_score = score.min(1.0);
                node.mitre_tags = tags;
            }
        }
    }

    /// Get full ancestor chain for a PID
    pub fn get_ancestry(&self, pid: u32) -> Vec<&ProcessNode> {
        let mut chain = vec![];
        let mut current = pid;
        let mut visited = std::collections::HashSet::new();

        while let Some(node) = self.nodes.get(&current) {
            if visited.contains(&current) { break; }
            visited.insert(current);
            chain.push(node);
            if node.ppid == 0 || node.ppid == current { break; }
            current = node.ppid;
        }

        chain
    }

    /// Find high-risk processes (risk_score >= threshold)
    pub fn get_high_risk(&self, threshold: f32) -> Vec<&ProcessNode> {
        self.nodes.values()
            .filter(|n| n.risk_score >= threshold)
            .collect()
    }

    /// Convert to JSON for API serialization
    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<&ProcessNode> = self.nodes.values().collect();
        serde_json::json!({
            "total_processes": nodes.len(),
            "high_risk_count": nodes.iter().filter(|n| n.risk_score >= 0.5).count(),
            "processes": nodes,
        })
    }
}

impl Default for ProcessTree {
    fn default() -> Self { Self::new() }
}
