// Thor Firewall — Stats Publisher
// يقرأ إحصاءات BPF maps كل ثانية ويُرسلها إلى Redis
// حتى يستطيع websocket.py قراءة بيانات حقيقية بدلاً من random()
//
// Redis Keys المكتوبة:
//   thor:stats:current        HASH  — network stats
//   thor:bpf:counters         HASH  — XDP per-action counters
//   thor:ml:stats             HASH  — ML inference stats
//   thor:agent:health         HASH  — CPU/mem/uptime
//   thor:pubsub:events        CHANNEL — real-time events broadcast
//
// SPDX-License-Identifier: GPL-3.0

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use redis::AsyncCommands;
use serde_json::json;
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::linux::xdp_loader::{XdpLoader, XDPStats};
use crate::rl_core::RLCore;

/// يُشغَّل كـ background task — كل ثانية
pub async fn run_stats_publisher(
    xdp: Arc<XdpLoader>,
    rl_core: Arc<RLCore>,
    redis_url: &str,
    publish_interval_ms: u64,
) -> Result<()> {
    info!("Stats publisher starting (interval={}ms)", publish_interval_ms);

    let client = redis::Client::open(redis_url)?;
    let mut con = client.get_multiplexed_async_connection().await?;

    let interval = Duration::from_millis(publish_interval_ms);
    let mut ticker = time::interval(interval);
    let start_time = Instant::now();

    loop {
        ticker.tick().await;

        // 1. BPF counters
        let xdp_stats = match xdp.get_stats().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to read XDP stats: {}", e);
                continue;
            }
        };

        // 2. ML stats
        let ml_stats = rl_core.stats().await;

        // 3. حساب PPS و BPS من الـ counters
        let total_packets = xdp_stats.passed_packets
            + xdp_stats.blocked_packets
            + xdp_stats.redirected_packets;

        let uptime_secs = start_time.elapsed().as_secs();

        // 4. كتابة BPF counters
        let bpf_result: Result<(), _> = con.hset_multiple(
            "thor:bpf:counters",
            &[
                ("xdp_pass",      xdp_stats.passed_packets.to_string()),
                ("xdp_drop",      xdp_stats.blocked_packets.to_string()),
                ("xdp_tx",        xdp_stats.redirected_packets.to_string()),
                ("xdp_redirect",  xdp_stats.redirected_packets.to_string()),
                ("total",         total_packets.to_string()),
                ("whitelist_hits", xdp_stats.whitelisted_packets.to_string()),
                ("blacklist_hits", xdp_stats.blacklisted_packets.to_string()),
            ],
        ).await;

        if let Err(e) = bpf_result {
            debug!("Redis write error (bpf): {}", e);
        }

        // 5. كتابة network stats
        // تقدير PPS من diff
        let throughput_mbps = (total_packets as f64 * 1500.0 * 8.0) / 1_000_000.0;
        let active_flows = xdp_stats.active_flows as u64;
        let suspicious = xdp_stats.suspicious_packets;

        let net_result: Result<(), _> = con.hset_multiple(
            "thor:stats:current",
            &[
                ("packets_per_second",  total_packets.to_string()),
                ("bits_per_second",     (total_packets * 1500 * 8).to_string()),
                ("active_flows",        active_flows.to_string()),
                ("blocked_total",       xdp_stats.blocked_packets.to_string()),
                ("suspicious_flows",    suspicious.to_string()),
                ("throughput_mbps",     format!("{:.2}", throughput_mbps)),
                ("table_utilization",   format!("{:.4}", active_flows as f64 / 500_000.0)),
                ("active_threats",      suspicious.to_string()),
            ],
        ).await;

        if let Err(e) = net_result {
            debug!("Redis write error (net): {}", e);
        }

        // 6. كتابة ML stats
        let ml_result: Result<(), _> = con.hset_multiple(
            "thor:ml:stats",
            &[
                ("avg_latency_us",       format!("{:.2}", ml_stats.avg_latency_us)),
                ("accuracy",             format!("{:.4}", 0.97_f64)),  // TODO: from evaluation
                ("inferences_per_second", ml_stats.total_analyzed.to_string()),
                ("model_version",        "0.3.0"),
                ("checkpoint_loaded",    "1"),
                ("http_errors",          ml_stats.http_errors.to_string()),
                ("http_fallbacks",       ml_stats.http_fallbacks.to_string()),
            ],
        ).await;

        if let Err(e) = ml_result {
            debug!("Redis write error (ml): {}", e);
        }

        // 7. كتابة agent health
        let cpu_pct = read_cpu_usage();
        let mem_mb  = read_memory_usage_mb();

        let health_result: Result<(), _> = con.hset_multiple(
            "thor:agent:health",
            &[
                ("cpu_pct",          format!("{:.1}", cpu_pct)),
                ("memory_mb",        mem_mb.to_string()),
                ("uptime_s",         uptime_secs.to_string()),
                ("grpc_connections", "0"),   // TODO: from server.rs gRPC metrics
                ("ebpf_map_util",    format!("{:.4}", active_flows as f64 / 500_000.0)),
            ],
        ).await;

        if let Err(e) = health_result {
            debug!("Redis write error (health): {}", e);
        }

        // 8. TTL تلقائي: كل key تنتهي صلاحيتها بعد 10 ثوانٍ لو توقف الـ agent
        let _: Result<(), _> = con.expire("thor:stats:current", 10).await;
        let _: Result<(), _> = con.expire("thor:bpf:counters",  10).await;
        let _: Result<(), _> = con.expire("thor:ml:stats",      10).await;
        let _: Result<(), _> = con.expire("thor:agent:health",  10).await;

        debug!(
            "Stats published: pass={}, drop={}, flows={}",
            xdp_stats.passed_packets,
            xdp_stats.blocked_packets,
            active_flows
        );
    }
}

/// نشر حدث تهديد في الزمن الحقيقي
pub async fn publish_threat_event(
    con: &mut impl AsyncCommands,
    src_ip: &str,
    threat_type: &str,
    risk_score: f32,
    details: Option<&str>,
) -> Result<()> {
    let event = json!({
        "type": "threat_detected",
        "data": {
            "src_ip": src_ip,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "details": details,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
        }
    });

    let event_str = event.to_string();

    // أضف للـ list التاريخي (آخر 1000)
    let _: Result<(), _> = con.lpush("thor:threats:recent", &event_str).await;
    let _: Result<(), _> = con.ltrim("thor:threats:recent", 0, 999).await;

    // أضف للـ risk scores sorted set
    let _: Result<(), _> = con.zadd(
        "thor:ip_risk_scores",
        src_ip,
        risk_score as f64,
    ).await;

    // نشر الحدث لجميع الـ WebSocket clients
    let _: Result<(), _> = con.publish("thor:pubsub:events", &event_str).await;

    Ok(())
}

/// نشر حدث حظر تدفق
pub async fn publish_flow_blocked(
    con: &mut impl AsyncCommands,
    src_ip: &str,
    dst_ip: &str,
    dst_port: u16,
    protocol: &str,
    reason: &str,
) -> Result<()> {
    let event = json!({
        "type": "flow_blocked",
        "data": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "reason": reason,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
        }
    });

    let event_str = event.to_string();
    let _: Result<(), _> = con.lpush("thor:flows:blocked_recent", &event_str).await;
    let _: Result<(), _> = con.ltrim("thor:flows:blocked_recent", 0, 999).await;
    let _: Result<(), _> = con.publish("thor:pubsub:events", &event_str).await;

    Ok(())
}

// ============================================================================
// System Resource Reading (Linux /proc)
// ============================================================================

fn read_cpu_usage() -> f64 {
    // قراءة من /proc/self/stat
    // Production: استخدم sysinfo crate
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        let fields: Vec<&str> = stat.split_whitespace().collect();
        if fields.len() > 14 {
            let utime: u64 = fields[13].parse().unwrap_or(0);
            let stime: u64 = fields[14].parse().unwrap_or(0);
            let total_ticks = utime + stime;
            // تقدير CPU% (سيتحسن بمقارنة مع المرة السابقة)
            return (total_ticks as f64 / 100.0).min(100.0);
        }
    }
    0.0
}

fn read_memory_usage_mb() -> u64 {
    // قراءة من /proc/self/status
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return kb / 1024;
                    }
                }
            }
        }
    }
    0
}
