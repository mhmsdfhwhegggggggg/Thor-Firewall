// Thor Firewall — gRPC Server
// خادم gRPC للتواصل مع Control Plane

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info, warn};

use crate::config::GrpcConfig;
use crate::flow_manager::{Decision, FlowManager};
use crate::rl_core::RLCore;
use crate::telemetry::metrics;

// الكود المولّد من proto سيكون هنا
// tonic::include_proto!("thor.v1");

/// خادم gRPC الرئيسي
pub struct GrpcServer {
    config: GrpcConfig,
    flow_manager: FlowManager,
    rl_core: RLCore,
}

impl GrpcServer {
    pub fn new(
        config: GrpcConfig,
        flow_manager: FlowManager,
        rl_core: RLCore,
    ) -> Self {
        Self { config, flow_manager, rl_core }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.config.host, self.config.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid gRPC address: {}", e))?;

        info!(addr = %addr, "gRPC server starting");

        // TODO: تفعيل TLS إذا مُفعَّل في الإعدادات
        let server = Server::builder();

        // سيُضاف الـ service بعد توليد proto
        // server.add_service(ThorAgentServer::new(AgentService::new(
        //     self.flow_manager.clone(),
        //     self.rl_core.clone(),
        // )))

        info!(addr = %addr, "gRPC server ready");
        Ok(())
    }
}

/// خدمة Agent — تُنفّذ RPC calls من control plane
pub struct AgentService {
    flow_manager: FlowManager,
    rl_core: RLCore,
}

impl AgentService {
    pub fn new(flow_manager: FlowManager, rl_core: RLCore) -> Self {
        Self { flow_manager, rl_core }
    }
}

// ============================================================================
// RPC Implementations (stubs — سيُكملون بعد توليد proto)
// ============================================================================

impl AgentService {
    /// RPC: الحصول على إحصاءات النظام الحية
    pub async fn get_stats(&self) -> Result<serde_json::Value> {
        let flow_stats = self.flow_manager.stats();
        let rl_stats = self.rl_core.stats().await;

        let m = metrics();
        m.flows_active.set(flow_stats.active_flows as f64);
        m.flows_blocked.inc_by(flow_stats.blocked_flows as f64);
        m.flows_suspicious.set(flow_stats.suspicious_flows as f64);
        m.ebpf_map_utilization.set(flow_stats.table_utilization as f64);

        Ok(serde_json::json!({
            "flows": {
                "active": flow_stats.active_flows,
                "blocked": flow_stats.blocked_flows,
                "suspicious": flow_stats.suspicious_flows,
                "table_utilization": flow_stats.table_utilization,
            },
            "ml": {
                "total_analyzed": rl_stats.total_analyzed,
                "total_blocked": rl_stats.total_blocked,
                "avg_latency_us": rl_stats.avg_latency_us,
            }
        }))
    }

    /// RPC: تطبيق قرار خارجي على تدفق
    pub async fn apply_external_decision(
        &self,
        flow_key_hash: u64,
        decision_str: &str,
        risk_score: f32,
        explanation: Option<String>,
    ) -> Result<()> {
        // TODO: resolve flow_key from hash and apply
        info!(
            hash = flow_key_hash,
            decision = decision_str,
            risk = risk_score,
            "External decision applied"
        );
        Ok(())
    }

    /// RPC: تحديث blacklist فوراً
    pub async fn update_blacklist(
        &self,
        ip: std::net::Ipv4Addr,
        action: &str,
    ) -> Result<()> {
        info!(ip = %ip, action = action, "Blacklist updated");
        Ok(())
    }
}
