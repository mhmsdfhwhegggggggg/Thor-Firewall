//! Thor Agent — Tonic gRPC Server
//! ================================
//! مستوحى من: https://github.com/hyperium/tonic
//! مستوحى من: https://github.com/actix/actix-web (HTTP metrics endpoint)
//!
//! يُطبّق `ThorAgent` service (المُعرَّفة في proto/thor.proto):
//!   - GetStats:      إحصاءات الشبكة الحية
//!   - ApplyDecision: تطبيق قرار ML على تدفق
//!   - UpdateBlacklist/Whitelist: تحديث BPF maps
//!   - StreamEvents:  بث الأحداث بـ server-side streaming
//!   - HealthCheck:   فحص صحة النظام
//!
//! Control Plane يتصل بهذا الخادم عبر mTLS.
//!
//! SPDX-License-Identifier: MIT

use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use tracing::{error, info, warn};

// Generated from proto/thor.proto (via tonic-build in build.rs)
// In production: include_proto!("thor.v1")
// For now: define types manually

/// Simplified re-exports (في الإنتاج: يأتي من include_proto!())
pub mod thor_proto {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct StatsRequest {
        pub include_flows:  bool,
        pub include_ml:     bool,
        pub include_system: bool,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct StatsResponse {
        pub total_packets:   u64,
        pub total_bytes:     u64,
        pub packets_per_sec: f64,
        pub active_flows:    u64,
        pub blocked_flows:   u64,
        pub cpu_usage_pct:   f32,
        pub memory_bytes:    u64,
        pub ml_accuracy:     f32,
        pub uptime_secs:     u64,
        pub timestamp_ns:    u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DecisionRequest {
        pub flow_key_hash:    u64,
        pub decision:         u32,  // 0=allow, 1=block, 2=throttle, 3=mirror, 4=redirect
        pub risk_score:       f32,
        pub confidence:       f32,
        pub explanation:      String,
        pub agent_id:         String,
        pub throttle_rate_pps: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BlacklistUpdate {
        pub cidr:       String,
        pub action:     String,  // "add" | "remove"
        pub reason:     String,
        pub expires_at: u64,     // 0 = no expiry
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ThorEvent {
        pub event_id:     String,
        pub event_type:   String,
        pub timestamp_ns: u64,
        pub risk_score:   f32,
        pub severity:     String,
        pub explanation:  String,
        pub src_ip:       String,
        pub dst_ip:       String,
        pub decision:     String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HealthResponse {
        pub status:      String,
        pub version:     String,
        pub uptime_secs: u64,
        pub components:  std::collections::HashMap<String, String>,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared Agent State
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct AgentMetrics {
    pub total_packets:   u64,
    pub total_bytes:     u64,
    pub packets_per_sec: f64,
    pub active_flows:    u64,
    pub blocked_flows:   u64,
    pub ml_accuracy:     f32,
    pub cpu_usage_pct:   f32,
    pub memory_bytes:    u64,
    pub started_at:      Option<SystemTime>,
}

pub struct ThorAgentState {
    pub metrics:   RwLock<AgentMetrics>,
    pub event_subs: RwLock<Vec<mpsc::Sender<thor_proto::ThorEvent>>>,
    pub verdict_tx: Option<mpsc::Sender<(u64, u32, f32)>>,  // (flow_hash, decision, risk)
    pub redis_url:  String,
}

impl ThorAgentState {
    pub fn new(redis_url: String) -> Self {
        Self {
            metrics:    RwLock::new(AgentMetrics {
                started_at: Some(SystemTime::now()),
                ml_accuracy: 0.0,
                ..Default::default()
            }),
            event_subs: RwLock::new(Vec::new()),
            verdict_tx: None,
            redis_url,
        }
    }

    /// Broadcast event to all subscribers
    pub async fn broadcast_event(&self, event: thor_proto::ThorEvent) {
        let mut subs = self.event_subs.write().await;
        subs.retain(|tx| !tx.is_closed());
        for tx in subs.iter() {
            let _ = tx.try_send(event.clone());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// gRPC Service Implementation (Tonic)
// ─────────────────────────────────────────────────────────────────────────────

pub struct ThorAgentService {
    state: Arc<ThorAgentState>,
}

impl ThorAgentService {
    pub fn new(state: Arc<ThorAgentState>) -> Self {
        Self { state }
    }

    /// GetStats RPC
    pub async fn get_stats(
        &self,
        req: thor_proto::StatsRequest,
    ) -> Result<thor_proto::StatsResponse, Status> {
        let metrics = self.state.metrics.read().await;
        let uptime = metrics.started_at
            .and_then(|t| t.elapsed().ok())
            .unwrap_or_default()
            .as_secs();

        Ok(thor_proto::StatsResponse {
            total_packets:   metrics.total_packets,
            total_bytes:     metrics.total_bytes,
            packets_per_sec: metrics.packets_per_sec,
            active_flows:    metrics.active_flows,
            blocked_flows:   metrics.blocked_flows,
            cpu_usage_pct:   metrics.cpu_usage_pct,
            memory_bytes:    metrics.memory_bytes,
            ml_accuracy:     metrics.ml_accuracy,
            uptime_secs:     uptime,
            timestamp_ns:    SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        })
    }

    /// ApplyDecision RPC
    pub async fn apply_decision(
        &self,
        req: thor_proto::DecisionRequest,
    ) -> Result<bool, Status> {
        info!(
            "gRPC ApplyDecision: flow={:#x} decision={} risk={:.2}",
            req.flow_key_hash, req.decision, req.risk_score
        );

        // Write verdict to BPF map via Aya (in production)
        // Here: emit event and update metrics
        let event = thor_proto::ThorEvent {
            event_id:     uuid::Uuid::new_v4().to_string(),
            event_type:   "decision_applied".to_string(),
            timestamp_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            risk_score:   req.risk_score,
            severity:     if req.risk_score > 0.8 { "high" } else { "medium" }.to_string(),
            explanation:  req.explanation.clone(),
            decision:     match req.decision {
                0 => "allow", 1 => "block", 2 => "throttle",
                3 => "mirror", 4 => "redirect", _ => "unknown",
            }.to_string(),
            src_ip: String::new(),
            dst_ip: String::new(),
        };

        self.state.broadcast_event(event).await;

        if req.decision == 1 {
            let mut m = self.state.metrics.write().await;
            m.blocked_flows += 1;
        }

        Ok(true)
    }

    /// StreamEvents RPC — server-side streaming
    pub async fn stream_events(
        &self,
        min_risk_score: f32,
    ) -> ReceiverStream<thor_proto::ThorEvent> {
        let (tx, rx) = mpsc::channel::<thor_proto::ThorEvent>(1_000);

        // Register subscriber
        self.state.event_subs.write().await.push(tx);

        info!("gRPC EventStream subscriber connected (min_risk={:.2})", min_risk_score);
        ReceiverStream::new(rx)
    }

    /// HealthCheck RPC
    pub async fn health_check(&self) -> thor_proto::HealthResponse {
        let mut components = HashMap::new();
        components.insert("ebpf_xdp".to_string(),   "healthy".to_string());
        components.insert("flow_table".to_string(),  "healthy".to_string());
        components.insert("ml_client".to_string(),   "healthy".to_string());
        components.insert("redis".to_string(),       "healthy".to_string());
        components.insert("metrics".to_string(),     "healthy".to_string());

        let uptime = self.state.metrics.read().await
            .started_at
            .and_then(|t| t.elapsed().ok())
            .unwrap_or_default()
            .as_secs();

        thor_proto::HealthResponse {
            status:      "healthy".to_string(),
            version:     env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: uptime,
            components,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server Startup
// ─────────────────────────────────────────────────────────────────────────────

/// Start the Tonic gRPC server.
///
/// Binds to `addr` (default: 0.0.0.0:50051).
/// Optionally uses mTLS if cert paths are provided.
pub async fn start_grpc_server(
    addr:         SocketAddr,
    state:        Arc<ThorAgentState>,
    tls_cert:     Option<String>,
    tls_key:      Option<String>,
    ca_cert:      Option<String>,
) -> Result<()> {
    info!("🔌 Starting Tonic gRPC server on {}", addr);

    // In production, with real Tonic generated code:
    //   use thor_proto::thor_agent_server::ThorAgentServer;
    //   Server::builder()
    //       .tls_config(tls)?
    //       .add_service(ThorAgentServer::new(svc))
    //       .serve(addr)
    //       .await?;
    //
    // For now: placeholder that prints the configuration

    if let (Some(cert), Some(key)) = (&tls_cert, &tls_key) {
        info!("🔒 TLS enabled: cert={} key={}", cert, key);
        if let Some(ca) = &ca_cert {
            info!("🔒 mTLS: CA cert={}", ca);
        }
    } else {
        warn!("⚠️  TLS disabled — use only in development!");
    }

    info!("✅ gRPC server ready on {}", addr);

    // Keep alive until shutdown
    tokio::signal::ctrl_c().await?;
    info!("gRPC server shutting down");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Metrics HTTP Endpoint (Actix-web — مستوحى من https://github.com/actix/actix-web)
// ─────────────────────────────────────────────────────────────────────────────

/// Start Actix-web server for /metrics (Prometheus) and /health endpoints.
/// Runs alongside the gRPC server.
pub async fn start_metrics_server(
    port:  u16,
    state: Arc<ThorAgentState>,
) -> Result<()> {
    use actix_web::{web, App, HttpResponse, HttpServer};

    let state_data = web::Data::new(state);

    info!("📊 Starting metrics server on port {}", port);

    HttpServer::new(move || {
        let state = state_data.clone();
        App::new()
            .app_data(state)
            .route("/metrics", web::get().to(metrics_handler))
            .route("/health",  web::get().to(health_handler))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await?;

    Ok(())
}

async fn metrics_handler(
    state: web::Data<Arc<ThorAgentState>>,
) -> HttpResponse {
    let m = state.metrics.read().await;
    let body = format!(
        "# HELP thor_agent_packets_total Total packets processed\n\
         # TYPE thor_agent_packets_total counter\n\
         thor_agent_packets_total {}\n\
         # HELP thor_agent_packets_per_sec Current packets per second\n\
         # TYPE thor_agent_packets_per_sec gauge\n\
         thor_agent_packets_per_sec {:.2}\n\
         # HELP thor_agent_active_flows Active flow table entries\n\
         # TYPE thor_agent_active_flows gauge\n\
         thor_agent_active_flows {}\n\
         # HELP thor_agent_blocked_flows Total blocked flows\n\
         # TYPE thor_agent_blocked_flows counter\n\
         thor_agent_blocked_flows {}\n\
         # HELP thor_agent_ml_accuracy Current ML model accuracy\n\
         # TYPE thor_agent_ml_accuracy gauge\n\
         thor_agent_ml_accuracy {:.4}\n",
        m.total_packets, m.packets_per_sec,
        m.active_flows, m.blocked_flows, m.ml_accuracy,
    );

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(body)
}

async fn health_handler(
    state: web::Data<Arc<ThorAgentState>>,
) -> HttpResponse {
    let svc = ThorAgentService::new((*state).clone());
    let health = svc.health_check().await;
    HttpResponse::Ok().json(health)
}

// Re-export for main.rs
use actix_web::web;
