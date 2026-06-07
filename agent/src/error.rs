// Thor Firewall — Error Types
// أنواع الأخطاء الموحدة

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ThorError {
    #[error("Packet parsing failed: {0}")]
    ParseError(String),

    #[error("Flow table full (max: {max_flows})")]
    FlowTableFull { max_flows: usize },

    #[error("RL inference timeout after {timeout_ms}ms")]
    RLTimeout { timeout_ms: u64 },

    #[error("eBPF program load failed: {0}")]
    EBPFLoadError(String),

    #[error("WFP driver connection failed: {0}")]
    WFPError(String),

    #[error("gRPC communication error: {0}")]
    GRPCError(#[from] tonic::Status),

    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

pub type ThorResult<T> = Result<T, ThorError>;
