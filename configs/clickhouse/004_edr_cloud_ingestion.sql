-- ClickHouse Migration 004: EDR Events + Cloud Security + SOAR Executions
-- Partitioned by toYYYYMM(toDateTime(timestamp_ms / 1000)) for efficient time-range queries
-- Uses ReplicatedMergeTree for HA (single-node: MergeTree with TTL)

-- ─────────────────────── EDR Events ────────────────────────────

CREATE TABLE IF NOT EXISTS thor.edr_events
(
    id                  UUID         DEFAULT generateUUIDv4(),
    timestamp_ms        UInt64,
    hostname            LowCardinality(String),
    agent_version       LowCardinality(String),
    event_type          LowCardinality(String),  -- ProcessCreate, FileModify, MemoryScan ...
    severity            LowCardinality(String),  -- info, low, medium, high, critical
    pid                 UInt32       DEFAULT 0,
    ppid                UInt32       DEFAULT 0,
    process_name        String       DEFAULT '',
    process_exe         String       DEFAULT '',
    process_cmdline     String       DEFAULT '',
    process_uid         UInt32       DEFAULT 0,
    file_path           String       DEFAULT '',
    file_hash_sha256    String       DEFAULT '',
    file_size           UInt64       DEFAULT 0,
    network_src_ip      IPv4         DEFAULT '0.0.0.0',
    network_dst_ip      IPv4         DEFAULT '0.0.0.0',
    network_dst_port    UInt16       DEFAULT 0,
    network_protocol    LowCardinality(String) DEFAULT '',
    memory_region_start UInt64       DEFAULT 0,
    memory_region_perms String       DEFAULT '',
    yara_rule           String       DEFAULT '',
    container_id        String       DEFAULT '',
    mitre_techniques    Array(String),
    tags                Array(String),
    risk_score          Float32      DEFAULT 0.0,
    payload             String       DEFAULT '{}',
    tenant_id           LowCardinality(String) DEFAULT 'default',
    INDEX idx_hostname  hostname     TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_pid       pid          TYPE minmax GRANULARITY 1,
    INDEX idx_severity  severity     TYPE set(10) GRANULARITY 1,
    INDEX idx_risk      risk_score   TYPE minmax GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(toDateTime(timestamp_ms / 1000))
ORDER BY (tenant_id, hostname, timestamp_ms, event_type)
TTL toDateTime(timestamp_ms / 1000) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- ─────────────────────── Universal Events (Ingestion) ──────────

CREATE TABLE IF NOT EXISTS thor.events
(
    id                  UUID         DEFAULT generateUUIDv4(),
    timestamp_ms        UInt64,
    source_format       LowCardinality(String),
    source_host         LowCardinality(String),
    source_ip           IPv4         DEFAULT '0.0.0.0',
    log_level           LowCardinality(String) DEFAULT 'INFO',
    category            LowCardinality(String) DEFAULT 'generic',
    action              String       DEFAULT '',
    outcome             LowCardinality(String) DEFAULT '',
    actor_user          String       DEFAULT '',
    actor_process       String       DEFAULT '',
    actor_pid           UInt32       DEFAULT 0,
    target_host         String       DEFAULT '',
    target_ip           IPv4         DEFAULT '0.0.0.0',
    target_port         UInt16       DEFAULT 0,
    target_user         String       DEFAULT '',
    target_resource     String       DEFAULT '',
    raw                 String       DEFAULT '',
    labels              String       DEFAULT '{}',   -- JSON
    mitre_tactics       Array(String),
    mitre_techniques    Array(String),
    risk_score          Float32      DEFAULT 0.0,
    tenant_id           LowCardinality(String) DEFAULT 'default',
    event_hash          String       DEFAULT '',
    INDEX idx_src_host  source_host  TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_actor     actor_user   TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_category  category     TYPE set(20)  GRANULARITY 1,
    INDEX idx_risk      risk_score   TYPE minmax   GRANULARITY 1,
    INDEX idx_hash      event_hash   TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(toDateTime(timestamp_ms / 1000))
ORDER BY (tenant_id, source_format, timestamp_ms, source_host)
TTL toDateTime(timestamp_ms / 1000) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- ─────────────────────── Cloud Security Events ─────────────────

CREATE TABLE IF NOT EXISTS thor.cloud_events
(
    id                  UUID         DEFAULT generateUUIDv4(),
    timestamp_ms        UInt64,
    cloud_provider      LowCardinality(String),  -- aws, azure, gcp
    source_format       LowCardinality(String),  -- cloudtrail, guardduty, aad_signin...
    region              LowCardinality(String),
    account_id          String       DEFAULT '',
    action              String       DEFAULT '',
    outcome             LowCardinality(String),
    actor_user          String       DEFAULT '',
    actor_type          LowCardinality(String) DEFAULT '',
    source_ip           IPv4         DEFAULT '0.0.0.0',
    user_agent          String       DEFAULT '',
    resource_type       String       DEFAULT '',
    resource_id         String       DEFAULT '',
    error_code          String       DEFAULT '',
    mfa_used            Bool         DEFAULT false,
    risk_score          Float32      DEFAULT 0.0,
    mitre_techniques    Array(String),
    raw                 String       DEFAULT '{}',
    labels              String       DEFAULT '{}',
    tenant_id           LowCardinality(String) DEFAULT 'default',
    INDEX idx_cloud_act  action      TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_cloud_user actor_user  TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_cloud_risk risk_score  TYPE minmax GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(toDateTime(timestamp_ms / 1000))
ORDER BY (tenant_id, cloud_provider, timestamp_ms, actor_user)
TTL toDateTime(timestamp_ms / 1000) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- ─────────────────────── SOAR Executions ───────────────────────

CREATE TABLE IF NOT EXISTS thor.soar_executions
(
    id                  UUID         DEFAULT generateUUIDv4(),
    trigger_id          String       DEFAULT '',
    playbook            LowCardinality(String),
    status              LowCardinality(String),  -- pending, running, success, failed, partial
    started_at          UInt64,
    finished_at         UInt64,
    duration_ms         UInt32       DEFAULT 0,
    total_actions       UInt16       DEFAULT 0,
    success_actions     UInt16       DEFAULT 0,
    failed_actions      UInt16       DEFAULT 0,
    action_log          String       DEFAULT '[]',  -- JSON array of action results
    approved_by         String       DEFAULT '',
    tenant_id           LowCardinality(String) DEFAULT 'default',
    INDEX idx_playbook  playbook     TYPE set(20) GRANULARITY 1,
    INDEX idx_status    status       TYPE set(10) GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(toDateTime(started_at / 1000))
ORDER BY (tenant_id, playbook, started_at)
TTL toDateTime(started_at / 1000) + INTERVAL 730 DAY DELETE
SETTINGS index_granularity = 8192;

-- ─────────────────────── File Integrity Events ─────────────────

CREATE TABLE IF NOT EXISTS thor.fim_events
(
    id                  UUID         DEFAULT generateUUIDv4(),
    timestamp_ms        UInt64,
    hostname            LowCardinality(String),
    file_path           String,
    event_kind          LowCardinality(String),  -- create, modify, delete, rename, exec_bit_set
    file_hash_old       String       DEFAULT '',
    file_hash_new       String       DEFAULT '',
    file_size           UInt64       DEFAULT 0,
    uid                 UInt32       DEFAULT 0,
    gid                 UInt32       DEFAULT 0,
    mode_old            UInt32       DEFAULT 0,
    mode_new            UInt32       DEFAULT 0,
    process_name        String       DEFAULT '',
    pid                 UInt32       DEFAULT 0,
    mitre_techniques    Array(String),
    tenant_id           LowCardinality(String) DEFAULT 'default',
    INDEX idx_path      file_path    TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 1,
    INDEX idx_host      hostname     TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(toDateTime(timestamp_ms / 1000))
ORDER BY (tenant_id, hostname, file_path, timestamp_ms)
TTL toDateTime(timestamp_ms / 1000) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- ─────────────────────── ML Predictions ────────────────────────

CREATE TABLE IF NOT EXISTS thor.ml_predictions
(
    id                  UUID         DEFAULT generateUUIDv4(),
    timestamp_ms        UInt64,
    event_id            String       DEFAULT '',
    model_name          LowCardinality(String),
    model_version       LowCardinality(String),
    prediction_class    LowCardinality(String),
    confidence          Float32,
    threat_probability  Float32,
    features_hash       String       DEFAULT '',
    inference_ms        Float32      DEFAULT 0,
    batch_size          UInt16       DEFAULT 1,
    tenant_id           LowCardinality(String) DEFAULT 'default'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(toDateTime(timestamp_ms / 1000))
ORDER BY (tenant_id, model_name, timestamp_ms)
TTL toDateTime(timestamp_ms / 1000) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

-- ─────────────────────── Materialized Views ────────────────────

-- Hourly threat stats per tenant (for dashboard counters)
CREATE MATERIALIZED VIEW IF NOT EXISTS thor.mv_hourly_threat_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, severity)
AS SELECT
    tenant_id,
    toStartOfHour(toDateTime(timestamp_ms / 1000)) AS hour,
    severity,
    count()         AS event_count,
    sum(risk_score) AS total_risk,
    max(risk_score) AS max_risk
FROM thor.edr_events
GROUP BY tenant_id, hour, severity;

-- Top attacked hosts (rolling 24h)
CREATE MATERIALIZED VIEW IF NOT EXISTS thor.mv_top_attacked_hosts
ENGINE = SummingMergeTree()
ORDER BY (tenant_id, hostname, date)
AS SELECT
    tenant_id,
    hostname,
    toDate(toDateTime(timestamp_ms / 1000)) AS date,
    countIf(severity IN ('high', 'critical'))  AS high_critical_count,
    count()                                     AS total_events,
    max(risk_score)                             AS max_risk
FROM thor.edr_events
GROUP BY tenant_id, hostname, date;

-- ─────────────────────── Useful Queries ────────────────────────

-- Top risky hosts last 24h:
-- SELECT hostname, count() AS events, max(risk_score) AS max_risk
-- FROM thor.edr_events
-- WHERE timestamp_ms > (now() - INTERVAL 1 DAY) * 1000
-- GROUP BY hostname ORDER BY max_risk DESC LIMIT 20;

-- CloudTrail failed API calls by user:
-- SELECT actor_user, action, count() AS failures, max(timestamp_ms)
-- FROM thor.cloud_events
-- WHERE outcome = 'failure' AND timestamp_ms > (now() - INTERVAL 1 HOUR) * 1000
-- GROUP BY actor_user, action ORDER BY failures DESC LIMIT 20;
