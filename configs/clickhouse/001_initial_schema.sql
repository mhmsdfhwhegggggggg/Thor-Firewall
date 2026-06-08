-- Thor Firewall — ClickHouse Schema Migrations
-- Migration 001: Initial schema

-- ── Flows table ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.flows (
    ts           DateTime64(3, 'UTC') DEFAULT now64(),
    src_ip       IPv6,
    dst_ip       IPv6,
    src_port     UInt16,
    dst_port     UInt16,
    protocol     LowCardinality(String),
    bytes        UInt64,
    packets      UInt64,
    duration_ms  UInt32,
    decision     LowCardinality(String),
    risk_score   Float32,
    confidence   Float32,
    agent_id     String,
    node_name    String,
    flow_hash    UInt64,
    features     Array(Float32)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, src_ip, dst_ip)
TTL ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ── Threats table ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.threats (
    ts           DateTime64(3, 'UTC') DEFAULT now64(),
    threat_id    String,
    threat_type  LowCardinality(String),
    severity     LowCardinality(String),
    src_ip       IPv6,
    dst_ip       Nullable(IPv6),
    risk_score   Float32,
    blocked      Bool,
    decision     LowCardinality(String),
    mitre_id     String,
    mitre_name   String,
    description  String,
    ioc_matches  Array(String),
    soar_actions Array(String),
    node_name    String
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, threat_type, severity)
TTL ts + INTERVAL 365 DAY;

-- ── Audit log (append-only, immutable) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.audit_log (
    ts             DateTime64(3, 'UTC') DEFAULT now64(),
    entry_id       String,
    event_type     LowCardinality(String),
    actor_id       String,
    target         String,
    action         String,
    result         LowCardinality(String),
    source_ip      Nullable(IPv6),
    session_id     String,
    details        String,   -- JSON blob
    hmac_signature String
) ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (entry_id, ts)
TTL ts + INTERVAL 2190 DAY;  -- 6 years retention for compliance

-- ── UEBA events ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.ueba_events (
    ts           DateTime64(3, 'UTC') DEFAULT now64(),
    entity_id    String,
    entity_type  LowCardinality(String),
    anomaly_type LowCardinality(String),
    severity     LowCardinality(String),
    risk_delta   Float32,
    description  String,
    mitre_id     String,
    evidence     String   -- JSON blob
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, entity_id)
TTL ts + INTERVAL 90 DAY;

-- ── Cases table ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.cases (
    id             String,
    title          String,
    severity       LowCardinality(String),
    status         LowCardinality(String),
    assignee       String,
    created_at     DateTime64(3, 'UTC'),
    updated_at     DateTime64(3, 'UTC'),
    description    String,
    notes          String,
    incident_count UInt32,
    sla_hours      UInt16,
    closed_at      Nullable(DateTime64(3, 'UTC'))
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (id);

-- ── Materialized view: threat summary by hour ─────────────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS thor.threat_summary_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(hour)
ORDER BY (hour, threat_type, severity)
AS SELECT
    toStartOfHour(ts)    AS hour,
    threat_type,
    severity,
    count()              AS count,
    sum(blocked)         AS blocked_count,
    avg(risk_score)      AS avg_risk
FROM thor.threats
GROUP BY hour, threat_type, severity;

-- ── Create database if not exists ────────────────────────────────────────────
CREATE DATABASE IF NOT EXISTS thor;
