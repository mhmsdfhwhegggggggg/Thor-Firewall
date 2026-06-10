-- Thor Firewall — ClickHouse Schema Migration 003
-- UEBA Peer Groups + Online Learning Metrics + Drift Events

CREATE DATABASE IF NOT EXISTS thor;

-- ── UEBA Entity Risk History ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.ueba_risk_history (
    ts           DateTime64(3, 'UTC') DEFAULT now64(),
    entity_id    String,
    entity_type  LowCardinality(String),
    event_type   LowCardinality(String),
    score_delta  Float32,
    cumulative_score Float32,
    mitre_id     String DEFAULT '',
    details      String DEFAULT '{}'  -- JSON
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (entity_id, ts)
TTL ts + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ── UEBA Peer Group Assignments ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.ueba_peer_groups (
    ts            DateTime DEFAULT now(),
    entity_id     String,
    entity_type   LowCardinality(String),
    group_id      UInt8,
    group_label   String,
    anomaly_score Float32 DEFAULT 0.0,
    is_outlier    Bool DEFAULT false,
    peer_rank     Float32 DEFAULT 0.5,
    top_deviations Array(String)
) ENGINE = ReplacingMergeTree(ts)
ORDER BY (entity_id, ts)
TTL ts + INTERVAL 30 DAY;

-- ── ML Online Training Metrics ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.ml_training_metrics (
    ts          DateTime64(3, 'UTC') DEFAULT now64(),
    model_name  LowCardinality(String),
    train_step  UInt64,
    loss        Float32,
    accuracy    Float32 DEFAULT 0.0,
    f1_score    Float32 DEFAULT 0.0,
    n_samples   UInt32,
    lr          Float32,
    replay_size UInt32 DEFAULT 0
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (model_name, ts)
TTL ts + INTERVAL 90 DAY;

-- ── Concept Drift Events ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.drift_events (
    ts          DateTime64(3, 'UTC') DEFAULT now64(),
    detector    LowCardinality(String),  -- adwin | ddm | page_hinkley
    status      LowCardinality(String),  -- warning | drift
    metric      String,
    old_mean    Float32,
    new_mean    Float32,
    change_pct  Float32,
    message     String,
    resolved    Bool DEFAULT false
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (detector, ts)
TTL ts + INTERVAL 365 DAY;

-- ── Compliance Evidence Log ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.compliance_evidence (
    ts           DateTime64(3, 'UTC') DEFAULT now64(),
    evidence_id  String,
    framework    LowCardinality(String),
    control_id   String,
    source       LowCardinality(String),
    category     LowCardinality(String),
    title        String,
    description  String,
    value_json   String DEFAULT '{}'
) ENGINE = ReplacingMergeTree(ts)
ORDER BY (framework, control_id, ts)
TTL ts + INTERVAL 2190 DAY;  -- 6 years

-- ── Compliance Evaluation History ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.compliance_history (
    ts            DateTime64(3, 'UTC') DEFAULT now64(),
    framework     LowCardinality(String),
    overall_score Float32,
    pass_count    UInt16,
    fail_count    UInt16,
    partial_count UInt16,
    report_json   String DEFAULT '{}'
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (framework, ts)
TTL ts + INTERVAL 2190 DAY;

-- ── Threat Graph Snapshot (daily) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.graph_snapshots (
    snapshot_date Date DEFAULT today(),
    node_count    UInt32,
    edge_count    UInt32,
    ioc_nodes     UInt32,
    high_risk     UInt32,
    campaigns     UInt16,
    stats_json    String DEFAULT '{}'
) ENGINE = ReplacingMergeTree(snapshot_date)
ORDER BY snapshot_date
TTL snapshot_date + INTERVAL 365 DAY;

-- ── Integration Query Log ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.integration_queries (
    ts           DateTime64(3, 'UTC') DEFAULT now64(),
    integration  LowCardinality(String),  -- virustotal | shodan | slack
    query_type   LowCardinality(String),  -- ip | domain | hash | alert
    target       String,
    result_code  UInt16,   -- HTTP status or 0=ok, 1=error
    cached       Bool DEFAULT false,
    latency_ms   Float32
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (integration, ts)
TTL ts + INTERVAL 30 DAY;

-- ── Materialized view: UEBA risk summary per entity per day ──────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS thor.ueba_daily_summary
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (entity_id, day)
AS SELECT
    toDate(ts)       AS day,
    entity_id,
    entity_type,
    count()          AS event_count,
    sum(score_delta) AS total_score_delta,
    max(cumulative_score) AS peak_score
FROM thor.ueba_risk_history
GROUP BY day, entity_id, entity_type;
