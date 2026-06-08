-- Thor Firewall — TimescaleDB Initialization
-- ─────────────────────────────────────────────────────────────────────────────
-- Time-series metrics storage للـ:
--   - Agent performance metrics (packets/sec, latency, CPU)
--   - ML model accuracy over time
--   - Flow rate per protocol
-- ─────────────────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ── Agent Metrics ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_metrics (
    time            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_id        TEXT        NOT NULL,
    interface       TEXT        NOT NULL,
    packets_per_sec DOUBLE PRECISION,
    bits_per_sec    DOUBLE PRECISION,
    active_flows    BIGINT,
    blocked_flows   BIGINT,
    ebpf_cpu_pct    DOUBLE PRECISION,
    memory_bytes    BIGINT,
    latency_p50_us  DOUBLE PRECISION,
    latency_p99_us  DOUBLE PRECISION,
    latency_p999_us DOUBLE PRECISION
);

SELECT create_hypertable(
    'agent_metrics', 'time',
    chunk_time_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- ── ML Metrics ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ml_metrics (
    time              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    model_name        TEXT        NOT NULL,
    protocol          TEXT,
    accuracy          DOUBLE PRECISION,
    precision_val     DOUBLE PRECISION,
    recall            DOUBLE PRECISION,
    f1_score          DOUBLE PRECISION,
    false_positive_rate DOUBLE PRECISION,
    inference_p50_us  DOUBLE PRECISION,
    inference_p99_us  DOUBLE PRECISION,
    decisions_total   BIGINT,
    corrections_total BIGINT
);

SELECT create_hypertable(
    'ml_metrics', 'time',
    chunk_time_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- ── Flow Rate Metrics ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS flow_rate_metrics (
    time            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    protocol        TEXT        NOT NULL,
    decision        TEXT        NOT NULL,
    flows_per_sec   DOUBLE PRECISION,
    bytes_per_sec   DOUBLE PRECISION,
    risk_score_avg  DOUBLE PRECISION,
    risk_score_p95  DOUBLE PRECISION
);

SELECT create_hypertable(
    'flow_rate_metrics', 'time',
    chunk_time_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- ── UEBA Anomaly Timeline ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ueba_anomalies (
    time            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    host_ip         TEXT        NOT NULL,
    user_id         TEXT,
    anomaly_score   DOUBLE PRECISION,
    anomaly_type    TEXT,
    baseline_score  DOUBLE PRECISION,
    sigma_deviation DOUBLE PRECISION
);

SELECT create_hypertable(
    'ueba_anomalies', 'time',
    chunk_time_interval => INTERVAL '6 hours',
    if_not_exists => TRUE
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent
    ON agent_metrics (agent_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_ml_metrics_model
    ON ml_metrics (model_name, time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_rate_protocol
    ON flow_rate_metrics (protocol, decision, time DESC);

CREATE INDEX IF NOT EXISTS idx_ueba_host
    ON ueba_anomalies (host_ip, time DESC);

-- ── Retention Policies (30 days) ──────────────────────────────────────────────
SELECT add_retention_policy('agent_metrics',   INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('ml_metrics',      INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('flow_rate_metrics',INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('ueba_anomalies',  INTERVAL '30 days', if_not_exists => TRUE);

-- ── Continuous Aggregates (1-minute rollups) ──────────────────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS agent_metrics_1min
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 minute', time) AS bucket,
    agent_id,
    AVG(packets_per_sec) AS avg_pps,
    MAX(packets_per_sec) AS max_pps,
    AVG(active_flows)    AS avg_flows,
    AVG(latency_p99_us)  AS avg_p99_us
FROM agent_metrics
GROUP BY bucket, agent_id;

GRANT ALL ON ALL TABLES IN SCHEMA public TO thor;
