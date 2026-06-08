#!/usr/bin/env bash
# Thor Firewall — ClickHouse Database Initialization
# تهيئة قاعدة بيانات ClickHouse
#
# الاستخدام:
#   ./scripts/db/init_clickhouse.sh [HOST] [PORT] [USER] [PASSWORD]
#
# الافتراضي: localhost:8123 / default / ""

set -euo pipefail

CLICKHOUSE_HOST="${1:-localhost}"
CLICKHOUSE_PORT="${2:-8123}"
CLICKHOUSE_USER="${3:-default}"
CLICKHOUSE_PASS="${4:-}"
CLICKHOUSE_DB="thor"

CH_URL="http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"

echo "🔥 Thor Firewall — ClickHouse Init"
echo "   Host: ${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
echo "   DB:   ${CLICKHOUSE_DB}"
echo ""

# ────────────────────────────────────────────────────────────────────────────
# Helper: run a ClickHouse query
# ────────────────────────────────────────────────────────────────────────────
ch_exec() {
    local query="$1"
    curl -s -u "${CLICKHOUSE_USER}:${CLICKHOUSE_PASS}" \
         --data-urlencode "query=${query}" \
         "${CH_URL}/?database=${CLICKHOUSE_DB}"
}

ch_exec_raw() {
    curl -s -u "${CLICKHOUSE_USER}:${CLICKHOUSE_PASS}" \
         --data "${1}" \
         "${CH_URL}/"
}

# ────────────────────────────────────────────────────────────────────────────
# Step 1: Create Database
# ────────────────────────────────────────────────────────────────────────────
echo "📦 Creating database '${CLICKHOUSE_DB}'..."
ch_exec_raw "CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DB}"
echo "   ✅ Database ready"

# ────────────────────────────────────────────────────────────────────────────
# Step 2: Network Flows table
# الجدول الرئيسي لتسجيل تدفقات الشبكة
# ────────────────────────────────────────────────────────────────────────────
echo "📊 Creating flows table..."
ch_exec "
CREATE TABLE IF NOT EXISTS flows (
    -- Primary key
    event_date      Date        DEFAULT toDate(timestamp),
    timestamp       DateTime64(3, 'UTC') NOT NULL,
    agent_id        LowCardinality(String) DEFAULT 'unknown',

    -- Flow 5-tuple
    src_ip          IPv4        NOT NULL,
    dst_ip          IPv4        NOT NULL,
    src_port        UInt16      NOT NULL,
    dst_port        UInt16      NOT NULL,
    protocol        UInt8       NOT NULL,  -- 6=TCP 17=UDP 1=ICMP

    -- Layer-7
    app_proto       LowCardinality(String) DEFAULT 'unknown',
    tls_ja3         FixedString(32)        DEFAULT '',
    http_host       String                 DEFAULT '',

    -- Statistics
    packets         UInt64      DEFAULT 0,
    bytes           UInt64      DEFAULT 0,
    duration_ms     UInt32      DEFAULT 0,

    -- ML decision
    decision        LowCardinality(String) NOT NULL,  -- allow|block|throttle|mirror
    risk_score      Float32     DEFAULT 0.0,
    confidence      Float32     DEFAULT 0.0,
    is_threat       UInt8       DEFAULT 0,
    threat_type     LowCardinality(String) DEFAULT '',
    mitre_id        LowCardinality(String) DEFAULT '',

    -- Feature vector (stored compressed)
    features        Array(Float32) DEFAULT [],

    -- Geo
    src_country     LowCardinality(String) DEFAULT '',
    src_asn         UInt32      DEFAULT 0,
    dst_country     LowCardinality(String) DEFAULT '',

    -- Indexes hint
    INDEX idx_src_ip   src_ip   TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dst_port dst_port TYPE set(100)            GRANULARITY 1,
    INDEX idx_risk     risk_score TYPE minmax             GRANULARITY 2
)
ENGINE = MergeTree()
PARTITION BY (event_date, agent_id)
ORDER BY (timestamp, src_ip, dst_ip, dst_port)
TTL event_date + INTERVAL 30 DAY
SETTINGS
    index_granularity = 8192,
    min_bytes_for_wide_part = 10000000,
    compress_marks_granularity = 128
"
echo "   ✅ flows table ready"

# ────────────────────────────────────────────────────────────────────────────
# Step 3: Threat Events table
# ────────────────────────────────────────────────────────────────────────────
echo "🚨 Creating threat_events table..."
ch_exec "
CREATE TABLE IF NOT EXISTS threat_events (
    event_date      Date        DEFAULT toDate(timestamp),
    timestamp       DateTime64(3, 'UTC') NOT NULL,
    incident_id     String      DEFAULT '',
    agent_id        LowCardinality(String) DEFAULT 'unknown',

    -- Source/target
    src_ip          IPv4        NOT NULL,
    dst_ip          IPv4        NOT NULL,
    src_port        UInt16      DEFAULT 0,
    dst_port        UInt16      NOT NULL,
    protocol        UInt8       NOT NULL,

    -- Classification
    severity        LowCardinality(String) NOT NULL,   -- low|medium|high|critical
    threat_type     LowCardinality(String) NOT NULL,
    mitre_id        LowCardinality(String) DEFAULT '',
    mitre_tactic    LowCardinality(String) DEFAULT '',

    -- Scores
    risk_score      Float32     NOT NULL,
    confidence      Float32     DEFAULT 0.0,
    marl_risk       Float32     DEFAULT 0.0,
    behavioral_risk Float32     DEFAULT 0.0,
    correlation_risk Float32    DEFAULT 0.0,
    zero_day_risk   Float32     DEFAULT 0.0,

    -- Response
    blocked         UInt8       DEFAULT 0,
    action          LowCardinality(String) DEFAULT 'log',
    soar_executed   UInt8       DEFAULT 0,
    soar_actions    Array(String) DEFAULT [],

    -- Context
    explanation     String      DEFAULT '',
    geo_country     LowCardinality(String) DEFAULT '',
    src_asn         UInt32      DEFAULT 0,
    tags            Array(String) DEFAULT [],

    INDEX idx_src_ip    src_ip     TYPE bloom_filter(0.005) GRANULARITY 4,
    INDEX idx_severity  severity   TYPE set(10)              GRANULARITY 1,
    INDEX idx_threat    threat_type TYPE set(50)             GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY (event_date, severity)
ORDER BY (timestamp, src_ip)
TTL event_date + INTERVAL 365 DAY
SETTINGS index_granularity = 4096
"
echo "   ✅ threat_events table ready"

# ────────────────────────────────────────────────────────────────────────────
# Step 4: Agent Health Metrics table
# ────────────────────────────────────────────────────────────────────────────
echo "💓 Creating agent_metrics table..."
ch_exec "
CREATE TABLE IF NOT EXISTS agent_metrics (
    timestamp       DateTime64(1, 'UTC') NOT NULL,
    agent_id        LowCardinality(String) NOT NULL,

    -- Throughput
    pps             UInt64      DEFAULT 0,  -- packets per second
    bps             UInt64      DEFAULT 0,  -- bits per second
    active_flows    UInt32      DEFAULT 0,
    blocked_flows   UInt32      DEFAULT 0,

    -- ML
    ml_inferences   UInt64      DEFAULT 0,
    ml_latency_us   Float32     DEFAULT 0,
    ml_accuracy     Float32     DEFAULT 0,
    cache_hit_rate  Float32     DEFAULT 0,

    -- System
    cpu_pct         Float32     DEFAULT 0,
    memory_mb       Float32     DEFAULT 0,
    ebpf_errors     UInt32      DEFAULT 0,

    -- Counters
    rules_applied   UInt64      DEFAULT 0,
    iocs_matched    UInt64      DEFAULT 0
)
ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, agent_id)
TTL toDate(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 4096
"
echo "   ✅ agent_metrics table ready"

# ────────────────────────────────────────────────────────────────────────────
# Step 5: Audit Log table
# ────────────────────────────────────────────────────────────────────────────
echo "📋 Creating audit_log table..."
ch_exec "
CREATE TABLE IF NOT EXISTS audit_log (
    timestamp       DateTime64(3, 'UTC') NOT NULL,
    event_date      Date        DEFAULT toDate(timestamp),
    actor           String      NOT NULL,   -- user, agent-id, or 'thor-ai'
    action          String      NOT NULL,   -- rule_added, ip_blocked, etc.
    target          String      DEFAULT '',
    detail          String      DEFAULT '',
    ip_address      String      DEFAULT '',
    result          LowCardinality(String) DEFAULT 'success',
    request_id      String      DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY (event_date)
ORDER BY (timestamp, actor)
TTL event_date + INTERVAL 365 DAY
"
echo "   ✅ audit_log table ready"

# ────────────────────────────────────────────────────────────────────────────
# Step 6: Materialized Views for fast aggregations
# ────────────────────────────────────────────────────────────────────────────
echo "⚡ Creating materialized views..."

ch_exec "
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_top_blocked_ips
ENGINE = SummingMergeTree()
PARTITION BY toDate(day)
ORDER BY (day, src_ip, threat_type)
POPULATE AS
SELECT
    toStartOfDay(timestamp) AS day,
    src_ip,
    threat_type,
    count()          AS hit_count,
    max(risk_score)  AS max_risk,
    sum(toUInt64(blocked)) AS blocked_count
FROM threat_events
GROUP BY day, src_ip, threat_type
"

ch_exec "
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_hourly_stats
ENGINE = SummingMergeTree()
PARTITION BY toDate(hour)
ORDER BY (hour, agent_id)
POPULATE AS
SELECT
    toStartOfHour(timestamp) AS hour,
    agent_id,
    count()              AS total_flows,
    sum(toUInt64(is_threat)) AS threat_flows,
    sum(bytes)           AS total_bytes,
    sum(packets)         AS total_packets,
    avg(risk_score)      AS avg_risk
FROM flows
GROUP BY hour, agent_id
"

echo "   ✅ Materialized views ready"

# ────────────────────────────────────────────────────────────────────────────
# Step 7: Insert sample data for testing
# ────────────────────────────────────────────────────────────────────────────
echo "🌱 Inserting sample data..."

ch_exec "
INSERT INTO threat_events
    (timestamp, src_ip, dst_ip, dst_port, protocol, severity, threat_type, risk_score, confidence, blocked, action)
VALUES
    (now(), '185.234.218.48', '10.0.1.1', 22,  6, 'high',     'brute-force', 0.88, 0.92, 1, 'block'),
    (now(), '91.109.4.80',    '10.0.1.1', 80,  6, 'medium',   'port-scan',   0.65, 0.78, 0, 'throttle'),
    (now(), '103.73.65.47',   '10.0.1.1', 443, 6, 'critical', 'syn-flood',   0.97, 0.99, 1, 'block'),
    (now(), '45.33.32.100',   '10.0.1.1', 53,  17,'high',     'dns-tunnel',  0.82, 0.88, 1, 'block')
"

echo "   ✅ Sample data inserted"

echo ""
echo "════════════════════════════════════════"
echo "🎉 Thor ClickHouse initialization complete!"
echo ""
echo "   Tables created:"
echo "     ✅ thor.flows"
echo "     ✅ thor.threat_events"
echo "     ✅ thor.agent_metrics"
echo "     ✅ thor.audit_log"
echo "     ✅ thor.mv_top_blocked_ips (materialized view)"
echo "     ✅ thor.mv_hourly_stats    (materialized view)"
echo ""
echo "   Test with:"
echo "   curl '${CH_URL}/?query=SELECT+count()+FROM+thor.threat_events'"
echo "════════════════════════════════════════"
