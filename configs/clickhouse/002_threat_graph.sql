-- Thor Firewall — ClickHouse Threat Graph Schema
-- Migration 002: Threat Graph (CrowdStrike Threat Graph Equivalent)
-- الهدف: قاعدة بيانات graph تربط مليارات الأحداث

CREATE DATABASE IF NOT EXISTS thor;

-- ── Graph Nodes (الكيانات) ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.graph_nodes (
    node_id      String,
    node_type    Enum8('ip'=1, 'host'=2, 'user'=3, 'process'=4,
                       'file'=5, 'domain'=6, 'asn'=7, 'country'=8),
    first_seen   DateTime DEFAULT now(),
    last_seen    DateTime DEFAULT now(),
    risk_score   Float32  DEFAULT 0.0,
    threat_tags  Array(String),    -- ['c2', 'scanner', 'botnet', 'tor_exit']
    ioc_match    Bool     DEFAULT false,
    ioc_sources  Array(String),    -- ['misp', 'otx', 'abuseipdb']
    country      LowCardinality(String) DEFAULT '',
    asn          String DEFAULT '',
    hostname     String DEFAULT '',
    metadata     String DEFAULT '{}'  -- JSON
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (node_type, node_id)
SETTINGS index_granularity = 4096;

-- ── Graph Edges (العلاقات) ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.graph_edges (
    src_node     String,
    dst_node     String,
    edge_type    Enum8('network_flow'=1, 'authenticated'=2, 'transferred_data'=3,
                       'resolved_domain'=4, 'same_campaign'=5, 'lateral_moved'=6),
    first_seen   DateTime DEFAULT now(),
    last_seen    DateTime DEFAULT now(),
    flow_count   UInt64   DEFAULT 0,
    bytes_total  UInt64   DEFAULT 0,
    packets_total UInt64  DEFAULT 0,
    risk_score   Float32  DEFAULT 0.0,
    protocols    Array(LowCardinality(String)),
    dst_ports    Array(UInt16)
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (src_node, dst_node, edge_type)
SETTINGS index_granularity = 4096;

-- ── Threat Campaigns ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.threat_campaigns (
    campaign_id   String,
    name          String,
    threat_actor  String DEFAULT 'Unknown',
    start_time    DateTime,
    last_activity DateTime,
    node_ids      Array(String),    -- الكيانات المشاركة
    ioc_list      Array(String),    -- IOCs المرتبطة
    mitre_ids     Array(String),
    severity      LowCardinality(String) DEFAULT 'medium',
    confidence    Float32 DEFAULT 0.5,
    description   String DEFAULT ''
) ENGINE = ReplacingMergeTree(last_activity)
ORDER BY campaign_id;

-- ── Materialized View: تحديث الـ edges تلقائياً من الـ flows ─────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS thor.graph_edges_from_flows
TO thor.graph_edges
AS SELECT
    toString(src_ip) AS src_node,
    toString(dst_ip) AS dst_node,
    1                AS edge_type,    -- network_flow
    min(ts)          AS first_seen,
    max(ts)          AS last_seen,
    count()          AS flow_count,
    sum(bytes)       AS bytes_total,
    sum(packets)     AS packets_total,
    avg(risk_score)  AS risk_score,
    groupUniqArray(protocol) AS protocols,
    groupUniqArray(dst_port) AS dst_ports
FROM thor.flows
WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
GROUP BY src_ip, dst_ip;

-- ── Materialized View: تحديث الـ nodes تلقائياً ─────────────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS thor.graph_nodes_from_flows
TO thor.graph_nodes
AS SELECT
    toString(src_ip) AS node_id,
    1                AS node_type,    -- ip
    min(ts)          AS first_seen,
    max(ts)          AS last_seen,
    max(risk_score)  AS risk_score,
    [] AS threat_tags,
    false AS ioc_match,
    [] AS ioc_sources,
    '' AS country,
    '' AS asn,
    '' AS hostname,
    '{}' AS metadata
FROM thor.flows
WHERE src_ip IS NOT NULL
GROUP BY src_ip;

-- ── XDR Incidents Table ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.xdr_incidents (
    incident_id   String,
    chain_id      String,
    title         String,
    severity      LowCardinality(String),
    status        LowCardinality(String) DEFAULT 'open',
    risk_score    Float32,
    start_time    DateTime,
    end_time      DateTime,
    affected_ips  Array(String),
    event_count   UInt32 DEFAULT 0,
    mitre_tactics Array(String),
    kill_chain_pct Float32 DEFAULT 0.0,  -- % Kill Chain اكتمل
    summary       String DEFAULT '',
    assigned_to   String DEFAULT '',
    created_at    DateTime DEFAULT now(),
    updated_at    DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (incident_id)
TTL created_at + INTERVAL 365 DAY;

-- ── Risk Events Table (لـ Risk-Based Alerting) ───────────────────────────────
CREATE TABLE IF NOT EXISTS thor.risk_events (
    ts           DateTime64(3) DEFAULT now64(),
    entity_id    String,
    entity_type  LowCardinality(String),
    event_type   LowCardinality(String),
    score_delta  UInt16,
    details      String DEFAULT '{}'
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, entity_id)
TTL ts + INTERVAL 30 DAY;

-- ── Graph Query Helpers ───────────────────────────────────────────────────────

-- أفضل 20 IP بـ outbound connections (scanners / lateral movers)
CREATE VIEW IF NOT EXISTS thor.top_talkers AS
SELECT
    src_node AS ip,
    count()  AS edge_count,
    sum(flow_count) AS total_flows,
    sum(bytes_total) AS total_bytes,
    max(risk_score) AS max_risk
FROM thor.graph_edges
WHERE edge_type = 1  -- network_flow
  AND last_seen >= now() - INTERVAL 24 HOUR
GROUP BY src_node
ORDER BY total_flows DESC
LIMIT 20;

-- IPs مع أعلى risk score
CREATE VIEW IF NOT EXISTS thor.high_risk_ips AS
SELECT node_id AS ip, risk_score, threat_tags, ioc_match, country, last_seen
FROM thor.graph_nodes
WHERE node_type = 1   -- ip
  AND risk_score > 0.7
ORDER BY risk_score DESC
LIMIT 100;
