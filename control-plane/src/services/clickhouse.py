"""
Thor Firewall — ClickHouse Forensics Client
قاعدة بيانات التحليل الجنائي عالية الأداء

ClickHouse: أسرع قاعدة بيانات OLAP — تُحلّل مليارات الصفوف/ثانية
تُستخدم لـ:
  - تخزين كل تدفق شبكي (نُعيد البحث لاحقاً)
  - استعلامات زمنية للتحقيق الجنائي
  - كشف الأنماط التاريخية (IoC hunting)
  - تصدير بيانات للـ SIEM

Schema:
  thor_flows     — جدول الحوادث الشبكية (MergeTree, TTL 90 days)
  thor_threats   — أحداث التهديدات المُكتشفة
  thor_decisions — قرارات ML لكل تدفق
  thor_stats     — إحصاءات دقيقية (SummingMergeTree)
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import clickhouse_connect
from clickhouse_connect.driver import AsyncClient as CHAsyncClient
from clickhouse_connect.driver.exceptions import ClickHouseError

logger = logging.getLogger("thor.clickhouse")

# ============================================================================
# Configuration
# ============================================================================

@dataclass
class ClickHouseConfig:
    host: str = "localhost"
    port: int = 8123
    database: str = "thor"
    username: str = "thor_agent"
    password: str = ""
    # حجم batch للإدراج (أفضل أداء مع > 1000 صف)
    batch_size: int = 5_000
    # فترة flush (ثوانٍ) — يُرسل حتى لو البatch لم يكتمل
    flush_interval_sec: float = 2.0
    # DDL timeout (ثوانٍ)
    ddl_timeout: int = 30
    # Connection pool size
    pool_size: int = 4
    # Compression للبيانات المُرسلة
    compress: bool = True


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class FlowRow:
    """صف في جدول thor_flows"""
    # وقت أول حزمة (ثانية من UNIX)
    first_seen:         datetime
    # وقت آخر حزمة
    last_seen:          datetime
    # Flow identifiers
    src_ip:             str
    dst_ip:             str
    src_port:           int
    dst_port:           int
    protocol:           str   # "TCP" | "UDP" | "ICMP"
    # Metrics
    packets:            int
    bytes_total:        int
    packets_per_second: float
    bits_per_second:    float
    avg_packet_size:    float
    payload_entropy:    float
    # ML output
    risk_score:         float
    decision:           str   # "allow" | "block" | "throttle" | "mirror"
    confidence:         float
    agent_id:           str
    # Optional context
    country_src:        str = ""
    asn_src:            int = 0
    tags:               List[str] = None
    explanation:        str = ""
    # Geolocation
    latitude_src:       float = 0.0
    longitude_src:      float = 0.0

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class ThreatRow:
    """صف في جدول thor_threats"""
    timestamp:          datetime
    severity:           str   # "low" | "medium" | "high" | "critical"
    threat_type:        str   # "port_scan" | "syn_flood" | "c2_beacon" | ...
    src_ip:             str
    dst_ip:             str
    dst_port:           int
    protocol:           str
    risk_score:         float
    confidence:         float
    mitre_tactic:       str   # "Reconnaissance" | "C2" | ...
    mitre_technique:    str   # "T1046" | ...
    packets:            int
    bytes_total:        int
    blocked:            bool
    explanation:        str = ""
    ioc_matched:        str = ""   # IOC database reference


@dataclass
class DecisionRow:
    """صف في جدول thor_decisions — كل قرار ML"""
    timestamp:      datetime
    flow_hash:      int
    src_ip:         str
    dst_ip:         str
    src_port:       int
    dst_port:       int
    protocol:       str
    decision:       str
    risk_score:     float
    confidence:     float
    latency_us:     int
    agent_id:       str
    model_version:  str = "1.0.0"


# ============================================================================
# ClickHouse Schema DDL
# ============================================================================

SCHEMA_DDL = """
-- ─────────────────────────────────────────────────────────────────
-- Database
-- ─────────────────────────────────────────────────────────────────
CREATE DATABASE IF NOT EXISTS thor
    COMMENT 'Thor Firewall forensics database';

-- ─────────────────────────────────────────────────────────────────
-- thor_flows — كل تدفق شبكي
-- MergeTree مع TTL 90 يوماً للضغط التلقائي
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.thor_flows (
    first_seen          DateTime64(3, 'UTC'),
    last_seen           DateTime64(3, 'UTC'),
    src_ip              IPv4,
    dst_ip              IPv4,
    src_port            UInt16,
    dst_port            UInt16,
    protocol            LowCardinality(String),
    packets             UInt64,
    bytes_total         UInt64,
    packets_per_second  Float64,
    bits_per_second     Float64,
    avg_packet_size     Float32,
    payload_entropy     Float32,
    risk_score          Float32,
    decision            LowCardinality(String),
    confidence          Float32,
    agent_id            LowCardinality(String),
    country_src         LowCardinality(String),
    asn_src             UInt32,
    tags                Array(String),
    explanation         String,
    latitude_src        Float32,
    longitude_src       Float32
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first_seen)
ORDER BY (first_seen, src_ip, dst_ip, dst_port)
TTL first_seen + INTERVAL 90 DAY
SETTINGS index_granularity = 8192, min_bytes_for_wide_part = 10485760;

-- ─────────────────────────────────────────────────────────────────
-- thor_threats — أحداث التهديدات
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.thor_threats (
    timestamp           DateTime64(3, 'UTC'),
    severity            LowCardinality(String),
    threat_type         LowCardinality(String),
    src_ip              IPv4,
    dst_ip              IPv4,
    dst_port            UInt16,
    protocol            LowCardinality(String),
    risk_score          Float32,
    confidence          Float32,
    mitre_tactic        LowCardinality(String),
    mitre_technique     LowCardinality(String),
    packets             UInt64,
    bytes_total         UInt64,
    blocked             Bool,
    explanation         String,
    ioc_matched         String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, severity, src_ip)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ─────────────────────────────────────────────────────────────────
-- thor_decisions — كل قرار ML (لحساب accuracy وإعادة التدريب)
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.thor_decisions (
    timestamp       DateTime64(3, 'UTC'),
    flow_hash       UInt64,
    src_ip          IPv4,
    dst_ip          IPv4,
    src_port        UInt16,
    dst_port        UInt16,
    protocol        LowCardinality(String),
    decision        LowCardinality(String),
    risk_score      Float32,
    confidence      Float32,
    latency_us      UInt32,
    agent_id        LowCardinality(String),
    model_version   LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, flow_hash)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ─────────────────────────────────────────────────────────────────
-- thor_stats_1m — إحصاءات دقيقية مُجمَّعة
-- SummingMergeTree تجمع الصفوف ذات نفس المفتاح
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS thor.thor_stats_1m (
    minute          DateTime('UTC'),
    protocol        LowCardinality(String),
    total_packets   UInt64,
    total_bytes     UInt64,
    total_flows     UInt64,
    blocked_flows   UInt64,
    threats_detected UInt32,
    avg_risk_score  Float64
)
ENGINE = SummingMergeTree((total_packets, total_bytes, total_flows, blocked_flows, threats_detected))
PARTITION BY toYYYYMM(minute)
ORDER BY (minute, protocol)
TTL minute + INTERVAL 365 DAY;

-- ─────────────────────────────────────────────────────────────────
-- Materialized View: flows → stats_1m (تحديث تلقائي)
-- ─────────────────────────────────────────────────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS thor.mv_stats_1m
TO thor.thor_stats_1m
AS SELECT
    toStartOfMinute(first_seen)    AS minute,
    protocol,
    count()                        AS total_flows,
    sum(packets)                   AS total_packets,
    sum(bytes_total)               AS total_bytes,
    countIf(decision = 'block')    AS blocked_flows,
    0                              AS threats_detected,
    avg(risk_score)                AS avg_risk_score
FROM thor.thor_flows
GROUP BY minute, protocol;
"""


# ============================================================================
# ClickHouse Client
# ============================================================================

class ThorClickHouseClient:
    """
    Client ClickHouse مع batch insertion و schema initialization تلقائية
    """

    def __init__(self, config: ClickHouseConfig):
        self.config = config
        self._client: Optional[CHAsyncClient] = None
        self._initialized = False

        # Buffers داخلية للـ batch insertion
        self._flow_buffer:     List[FlowRow]     = []
        self._threat_buffer:   List[ThreatRow]   = []
        self._decision_buffer: List[DecisionRow] = []

        # Background flush task
        self._flush_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        """الاتصال بـ ClickHouse وتهيئة الـ Schema"""
        try:
            self._client = await clickhouse_connect.get_async_client(
                host=self.config.host,
                port=self.config.port,
                database="default",  # نبدأ بـ default ثم ننشئ thor
                username=self.config.username,
                password=self.config.password,
                compress=self.config.compress,
                connect_timeout=10,
                send_receive_timeout=60,
            )

            await self._init_schema()
            self._initialized = True

            # بدء flush loop في الخلفية
            self._flush_task = asyncio.create_task(self._flush_loop())

            logger.info(
                "ClickHouse connected: %s:%d/thor",
                self.config.host,
                self.config.port,
            )

        except Exception as e:
            logger.error("ClickHouse connection failed: %s", e)
            raise

    async def _init_schema(self) -> None:
        """إنشاء قاعدة البيانات والجداول إذا لم تكن موجودة"""
        # تنفيذ كل جملة DDL على حدة (ClickHouse لا يدعم multi-statement)
        statements = [s.strip() for s in SCHEMA_DDL.split(";") if s.strip()]
        for stmt in statements:
            if stmt:
                try:
                    await self._client.command(stmt)
                except ClickHouseError as e:
                    if "already exists" not in str(e).lower():
                        logger.warning("DDL warning: %s", e)

        # التبديل لقاعدة thor
        self._client = await clickhouse_connect.get_async_client(
            host=self.config.host,
            port=self.config.port,
            database=self.config.database,
            username=self.config.username,
            password=self.config.password,
            compress=self.config.compress,
        )
        logger.info("ClickHouse schema initialized")

    # ─────────────────────────────────────────────────────────────────────
    # Insertion Methods (buffered)
    # ─────────────────────────────────────────────────────────────────────

    async def insert_flow(self, row: FlowRow) -> None:
        async with self._lock:
            self._flow_buffer.append(row)
            if len(self._flow_buffer) >= self.config.batch_size:
                await self._flush_flows()

    async def insert_threat(self, row: ThreatRow) -> None:
        async with self._lock:
            self._threat_buffer.append(row)
            if len(self._threat_buffer) >= self.config.batch_size:
                await self._flush_threats()

    async def insert_decision(self, row: DecisionRow) -> None:
        async with self._lock:
            self._decision_buffer.append(row)
            if len(self._decision_buffer) >= self.config.batch_size:
                await self._flush_decisions()

    # ─────────────────────────────────────────────────────────────────────
    # Flush Logic
    # ─────────────────────────────────────────────────────────────────────

    async def _flush_loop(self) -> None:
        """يُشغَّل كل flush_interval_sec لإرسال البيانات المتراكمة"""
        while True:
            await asyncio.sleep(self.config.flush_interval_sec)
            try:
                async with self._lock:
                    if self._flow_buffer:
                        await self._flush_flows()
                    if self._threat_buffer:
                        await self._flush_threats()
                    if self._decision_buffer:
                        await self._flush_decisions()
            except Exception as e:
                logger.error("Flush loop error: %s", e)

    async def _flush_flows(self) -> None:
        if not self._flow_buffer:
            return
        rows = self._flow_buffer[:]
        self._flow_buffer.clear()

        data = []
        for r in rows:
            data.append([
                r.first_seen, r.last_seen,
                r.src_ip, r.dst_ip,
                r.src_port, r.dst_port, r.protocol,
                r.packets, r.bytes_total,
                r.packets_per_second, r.bits_per_second,
                r.avg_packet_size, r.payload_entropy,
                r.risk_score, r.decision, r.confidence, r.agent_id,
                r.country_src, r.asn_src, r.tags, r.explanation,
                r.latitude_src, r.longitude_src,
            ])

        columns = [
            "first_seen", "last_seen", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol",
            "packets", "bytes_total", "packets_per_second", "bits_per_second",
            "avg_packet_size", "payload_entropy",
            "risk_score", "decision", "confidence", "agent_id",
            "country_src", "asn_src", "tags", "explanation",
            "latitude_src", "longitude_src",
        ]

        await self._client.insert("thor_flows", data, column_names=columns)
        logger.debug("Flushed %d flows to ClickHouse", len(rows))

    async def _flush_threats(self) -> None:
        if not self._threat_buffer:
            return
        rows = self._threat_buffer[:]
        self._threat_buffer.clear()

        data = [[
            r.timestamp, r.severity, r.threat_type,
            r.src_ip, r.dst_ip, r.dst_port, r.protocol,
            r.risk_score, r.confidence,
            r.mitre_tactic, r.mitre_technique,
            r.packets, r.bytes_total, r.blocked,
            r.explanation, r.ioc_matched,
        ] for r in rows]

        columns = [
            "timestamp", "severity", "threat_type",
            "src_ip", "dst_ip", "dst_port", "protocol",
            "risk_score", "confidence",
            "mitre_tactic", "mitre_technique",
            "packets", "bytes_total", "blocked",
            "explanation", "ioc_matched",
        ]
        await self._client.insert("thor_threats", data, column_names=columns)
        logger.debug("Flushed %d threats to ClickHouse", len(rows))

    async def _flush_decisions(self) -> None:
        if not self._decision_buffer:
            return
        rows = self._decision_buffer[:]
        self._decision_buffer.clear()

        data = [[
            r.timestamp, r.flow_hash,
            r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.protocol,
            r.decision, r.risk_score, r.confidence,
            r.latency_us, r.agent_id, r.model_version,
        ] for r in rows]

        columns = [
            "timestamp", "flow_hash",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "decision", "risk_score", "confidence",
            "latency_us", "agent_id", "model_version",
        ]
        await self._client.insert("thor_decisions", data, column_names=columns)
        logger.debug("Flushed %d decisions to ClickHouse", len(rows))

    # ─────────────────────────────────────────────────────────────────────
    # Query Methods — للـ Forensics API
    # ─────────────────────────────────────────────────────────────────────

    async def query_flows(
        self,
        start: datetime,
        end: datetime,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        min_risk: float = 0.0,
        decision: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[Dict]:
        """استعلام التدفقات الشبكية مع فلاتر متعددة"""
        conditions = [
            "first_seen BETWEEN {start:DateTime64} AND {end:DateTime64}",
        ]
        params: Dict[str, Any] = {"start": start, "end": end}

        if src_ip:
            conditions.append("src_ip = {src_ip:IPv4}")
            params["src_ip"] = src_ip
        if dst_ip:
            conditions.append("dst_ip = {dst_ip:IPv4}")
            params["dst_ip"] = dst_ip
        if dst_port:
            conditions.append("dst_port = {dst_port:UInt16}")
            params["dst_port"] = dst_port
        if protocol:
            conditions.append("protocol = {protocol:String}")
            params["protocol"] = protocol.upper()
        if min_risk > 0.0:
            conditions.append("risk_score >= {min_risk:Float32}")
            params["min_risk"] = min_risk
        if decision:
            conditions.append("decision = {decision:String}")
            params["decision"] = decision

        where = " AND ".join(conditions)
        query = f"""
            SELECT
                toString(first_seen)   AS first_seen,
                toString(last_seen)    AS last_seen,
                IPv4NumToString(src_ip) AS src_ip,
                IPv4NumToString(dst_ip) AS dst_ip,
                src_port, dst_port, protocol,
                packets, bytes_total,
                round(packets_per_second, 2) AS pps,
                round(bits_per_second / 1e6, 3) AS mbps,
                round(avg_packet_size, 1) AS avg_pkt,
                round(payload_entropy, 3) AS entropy,
                round(risk_score, 4) AS risk_score,
                decision,
                round(confidence, 3) AS confidence,
                agent_id, country_src, asn_src, tags,
                explanation
            FROM thor_flows
            WHERE {where}
            ORDER BY first_seen DESC
            LIMIT {limit} OFFSET {offset}
        """

        result = await self._client.query(query, parameters=params)
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    async def query_threats(
        self,
        start: datetime,
        end: datetime,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        src_ip: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict]:
        """استعلام أحداث التهديدات"""
        conditions = ["timestamp BETWEEN {start:DateTime64} AND {end:DateTime64}"]
        params: Dict[str, Any] = {"start": start, "end": end}

        if severity:
            conditions.append("severity = {severity:String}")
            params["severity"] = severity
        if threat_type:
            conditions.append("threat_type = {threat_type:String}")
            params["threat_type"] = threat_type
        if src_ip:
            conditions.append("src_ip = {src_ip:IPv4}")
            params["src_ip"] = src_ip
        if mitre_tactic:
            conditions.append("mitre_tactic = {mitre_tactic:String}")
            params["mitre_tactic"] = mitre_tactic

        where = " AND ".join(conditions)
        query = f"""
            SELECT
                toString(timestamp) AS timestamp,
                severity, threat_type,
                IPv4NumToString(src_ip) AS src_ip,
                IPv4NumToString(dst_ip) AS dst_ip,
                dst_port, protocol,
                round(risk_score, 4) AS risk_score,
                round(confidence, 3) AS confidence,
                mitre_tactic, mitre_technique,
                packets, bytes_total, blocked,
                explanation, ioc_matched
            FROM thor_threats
            WHERE {where}
            ORDER BY timestamp DESC, risk_score DESC
            LIMIT {limit}
        """

        result = await self._client.query(query, parameters=params)
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    async def query_timeline(
        self,
        start: datetime,
        end: datetime,
        granularity: str = "1 MINUTE",
    ) -> List[Dict]:
        """سلسلة زمنية للإحصاءات (للرسوم البيانية)"""
        valid = {"1 MINUTE", "5 MINUTE", "15 MINUTE", "1 HOUR", "1 DAY"}
        if granularity not in valid:
            granularity = "5 MINUTE"

        query = f"""
            SELECT
                toStartOf{granularity.replace(' ', '')}(minute) AS ts,
                sum(total_packets)    AS packets,
                sum(total_bytes)      AS bytes,
                sum(total_flows)      AS flows,
                sum(blocked_flows)    AS blocked,
                round(avg(avg_risk_score), 4) AS avg_risk
            FROM thor_stats_1m
            WHERE minute BETWEEN {{start:DateTime64}} AND {{end:DateTime64}}
            GROUP BY ts
            ORDER BY ts ASC
        """

        result = await self._client.query(query, parameters={"start": start, "end": end})
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    async def query_top_talkers(
        self,
        start: datetime,
        end: datetime,
        by: str = "bytes",
        limit: int = 20,
    ) -> List[Dict]:
        """أكثر الـ IPs نشاطاً (Top Talkers)"""
        metric = "sum(bytes_total)" if by == "bytes" else "sum(packets)"
        query = f"""
            SELECT
                IPv4NumToString(src_ip) AS ip,
                count() AS flow_count,
                sum(packets) AS total_packets,
                sum(bytes_total) AS total_bytes,
                round(avg(risk_score), 4) AS avg_risk,
                groupArray(DISTINCT decision) AS decisions,
                groupArray(DISTINCT country_src) AS countries
            FROM thor_flows
            WHERE first_seen BETWEEN {{start:DateTime64}} AND {{end:DateTime64}}
            GROUP BY src_ip
            ORDER BY {metric} DESC
            LIMIT {limit}
        """

        result = await self._client.query(query, parameters={"start": start, "end": end})
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    async def query_attack_heatmap(
        self,
        start: datetime,
        end: datetime,
    ) -> List[Dict]:
        """خريطة حرارة للهجمات: بلد المصدر × نوع التهديد"""
        query = """
            SELECT
                country_src AS country,
                count() AS attack_count,
                sum(bytes_total) AS total_bytes,
                round(avg(risk_score), 4) AS avg_risk,
                groupArray(DISTINCT threat_type) AS threat_types
            FROM thor_threats AS t
            JOIN thor_flows AS f
              ON t.src_ip = f.src_ip
              AND t.timestamp BETWEEN f.first_seen AND f.last_seen
            WHERE t.timestamp BETWEEN {start:DateTime64} AND {end:DateTime64}
              AND country_src != ''
            GROUP BY country_src
            ORDER BY attack_count DESC
            LIMIT 50
        """

        result = await self._client.query(query, parameters={"start": start, "end": end})
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    async def search_ip(self, ip: str, days_back: int = 30) -> Dict:
        """بحث شامل عن IP — كل النشاط المُسجَّل"""
        from datetime import timedelta
        end = datetime.now(tz=timezone.utc)
        start = end - timedelta(days=days_back)

        # استعلامات موازية
        flows_task = self._client.query(f"""
            SELECT count(), sum(packets), sum(bytes_total),
                   min(first_seen), max(last_seen),
                   groupArray(DISTINCT decision) AS decisions,
                   round(avg(risk_score), 4) AS avg_risk
            FROM thor_flows
            WHERE src_ip = {{ip:IPv4}}
              AND first_seen >= {{start:DateTime64}}
        """, parameters={"ip": ip, "start": start})

        threats_task = self._client.query(f"""
            SELECT count(), groupArray(DISTINCT threat_type),
                   groupArray(DISTINCT mitre_technique),
                   max(risk_score) AS max_risk
            FROM thor_threats
            WHERE src_ip = {{ip:IPv4}}
              AND timestamp >= {{start:DateTime64}}
        """, parameters={"ip": ip, "start": start})

        flows_r, threats_r = await asyncio.gather(flows_task, threats_task)

        flow_row   = flows_r.result_rows[0]   if flows_r.result_rows   else [0] * 7
        threat_row = threats_r.result_rows[0] if threats_r.result_rows else [0, [], [], 0.0]

        return {
            "ip": ip,
            "period_days": days_back,
            "flows": {
                "count":        flow_row[0],
                "packets":      flow_row[1],
                "bytes":        flow_row[2],
                "first_seen":   str(flow_row[3]) if flow_row[3] else None,
                "last_seen":    str(flow_row[4]) if flow_row[4] else None,
                "decisions":    flow_row[5],
                "avg_risk":     flow_row[6],
            },
            "threats": {
                "count":            threat_row[0],
                "threat_types":     threat_row[1],
                "mitre_techniques": threat_row[2],
                "max_risk":         threat_row[3],
            },
        }

    async def export_csv(
        self,
        table: str,
        start: datetime,
        end: datetime,
    ) -> bytes:
        """تصدير بيانات بصيغة CSV لاستيرادها في SIEM"""
        valid_tables = {"thor_flows", "thor_threats", "thor_decisions"}
        if table not in valid_tables:
            raise ValueError(f"Invalid table: {table}")

        query = f"""
            SELECT *
            FROM {table}
            WHERE {'first_seen' if table == 'thor_flows' else 'timestamp'}
                BETWEEN {{start:DateTime64}} AND {{end:DateTime64}}
            ORDER BY 1
            FORMAT CSVWithNames
        """

        result = await self._client.raw_query(query, parameters={"start": start, "end": end})
        return result

    async def close(self) -> None:
        if self._flush_task:
            self._flush_task.cancel()
        # Final flush
        async with self._lock:
            await self._flush_flows()
            await self._flush_threats()
            await self._flush_decisions()
        if self._client:
            await self._client.close()
        logger.info("ClickHouse client closed")


# ============================================================================
# Singleton / Dependency Injection
# ============================================================================

_ch_client: Optional[ThorClickHouseClient] = None


async def get_clickhouse() -> ThorClickHouseClient:
    """FastAPI dependency — returns connected ClickHouse client"""
    global _ch_client
    if _ch_client is None or not _ch_client._initialized:
        raise RuntimeError("ClickHouse client not initialized. Call init_clickhouse() at startup.")
    return _ch_client


async def init_clickhouse(config: Optional[ClickHouseConfig] = None) -> ThorClickHouseClient:
    """يُستدعى عند startup الـ FastAPI app"""
    global _ch_client
    cfg = config or ClickHouseConfig()
    _ch_client = ThorClickHouseClient(cfg)

    try:
        await _ch_client.connect()
    except Exception as e:
        logger.warning("ClickHouse unavailable at startup: %s — forensics disabled", e)
        # لا نوقف الـ API — الـ forensics اختيارية
        _ch_client._initialized = False

    return _ch_client
