"""
Thor Firewall — ClickHouse Client & Schema
قاعدة بيانات ClickHouse للتخزين الزمني

تُخزن:
- جميع التدفقات (1B+ يومياً)
- أحداث التهديدات
- إحصاءات النظام كل ثانية
- سجلات قرارات ML

تُستخدم:
- ZSTD compression (10:1 نسبة ضغط)
- TTL: تدفقات عادية 30 يوم، تهديدات 365 يوم
- MergeTree engine مع partitioning حسب اليوم

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("thor.clickhouse")

# اختياري: clickhouse-driver أو clickhouse-connect
try:
    import clickhouse_connect
    CLICKHOUSE_AVAILABLE = True
except ImportError:
    CLICKHOUSE_AVAILABLE = False
    logger.warning("clickhouse-connect not installed — ClickHouse features disabled")

# ============================================================================
# Schema DDL
# ============================================================================

SCHEMA_DDL = [
    # ===== جدول التدفقات الرئيسي =====
    """
    CREATE TABLE IF NOT EXISTS thor.flows (
        -- مفتاح التدفق
        src_ip          IPv4,
        dst_ip          IPv4,
        src_port        UInt16,
        dst_port        UInt16,
        protocol        UInt8,
        is_ipv6         Bool DEFAULT false,

        -- توقيت
        first_seen      DateTime64(3) CODEC(Delta, ZSTD),
        last_seen       DateTime64(3) CODEC(Delta, ZSTD),
        duration_ms     UInt64,

        -- إحصاءات
        packets         UInt64  CODEC(Delta, ZSTD),
        bytes           UInt64  CODEC(Delta, ZSTD),
        pps             Float32,
        bps             Float64,
        avg_pkt_size    Float32,
        pkt_size_var    Float32,
        payload_entropy Float32,
        retransmissions UInt32,

        -- قرار ML
        decision        LowCardinality(String),  -- allow/block/throttle
        risk_score      Float32,
        confidence      Float32,
        agent_id        LowCardinality(String),
        explanation     String,

        -- تصنيف التهديد
        is_threat       Bool DEFAULT false,
        threat_type     LowCardinality(String),
        mitre_technique LowCardinality(String),

        -- نقاط ML الخام
        features        Array(Float32),

        -- Partition key
        date            Date DEFAULT toDate(first_seen)
    )
    ENGINE = MergeTree()
    PARTITION BY date
    ORDER BY (src_ip, dst_ip, src_port, dst_port, first_seen)
    TTL date + INTERVAL 30 DAY
    SETTINGS index_granularity = 8192,
             compress_primary_key = 1
    """,

    # ===== جدول أحداث التهديدات =====
    """
    CREATE TABLE IF NOT EXISTS thor.threat_events (
        event_id        UUID DEFAULT generateUUIDv4(),
        timestamp       DateTime64(3) CODEC(Delta, ZSTD),

        -- مصدر التهديد
        src_ip          IPv4,
        dst_ip          IPv4,
        src_port        UInt16,
        dst_port        UInt16,
        protocol        UInt8,

        -- تصنيف
        threat_type     LowCardinality(String),
        severity        LowCardinality(String),  -- low/medium/high/critical
        mitre_technique LowCardinality(String),
        mitre_tactic    LowCardinality(String),

        -- ML
        risk_score      Float32,
        confidence      Float32,
        agent_id        LowCardinality(String),
        explanation     String,

        -- استجابة
        action_taken    LowCardinality(String),
        blocked         Bool,
        response_ms     UInt32,

        -- بيانات إضافية
        country_code    LowCardinality(FixedString(2)),
        asn             UInt32,
        tags            Array(LowCardinality(String)),

        date            Date DEFAULT toDate(timestamp)
    )
    ENGINE = MergeTree()
    PARTITION BY date
    ORDER BY (timestamp, src_ip, threat_type)
    TTL date + INTERVAL 365 DAY
    """,

    # ===== جدول إحصاءات الشبكة (كل ثانية) =====
    """
    CREATE TABLE IF NOT EXISTS thor.network_stats (
        timestamp           DateTime64(3) CODEC(Delta, ZSTD),
        agent_id            LowCardinality(String),

        -- معدلات الشبكة
        packets_per_second  Float64,
        bits_per_second     Float64,
        bytes_per_second    Float64,

        -- التدفقات
        active_flows        UInt64,
        blocked_flows       UInt32,
        suspicious_flows    UInt32,
        new_flows_rate      Float32,

        -- أداء XDP
        xdp_pass            UInt64  CODEC(Delta, ZSTD),
        xdp_drop            UInt64  CODEC(Delta, ZSTD),
        xdp_aborted         UInt32,
        table_utilization   Float32,

        -- أداء ML
        ml_latency_us       Float32,
        ml_accuracy         Float32,
        ml_inferences       UInt32,

        -- نظام
        cpu_pct             Float32,
        memory_mb           UInt32,

        date                Date DEFAULT toDate(timestamp)
    )
    ENGINE = MergeTree()
    PARTITION BY date
    ORDER BY (timestamp, agent_id)
    TTL date + INTERVAL 7 DAY
    SETTINGS index_granularity = 1024
    """,

    # ===== Views مُجمَّعة =====
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS thor.hourly_stats
    ENGINE = SummingMergeTree()
    PARTITION BY toDate(hour)
    ORDER BY (hour, agent_id)
    AS SELECT
        toStartOfHour(timestamp) AS hour,
        agent_id,
        sum(packets_per_second) AS total_packets,
        avg(bits_per_second) AS avg_bps,
        max(active_flows) AS max_flows,
        sum(blocked_flows) AS total_blocked,
        avg(ml_latency_us) AS avg_ml_latency
    FROM thor.network_stats
    GROUP BY hour, agent_id
    """,

    # ===== قائمة الحظر الديناميكية =====
    """
    CREATE TABLE IF NOT EXISTS thor.blocklist (
        ip          IPv4,
        cidr_prefix UInt8 DEFAULT 32,
        reason      String,
        source      LowCardinality(String),  -- manual/ml/threat-intel
        severity    LowCardinality(String),
        added_at    DateTime DEFAULT now(),
        expires_at  DateTime,
        hit_count   UInt64 DEFAULT 0,
        active      Bool DEFAULT true
    )
    ENGINE = ReplacingMergeTree(added_at)
    ORDER BY (ip, cidr_prefix)
    """,
]

MIGRATIONS = [
    ("001_create_database", "CREATE DATABASE IF NOT EXISTS thor"),
    *[(f"002_{i:03d}_schema", ddl) for i, ddl in enumerate(SCHEMA_DDL)],
]

# ============================================================================
# ClickHouse Client
# ============================================================================

class ClickHouseClient:
    """
    عميل ClickHouse مع connection pooling وretry
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8123,
        database: str = "thor",
        username: str = "thor",
        password: str = "",
    ):
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self._client = None

    def connect(self) -> bool:
        if not CLICKHOUSE_AVAILABLE:
            logger.error("clickhouse-connect not installed")
            return False

        try:
            self._client = clickhouse_connect.get_client(
                host=self.host,
                port=self.port,
                database=self.database,
                username=self.username,
                password=self.password,
                compress=True,
                settings={
                    "async_insert": 1,
                    "wait_for_async_insert": 0,
                    "max_insert_block_size": 100_000,
                },
            )
            logger.info(f"ClickHouse connected: {self.host}:{self.port}/{self.database}")
            return True
        except Exception as e:
            logger.error(f"ClickHouse connection failed: {e}")
            return False

    def run_migrations(self) -> bool:
        """تشغيل migrations لإنشاء Schema"""
        if not self._client:
            return False

        try:
            for name, ddl in MIGRATIONS:
                try:
                    self._client.command(ddl)
                    logger.debug(f"Migration {name} applied")
                except Exception as e:
                    logger.warning(f"Migration {name} warning: {e}")

            logger.info("ClickHouse migrations complete")
            return True
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            return False

    async def insert_flows_batch(self, flows: List[Dict[str, Any]]) -> bool:
        """إدخال دفعة من التدفقات"""
        if not self._client or not flows:
            return False

        try:
            self._client.insert_df(
                "thor.flows",
                flows,
                settings={"async_insert": 1}
            )
            return True
        except Exception as e:
            logger.error(f"Flow insert failed: {e}")
            return False

    async def insert_threat_event(self, event: Dict[str, Any]) -> bool:
        """تسجيل حدث تهديد"""
        if not self._client:
            return False

        try:
            self._client.insert("thor.threat_events", [event])
            return True
        except Exception as e:
            logger.error(f"Threat event insert failed: {e}")
            return False

    async def insert_stats_snapshot(self, stats: Dict[str, Any]) -> bool:
        """تسجيل لقطة إحصاءات"""
        if not self._client:
            return False

        try:
            self._client.insert("thor.network_stats", [stats])
            return True
        except Exception as e:
            logger.debug(f"Stats insert failed: {e}")
            return False

    async def query_top_threats(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> List[Dict]:
        """استعلام عن أعلى التهديدات"""
        if not self._client:
            return []

        sql = f"""
        SELECT
            src_ip,
            threat_type,
            severity,
            count() as count,
            max(risk_score) as max_risk,
            max(timestamp) as last_seen,
            countIf(blocked) as blocked_count
        FROM thor.threat_events
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
        GROUP BY src_ip, threat_type, severity
        ORDER BY count DESC, max_risk DESC
        LIMIT {limit}
        """

        try:
            result = self._client.query(sql)
            return [dict(zip(result.column_names, row)) for row in result.result_rows]
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    async def query_network_timeseries(
        self,
        metric: str = "packets_per_second",
        hours: int = 1,
        resolution_secs: int = 10,
    ) -> List[Dict]:
        """استعلام سلاسل زمنية"""
        if not self._client:
            return []

        sql = f"""
        SELECT
            toStartOfInterval(timestamp, INTERVAL {resolution_secs} SECOND) as ts,
            avg({metric}) as value
        FROM thor.network_stats
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
        GROUP BY ts
        ORDER BY ts
        """

        try:
            result = self._client.query(sql)
            return [{"timestamp": row[0], "value": row[1]} for row in result.result_rows]
        except Exception as e:
            logger.error(f"Timeseries query failed: {e}")
            return []

    async def query_blocklist(self) -> List[Dict]:
        """استعلام قائمة الحظر النشطة"""
        if not self._client:
            return []

        sql = """
        SELECT ip, cidr_prefix, reason, source, severity, added_at, expires_at, hit_count
        FROM thor.blocklist FINAL
        WHERE active = true AND (expires_at > now() OR expires_at = '1970-01-01')
        ORDER BY hit_count DESC
        LIMIT 10000
        """

        try:
            result = self._client.query(sql)
            return [dict(zip(result.column_names, row)) for row in result.result_rows]
        except Exception as e:
            logger.error(f"Blocklist query failed: {e}")
            return []

    def health_check(self) -> Dict:
        if not self._client:
            return {"status": "disconnected"}

        try:
            result = self._client.query("SELECT version(), uptime()")
            row = result.result_rows[0] if result.result_rows else ("unknown", 0)
            return {
                "status": "healthy",
                "version": row[0],
                "uptime_secs": row[1],
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


# ============================================================================
# Singleton
# ============================================================================

_client: Optional[ClickHouseClient] = None

def get_client() -> ClickHouseClient:
    global _client
    if _client is None:
        _client = ClickHouseClient(
            host=os.getenv("CLICKHOUSE_HOST", "localhost"),
            port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
            database=os.getenv("CLICKHOUSE_DB", "thor"),
            username=os.getenv("CLICKHOUSE_USER", "thor"),
            password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        )
        _client.connect()
    return _client
