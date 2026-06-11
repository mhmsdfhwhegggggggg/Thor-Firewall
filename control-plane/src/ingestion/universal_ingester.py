"""
Universal Ingestion Layer — Splunk HEC-compatible + CEF + LEEF + Syslog + Windows Event
Handles 100k+ events/sec via async batching into ClickHouse
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import aiohttp
import clickhouse_connect
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field, validator

logger = logging.getLogger("thor.ingestion")

# ─────────────────────────── Models ────────────────────────────

class LogFormat(str, Enum):
    SPLUNK_HEC = "splunk_hec"
    CEF        = "cef"
    LEEF       = "leef"
    SYSLOG     = "syslog"
    WINEVENT   = "winevent"
    JSON       = "json"
    THOR_NATIVE= "thor_native"

class NormalizedEvent(BaseModel):
    """Thor canonical event schema — stored in ClickHouse events table"""
    id: str                = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_ms: int      = Field(default_factory=lambda: int(time.time() * 1000))
    source_format: str     = "unknown"
    source_host: str       = ""
    source_ip: str         = ""
    log_level: str         = "INFO"
    category: str          = "generic"       # network, process, auth, file, cloud ...
    action: str            = ""
    outcome: str           = ""              # success, failure, unknown
    actor_user: str        = ""
    actor_process: str     = ""
    actor_pid: int         = 0
    target_host: str       = ""
    target_ip: str         = ""
    target_port: int       = 0
    target_user: str       = ""
    target_resource: str   = ""
    raw: str               = ""
    labels: dict[str, str] = Field(default_factory=dict)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    risk_score: float      = 0.0
    tenant_id: str         = "default"
    event_hash: str        = ""

    class Config:
        extra = "allow"

    def compute_hash(self) -> str:
        content = f"{self.source_host}|{self.timestamp_ms}|{self.raw}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

# ─────────────────────────── Parsers ───────────────────────────

class UniversalIngester:
    """
    Multi-format event ingester with:
    - Auto-detection of log format
    - Async batching (max 5000 events or 500ms)
    - ClickHouse bulk insert via native protocol
    - Redis pub/sub for real-time streaming to websocket clients
    - Deduplication via bloom filter (in-memory)
    """

    BATCH_SIZE    = 5000
    FLUSH_INTERVAL= 0.5   # seconds
    CH_TABLE      = "thor.events"

    def __init__(self, ch_client, redis_client=None):
        self.ch = ch_client
        self.redis = redis_client
        self._batch: list[NormalizedEvent] = []
        self._lock = asyncio.Lock()
        self._seen_hashes: set[str] = set()   # simple dedup window
        self._stats = {"ingested": 0, "dropped": 0, "errors": 0}

    async def start(self):
        """Start background flush loop"""
        asyncio.create_task(self._flush_loop())
        logger.info("Universal Ingester started")

    async def ingest_raw(
        self,
        data: str | bytes | dict,
        fmt: LogFormat = LogFormat.JSON,
        source_ip: str = "",
        tenant_id: str = "default",
    ) -> list[str]:
        """
        Parse raw log data, normalize, enqueue for batch insert.
        Returns list of assigned event IDs.
        """
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")

        # Auto-detect format if not specified
        if fmt == LogFormat.JSON and isinstance(data, str):
            fmt = self._detect_format(data)

        try:
            events = self._parse(data, fmt)
        except Exception as e:
            logger.error("Parse error (fmt=%s): %s", fmt, e)
            self._stats["errors"] += 1
            raise HTTPException(status_code=422, detail=f"Parse error: {e}")

        ids = []
        for ev in events:
            ev.source_ip = source_ip
            ev.tenant_id = tenant_id
            ev.event_hash = ev.compute_hash()

            # Deduplicate
            if ev.event_hash in self._seen_hashes:
                self._stats["dropped"] += 1
                continue
            self._seen_hashes.add(ev.event_hash)
            if len(self._seen_hashes) > 100_000:
                self._seen_hashes.clear()  # rolling window

            async with self._lock:
                self._batch.append(ev)

            ids.append(ev.id)
            self._stats["ingested"] += 1

        # Flush immediately if batch is full
        if len(self._batch) >= self.BATCH_SIZE:
            await self._flush()

        return ids

    async def ingest_splunk_hec(self, request: Request, token: str) -> dict:
        """
        Splunk HEC-compatible endpoint — drop-in replacement for Splunk indexers.
        Accepts: POST /services/collector/event
        """
        body = await request.body()
        # HEC can have multiple JSON objects on separate lines
        events_raw = [
            line for line in body.decode().strip().split("\n") if line.strip()
        ]
        all_ids = []
        for raw in events_raw:
            try:
                obj = json.loads(raw)
                # Splunk HEC format: {"time":..., "host":..., "event": {...}}
                normalized = self._normalize_splunk(obj)
                normalized.source_format = LogFormat.SPLUNK_HEC
                normalized.event_hash = normalized.compute_hash()
                async with self._lock:
                    self._batch.append(normalized)
                all_ids.append(normalized.id)
                self._stats["ingested"] += 1
            except Exception as e:
                logger.warning("HEC parse fail: %s", e)

        return {"text": "Success", "code": 0, "count": len(all_ids)}

    def _detect_format(self, data: str) -> LogFormat:
        stripped = data.strip()
        if stripped.startswith("CEF:"):
            return LogFormat.CEF
        if stripped.startswith("LEEF:"):
            return LogFormat.LEEF
        if stripped.startswith("{") and '"event"' in stripped:
            return LogFormat.SPLUNK_HEC
        if stripped.startswith("<") and stripped[1:4].isdigit():
            return LogFormat.SYSLOG
        if "<Event xmlns=" in stripped or "<EventData>" in stripped:
            return LogFormat.WINEVENT
        try:
            json.loads(stripped)
            return LogFormat.JSON
        except Exception:
            return LogFormat.SYSLOG

    def _parse(self, data: str | dict, fmt: LogFormat) -> list[NormalizedEvent]:
        from .parsers.cef_parser    import parse_cef
        from .parsers.syslog_parser import parse_syslog
        from .parsers.winevent_parser import parse_winevent

        if fmt == LogFormat.CEF:
            return [parse_cef(data)]
        if fmt == LogFormat.LEEF:
            return [self._parse_leef(data)]
        if fmt == LogFormat.SYSLOG:
            return [parse_syslog(data)]
        if fmt == LogFormat.WINEVENT:
            return [parse_winevent(data)]
        if fmt == LogFormat.SPLUNK_HEC:
            obj = json.loads(data) if isinstance(data, str) else data
            return [self._normalize_splunk(obj)]
        if fmt == LogFormat.JSON:
            obj = json.loads(data) if isinstance(data, str) else data
            return [self._normalize_json(obj)]
        return [NormalizedEvent(raw=str(data))]

    def _normalize_splunk(self, obj: dict) -> NormalizedEvent:
        inner = obj.get("event", obj)
        if isinstance(inner, str):
            inner = {"message": inner}
        ts_ms = int(float(obj.get("time", time.time())) * 1000)
        return NormalizedEvent(
            timestamp_ms   = ts_ms,
            source_format  = "splunk_hec",
            source_host    = obj.get("host", ""),
            category       = obj.get("sourcetype", "generic"),
            action         = inner.get("action", inner.get("EventCode", "")),
            actor_user     = inner.get("user", inner.get("Account_Name", "")),
            target_host    = inner.get("dest", inner.get("ComputerName", "")),
            raw            = json.dumps(obj),
            labels         = {k: str(v) for k, v in inner.items() if isinstance(v, str)},
        )

    def _normalize_json(self, obj: dict) -> NormalizedEvent:
        ts = obj.get("timestamp", obj.get("time", obj.get("@timestamp", time.time())))
        if isinstance(ts, str):
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                ts = time.time()
        return NormalizedEvent(
            timestamp_ms   = int(float(ts) * 1000) if float(ts) < 1e12 else int(ts),
            source_format  = "json",
            source_host    = obj.get("host", obj.get("hostname", "")),
            category       = obj.get("category", obj.get("type", "generic")),
            action         = obj.get("action", obj.get("event_type", "")),
            outcome        = obj.get("outcome", obj.get("result", "")),
            actor_user     = obj.get("user", obj.get("username", "")),
            actor_process  = obj.get("process", obj.get("process_name", "")),
            target_ip      = obj.get("dest_ip", obj.get("dst", "")),
            target_port    = int(obj.get("dest_port", obj.get("dpt", 0))),
            raw            = json.dumps(obj),
        )

    def _parse_leef(self, data: str) -> NormalizedEvent:
        """LEEF:2.0|Vendor|Product|Version|EventID|attr=val\tattr=val"""
        ev = NormalizedEvent(raw=data, source_format="leef")
        if not data.startswith("LEEF:"):
            return ev
        try:
            header, body = data.split("|", 5)[:-1], data.split("|", 5)[-1]
            if len(header) >= 5:
                ev.labels["vendor"]  = header[1] if len(header) > 1 else ""
                ev.labels["product"] = header[2] if len(header) > 2 else ""
                ev.action            = header[4] if len(header) > 4 else ""
            # Parse tab-separated key=val pairs
            for pair in body.split("\t"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    ev.labels[k.strip()] = v.strip()
            ev.source_host = ev.labels.get("src", "")
            ev.actor_user  = ev.labels.get("usrName", "")
        except Exception as e:
            logger.debug("LEEF parse warning: %s", e)
        return ev

    async def _flush_loop(self):
        while True:
            await asyncio.sleep(self.FLUSH_INTERVAL)
            if self._batch:
                await self._flush()

    async def _flush(self):
        async with self._lock:
            if not self._batch:
                return
            batch = self._batch[:]
            self._batch.clear()

        try:
            await self._bulk_insert(batch)

            if self.redis:
                # Publish high-severity events to real-time stream
                high_risk = [e for e in batch if e.risk_score >= 0.7]
                if high_risk:
                    await self.redis.publish(
                        "thor:events:high_risk",
                        json.dumps([e.dict() for e in high_risk])
                    )
        except Exception as e:
            logger.error("Flush error: %s", e)
            self._stats["errors"] += len(batch)

    async def _bulk_insert(self, events: list[NormalizedEvent]):
        """ClickHouse async bulk insert"""
        rows = []
        for e in events:
            rows.append([
                e.id, e.timestamp_ms, e.source_format, e.source_host,
                e.source_ip, e.log_level, e.category, e.action, e.outcome,
                e.actor_user, e.actor_process, e.actor_pid,
                e.target_host, e.target_ip, e.target_port, e.target_user,
                e.target_resource, e.raw, json.dumps(e.labels),
                e.mitre_tactics, e.mitre_techniques,
                e.risk_score, e.tenant_id, e.event_hash,
            ])

        cols = [
            "id","timestamp_ms","source_format","source_host","source_ip",
            "log_level","category","action","outcome","actor_user",
            "actor_process","actor_pid","target_host","target_ip","target_port",
            "target_user","target_resource","raw","labels",
            "mitre_tactics","mitre_techniques","risk_score","tenant_id","event_hash",
        ]

        # clickhouse-connect async insert
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self.ch.insert(self.CH_TABLE, rows, column_names=cols)
        )
        logger.debug("Flushed %d events to ClickHouse", len(rows))

    def get_stats(self) -> dict:
        return {**self._stats, "batch_pending": len(self._batch)}
