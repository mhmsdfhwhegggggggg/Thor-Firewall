"""
Thor Firewall — Threat Intelligence API Routes
Fixed: time_series hourly buckets now fully implemented.
"""
from __future__ import annotations
import json
import time
import math
import logging
from collections import defaultdict
from typing import List, Optional

from fastapi import APIRouter, Request, Query
from pydantic import BaseModel

logger = logging.getLogger("thor.routes.threats")
router = APIRouter()


class ThreatEvent(BaseModel):
    event_id:    str
    timestamp:   float
    src_ip:      str
    dst_ip:      str
    dst_port:    int
    protocol:    str
    threat_type: str
    severity:    str
    risk_score:  float
    confidence:  float
    explanation: Optional[str]
    blocked:     bool
    agent_id:    str


class TimeBucket(BaseModel):
    timestamp:    float    # Unix timestamp (start of hour)
    total:        int
    blocked:      int
    by_type:      dict


class ThreatSummary(BaseModel):
    total_threats: int
    blocked:       int
    allowed:       int
    by_type:       dict
    by_severity:   dict
    top_attackers: List[dict]
    time_series:   List[TimeBucket]   # NOW IMPLEMENTED — hourly buckets


@router.get("/threats", response_model=List[ThreatEvent], summary="List recent threats")
async def list_threats(
    request: Request,
    limit:       int           = Query(50, ge=1, le=1000),
    severity:    Optional[str] = Query(None, description="critical/high/medium/low"),
    threat_type: Optional[str] = Query(None),
    src_ip:      Optional[str] = Query(None),
):
    redis = request.app.state.redis
    raw   = await redis.zrevrange("threats:timeline", 0, limit * 3 - 1, withscores=True)

    threats = []
    for item, _score in raw:
        try:
            threat = json.loads(item)
            event  = ThreatEvent(**threat)
            if severity    and event.severity    != severity:    continue
            if threat_type and event.threat_type != threat_type: continue
            if src_ip      and event.src_ip       != src_ip:     continue
            threats.append(event)
            if len(threats) >= limit:
                break
        except Exception:
            continue
    return threats


@router.get("/threats/summary", response_model=ThreatSummary, summary="Threat summary with time series")
async def threat_summary(
    request: Request,
    window_hours: int = Query(24, ge=1, le=720),
):
    redis  = request.app.state.redis
    since  = time.time() - (window_hours * 3600)
    raw    = await redis.zrangebyscore("threats:timeline", since, "+inf", withscores=True)

    total          = len(raw)
    blocked        = 0
    by_type:  dict = {}
    by_sev:   dict = {}
    attackers: dict = {}

    # Hourly buckets — round each timestamp down to hour boundary
    buckets: dict = defaultdict(lambda: {"total": 0, "blocked": 0, "by_type": {}})

    for item, _ in raw:
        try:
            t = json.loads(item)
            ts        = float(t.get("timestamp", 0))
            ttype     = t.get("threat_type", "unknown")
            sev       = t.get("severity", "low")
            is_blocked = bool(t.get("blocked", False))
            src        = t.get("src_ip", "")

            if is_blocked:
                blocked += 1
            by_type[ttype] = by_type.get(ttype, 0) + 1
            by_sev[sev]    = by_sev.get(sev, 0) + 1
            attackers[src] = attackers.get(src, 0) + 1

            # Hourly bucket key = floor(ts / 3600) * 3600
            hour_ts = math.floor(ts / 3600) * 3600
            buckets[hour_ts]["total"] += 1
            if is_blocked:
                buckets[hour_ts]["blocked"] += 1
            bt = buckets[hour_ts]["by_type"]
            bt[ttype] = bt.get(ttype, 0) + 1
        except Exception:
            continue

    top_attackers = sorted(
        [{"ip": k, "count": v} for k, v in attackers.items()],
        key=lambda x: x["count"], reverse=True,
    )[:10]

    # Build time_series sorted ascending
    time_series = [
        TimeBucket(
            timestamp = ts,
            total     = bkt["total"],
            blocked   = bkt["blocked"],
            by_type   = bkt["by_type"],
        )
        for ts, bkt in sorted(buckets.items())
    ]

    return ThreatSummary(
        total_threats = total,
        blocked       = blocked,
        allowed       = total - blocked,
        by_type       = by_type,
        by_severity   = by_sev,
        top_attackers = top_attackers,
        time_series   = time_series,   # NOW REAL DATA
    )


@router.get("/threats/{event_id}", response_model=ThreatEvent, summary="Get single threat event")
async def get_threat(event_id: str, request: Request):
    redis = request.app.state.redis

    # Try dedicated key first
    raw = await redis.get(f"threat:{event_id}")
    if raw:
        try:
            return ThreatEvent(**json.loads(raw))
        except Exception:
            pass

    # Scan sorted set (for smaller deployments)
    all_raw = await redis.zrevrange("threats:timeline", 0, 999)
    for item in all_raw:
        try:
            t = json.loads(item)
            if t.get("event_id") == event_id:
                return ThreatEvent(**t)
        except Exception:
            continue

    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
