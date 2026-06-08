"""Thor Firewall — Threat Intelligence API Routes"""
import time
from typing import List, Optional
from fastapi import APIRouter, Request, Query
from pydantic import BaseModel

router = APIRouter()


class ThreatEvent(BaseModel):
    event_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    threat_type: str
    severity: str
    risk_score: float
    confidence: float
    explanation: Optional[str]
    blocked: bool
    agent_id: str


class ThreatSummary(BaseModel):
    total_threats: int
    blocked: int
    allowed: int
    by_type: dict
    by_severity: dict
    top_attackers: List[dict]
    time_series: List[dict]


@router.get("/threats", response_model=List[ThreatEvent], summary="List recent threats")
async def list_threats(
    request: Request,
    limit: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = Query(None, description="critical/high/medium/low"),
    threat_type: Optional[str] = Query(None),
):
    """List recent threat events detected by Thor's AI engine."""
    redis = request.app.state.redis

    # Get from Redis sorted set (by timestamp)
    raw = await redis.zrevrange("threats:timeline", 0, limit - 1, withscores=True)

    threats = []
    for item, score in raw:
        import json
        try:
            threat = json.loads(item)
            event = ThreatEvent(**threat)
            if severity and event.severity != severity:
                continue
            if threat_type and event.threat_type != threat_type:
                continue
            threats.append(event)
        except Exception:
            continue

    return threats


@router.get("/threats/summary", response_model=ThreatSummary, summary="Threat summary")
async def threat_summary(
    request: Request,
    window_hours: int = Query(24, ge=1, le=720),
):
    """Get threat summary for the specified time window."""
    redis = request.app.state.redis

    since = time.time() - (window_hours * 3600)
    raw = await redis.zrangebyscore("threats:timeline", since, "+inf", withscores=True)

    total = len(raw)
    blocked = 0
    by_type: dict = {}
    by_severity: dict = {}
    attacker_counts: dict = {}

    import json
    for item, _ in raw:
        try:
            threat = json.loads(item)
            if threat.get("blocked"):
                blocked += 1
            t = threat.get("threat_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
            s = threat.get("severity", "low")
            by_severity[s] = by_severity.get(s, 0) + 1
            src = threat.get("src_ip", "")
            attacker_counts[src] = attacker_counts.get(src, 0) + 1
        except Exception:
            continue

    top_attackers = sorted(
        [{"ip": k, "count": v} for k, v in attacker_counts.items()],
        key=lambda x: x["count"], reverse=True
    )[:10]

    return ThreatSummary(
        total_threats=total,
        blocked=blocked,
        allowed=total - blocked,
        by_type=by_type,
        by_severity=by_severity,
        top_attackers=top_attackers,
        time_series=[],  # TODO: implement hourly buckets
    )
