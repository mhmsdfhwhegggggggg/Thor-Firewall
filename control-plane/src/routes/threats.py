"""
Thor Firewall — Threats API Routes
"""
import time
import json
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

router = APIRouter()

# ============================================================================
# Models
# ============================================================================

class FlowKeyModel(BaseModel):
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: str

class ThreatEventResponse(BaseModel):
    event_id:       str
    timestamp:      float
    flow:           FlowKeyModel
    threat_type:    str
    severity:       str
    risk_score:     float
    confidence:     float
    explanation:    Optional[str]
    blocked:        bool
    agent_id:       str
    mitre_technique: Optional[str]

class CreateAlertRequest(BaseModel):
    flow_id:     str
    threat_type: str
    severity:    str = Field(..., pattern="^(low|medium|high|critical)$")
    risk_score:  float = Field(..., ge=0.0, le=1.0)
    explanation: Optional[str] = None
    blocked:     bool = False

# ============================================================================
# Demo threat data
# ============================================================================

DEMO_THREATS = [
    {
        "event_id":       "threat-001",
        "timestamp":      time.time() - 5,
        "flow":           {"src_ip": "103.45.67.89", "dst_ip": "10.0.0.5",  "src_port": 54321, "dst_port": 22,  "protocol": "tcp"},
        "threat_type":    "ssh-brute-force",
        "severity":       "critical",
        "risk_score":     0.97,
        "confidence":     0.95,
        "explanation":    "SSH brute force: 2847 attempts in 30s. Pattern matches known botnet fingerprint.",
        "blocked":        True,
        "agent_id":       "marl-tcp-agent",
        "mitre_technique": "T1110.001",
    },
    {
        "event_id":       "threat-002",
        "timestamp":      time.time() - 15,
        "flow":           {"src_ip": "185.220.101.23", "dst_ip": "10.0.0.1", "src_port": 45000, "dst_port": 80,  "protocol": "tcp"},
        "threat_type":    "syn-flood",
        "severity":       "high",
        "risk_score":     0.89,
        "confidence":     0.92,
        "explanation":    "SYN flood: 184,293 packets/s from TOR exit node. Applied SYN cookie mitigation.",
        "blocked":        True,
        "agent_id":       "marl-tcp-agent",
        "mitre_technique": "T1498.001",
    },
    {
        "event_id":       "threat-003",
        "timestamp":      time.time() - 45,
        "flow":           {"src_ip": "192.168.1.45", "dst_ip": "8.8.8.8",   "src_port": 54000, "dst_port": 53,  "protocol": "udp"},
        "threat_type":    "dns-tunnel",
        "severity":       "medium",
        "risk_score":     0.72,
        "confidence":     0.78,
        "explanation":    "DNS tunneling detected: entropy=7.91, unusually long subdomain labels, CICIDS match.",
        "blocked":        False,
        "agent_id":       "marl-udp-agent",
        "mitre_technique": "T1071.004",
    },
    {
        "event_id":       "threat-004",
        "timestamp":      time.time() - 120,
        "flow":           {"src_ip": "10.0.1.88", "dst_ip": "203.0.113.5",  "src_port": 49200, "dst_port": 4444,"protocol": "tcp"},
        "threat_type":    "c2-beacon",
        "severity":       "critical",
        "risk_score":     0.94,
        "confidence":     0.91,
        "explanation":    "C2 beacon detected: periodic interval 60.02s ±0.1s, encrypted payload (entropy=7.98).",
        "blocked":        True,
        "agent_id":       "marl-tcp-agent",
        "mitre_technique": "T1071.001",
    },
]

# ============================================================================
# Routes
# ============================================================================

@router.get("/threats", response_model=List[ThreatEventResponse],
            summary="List recent threats")
async def list_threats(
    request:    Request,
    limit:      int   = Query(50,  ge=1, le=1000),
    severity:   Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
    blocked:    Optional[bool] = Query(None),
    since:      Optional[float] = Query(None, description="Unix timestamp"),
    threat_type: Optional[str] = Query(None),
):
    """
    Returns recent threat events with optional filtering.
    Events come from Redis (published by the Rust agent) or demo data.
    """
    redis = request.app.state.redis

    # Try Redis first
    raw_events = await redis.lrange("threats:recent", 0, limit * 2)

    if raw_events:
        threats = []
        for raw in raw_events:
            try:
                evt = json.loads(raw)
                # Apply filters
                if severity   and evt.get("severity")    != severity:    continue
                if blocked is not None and evt.get("blocked") != blocked: continue
                if since      and evt.get("timestamp", 0) < since:       continue
                if threat_type and evt.get("threat_type") != threat_type: continue
                threats.append(ThreatEventResponse(**evt))
                if len(threats) >= limit: break
            except Exception:
                continue
        return threats

    # Return demo data
    threats = [t for t in DEMO_THREATS]
    if severity:
        threats = [t for t in threats if t["severity"] == severity]
    if blocked is not None:
        threats = [t for t in threats if t["blocked"] == blocked]
    if threat_type:
        threats = [t for t in threats if t["threat_type"] == threat_type]

    return [ThreatEventResponse(**t) for t in threats[:limit]]


@router.get("/threats/{event_id}", response_model=ThreatEventResponse,
            summary="Get threat details")
async def get_threat(event_id: str, request: Request):
    """Get detailed information about a specific threat event."""
    redis = request.app.state.redis
    raw = await redis.get(f"threat:{event_id}")

    if raw:
        return ThreatEventResponse(**json.loads(raw))

    # Check demo
    for t in DEMO_THREATS:
        if t["event_id"] == event_id:
            return ThreatEventResponse(**t)

    raise HTTPException(status_code=404, detail=f"Threat event {event_id} not found")


@router.post("/threats/alert", summary="Manually create a threat alert")
async def create_alert(request_body: CreateAlertRequest, request: Request):
    """
    Manually create a threat alert (from external threat intelligence, etc.)
    """
    redis = request.app.state.redis

    alert = {
        "event_id":       f"manual-{int(time.time())}",
        "timestamp":      time.time(),
        "flow":           {"src_ip": "unknown", "dst_ip": "unknown",
                           "src_port": 0, "dst_port": 0, "protocol": "unknown"},
        "threat_type":    request_body.threat_type,
        "severity":       request_body.severity,
        "risk_score":     request_body.risk_score,
        "confidence":     1.0,
        "explanation":    request_body.explanation,
        "blocked":        request_body.blocked,
        "agent_id":       "manual",
        "mitre_technique": None,
    }

    # Store in Redis
    await redis.lpush("threats:recent", json.dumps(alert))
    await redis.expire("threats:recent", 86_400)
    await redis.set(f"threat:{alert['event_id']}", json.dumps(alert), ex=86_400)

    # Broadcast via event bus
    await redis.publish("thor:alerts", json.dumps({
        "type":    "threat_detected",
        "channel": "thor:alerts",
        "data":    alert,
    }))

    return {"status": "created", "event_id": alert["event_id"]}


@router.get("/threats/stats/summary", summary="Threat statistics summary")
async def get_threat_summary(request: Request, window_s: int = Query(3600)):
    """Returns threat count summary grouped by severity and type."""
    redis = request.app.state.redis

    counts = {
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_type":     {},
        "blocked_pct": 0.0,
        "total":       0,
        "window_s":    window_s,
    }

    raw_events = await redis.lrange("threats:recent", 0, 9999)
    since = time.time() - window_s

    blocked = 0
    for raw in raw_events:
        try:
            evt = json.loads(raw)
            if evt.get("timestamp", 0) < since: continue
            counts["total"] += 1
            sev = evt.get("severity", "low")
            counts["by_severity"][sev] = counts["by_severity"].get(sev, 0) + 1
            tt = evt.get("threat_type", "unknown")
            counts["by_type"][tt] = counts["by_type"].get(tt, 0) + 1
            if evt.get("blocked"): blocked += 1
        except Exception: continue

    if counts["total"] == 0:
        # Demo stats
        counts["by_severity"] = {"critical": 2, "high": 1, "medium": 1, "low": 0}
        counts["by_type"]     = {"ssh-brute-force": 1, "syn-flood": 1, "dns-tunnel": 1, "c2-beacon": 1}
        counts["total"]       = 4
        blocked               = 3

    if counts["total"] > 0:
        counts["blocked_pct"] = round(blocked / counts["total"], 4)

    return counts
