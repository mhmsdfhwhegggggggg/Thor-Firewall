"""
Thor Firewall — UEBA API Routes
واجهة برمجية لـ User & Entity Behavior Analytics
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/ueba", tags=["UEBA"])

# ── Models ────────────────────────────────────────────────────────────────────

class UEBAEventIn(BaseModel):
    entity_id:    str
    entity_type:  str = "user"
    anomaly_type: str
    details:      Dict[str, Any] = {}
    mitre_id:     str = ""

class EntitySummary(BaseModel):
    entity_id:     str
    entity_type:   str
    current_score: int
    severity:      str
    is_alert:      bool
    peak_score:    int
    alert_count:   int
    top_anomalies: List[str]
    last_seen:     float

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/events", summary="Ingest UEBA anomaly event")
async def ingest_event(ev: UEBAEventIn):
    try:
        from ml.ueba.entity_scoring import add_ueba_event
        profile = add_ueba_event(
            entity_id    = ev.entity_id,
            anomaly_type = ev.anomaly_type,
            entity_type  = ev.entity_type,
            details      = ev.details,
            mitre_id     = ev.mitre_id,
        )
        return {
            "status":         "ingested",
            "entity_id":      profile.entity_id,
            "current_score":  profile.current_score,
            "severity":       profile.severity,
            "alert_triggered": profile.is_alert,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entities", summary="Get top risk entities")
async def get_top_entities(
    entity_type: Optional[str] = Query(None, description="user | host | ip"),
    top_n:       int           = Query(50, ge=1, le=200),
):
    try:
        from ml.ueba.entity_scoring import get_risk_scorer
        scorer   = get_risk_scorer()
        profiles = scorer.get_top_risk_entities(entity_type=entity_type, top_n=top_n)
        return {
            "entities": [
                {
                    "entity_id":     p.entity_id,
                    "entity_type":   p.entity_type,
                    "current_score": p.current_score,
                    "severity":      p.severity,
                    "is_alert":      p.is_alert,
                    "peak_score":    p.peak_score,
                    "alert_count":   p.alert_count,
                    "top_anomalies": p.top_anomalies(3),
                    "last_seen":     p.last_seen,
                }
                for p in profiles
            ],
            "total":       len(profiles),
            "alerts_count": sum(1 for p in profiles if p.is_alert),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entities/{entity_id}", summary="Get entity risk profile")
async def get_entity(entity_id: str):
    try:
        from ml.ueba.entity_scoring import get_risk_scorer
        scorer  = get_risk_scorer()
        profile = scorer.get_profile(entity_id)
        if not profile:
            raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found")
        return {
            "entity_id":     profile.entity_id,
            "entity_type":   profile.entity_type,
            "current_score": profile.current_score,
            "severity":      profile.severity,
            "is_alert":      profile.is_alert,
            "peak_score":    profile.peak_score,
            "alert_count":   profile.alert_count,
            "top_anomalies": profile.top_anomalies(5),
            "last_seen":     profile.last_seen,
            "first_seen":    profile.first_seen,
            "recent_events": [
                {
                    "anomaly_type": e.anomaly_type,
                    "score_delta":  e.score_delta,
                    "timestamp":    e.timestamp,
                    "mitre_id":     e.mitre_id,
                }
                for e in profile.events[-20:]
            ],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts", summary="Get active UEBA alerts")
async def get_alerts():
    try:
        from ml.ueba.entity_scoring import get_risk_scorer
        scorer  = get_risk_scorer()
        alerts  = scorer.get_active_alerts()
        return {
            "alerts": [
                {
                    "entity_id":     a.entity_id,
                    "entity_type":   a.entity_type,
                    "current_score": a.current_score,
                    "severity":      a.severity,
                    "top_anomalies": a.top_anomalies(3),
                    "last_alert_at": a.last_alert_at,
                }
                for a in alerts
            ],
            "total": len(alerts),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/entities/{entity_id}/acknowledge", summary="Acknowledge UEBA alert")
async def acknowledge(entity_id: str, body: dict = {}):
    try:
        from ml.ueba.entity_scoring import get_risk_scorer
        scorer    = get_risk_scorer()
        analyst   = body.get("analyst_id", "unknown")
        ok        = scorer.acknowledge_alert(entity_id, analyst)
        if not ok:
            raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found")
        return {"status": "acknowledged", "entity_id": entity_id, "analyst_id": analyst}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/entities/{entity_id}/reset", summary="Reset entity risk score after investigation")
async def reset_entity(entity_id: str, body: dict = {}):
    try:
        from ml.ueba.entity_scoring import get_risk_scorer
        get_risk_scorer().reset_entity(entity_id)
        return {"status": "reset", "entity_id": entity_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/peer-groups", summary="Get peer group analysis")
async def get_peer_groups(entity_type: str = Query("user")):
    try:
        from ml.ueba.peer_grouping import get_peer_analyzer
        analyzer = get_peer_analyzer()
        groups   = analyzer.get_groups(entity_type)
        outliers = analyzer.get_top_outliers(entity_type, top_n=10)
        return {
            "entity_type": entity_type,
            "groups": [
                {
                    "group_id":    g.group_id,
                    "label":       g.label,
                    "size":        g.size,
                    "radius":      round(g.radius, 4),
                    "members":     g.members[:10],
                }
                for g in groups
            ],
            "top_outliers": [
                {
                    "entity_id":    o.entity_id,
                    "group_label":  o.group_label,
                    "anomaly_score": o.anomaly_score,
                    "peer_rank":    o.peer_rank,
                    "top_deviations": o.top_deviations,
                }
                for o in outliers
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
