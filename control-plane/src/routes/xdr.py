"""
Thor XDR — API Routes
نقاط نهاية REST لـ XDR Correlation Engine
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..xdr.causality_builder import SecurityEvent, get_causality_builder
from ..xdr.event_stitcher    import RawEvent, get_risk_engine
from ..xdr.risk_engine       import RiskEvent, get_risk_engine

router = APIRouter(prefix="/api/v1/xdr", tags=["XDR"])


# ── Request Models ─────────────────────────────────────────────────────────────

class SecurityEventIn(BaseModel):
    event_id:    str
    timestamp:   Optional[float] = None
    src_ip:      str
    dst_ip:      Optional[str] = None
    threat_type: str
    severity:    str = "medium"
    risk_score:  float = 0.5
    details:     Dict[str, Any] = {}


class RiskEventIn(BaseModel):
    entity_id:   str
    event_type:  str
    score_delta: int
    details:     Dict[str, Any] = {}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/events", summary="Ingest security event into XDR engine")
async def ingest_event(ev: SecurityEventIn):
    """
    استوعب حدثاً أمنياً في XDR engine.
    سيتم ربطه بالأحداث المجاورة تلقائياً وبناء causality chain إذا تشكّلت.
    """
    sec_event = SecurityEvent(
        event_id    = ev.event_id,
        timestamp   = ev.timestamp or time.time(),
        src_ip      = ev.src_ip,
        dst_ip      = ev.dst_ip,
        threat_type = ev.threat_type,
        severity    = ev.severity,
        risk_score  = ev.risk_score,
        details     = ev.details,
    )
    builder = get_causality_builder()
    chain   = builder.add_event(sec_event)

    return {
        "status":        "ingested",
        "event_id":      ev.event_id,
        "chain_formed":  chain is not None,
        "chain_id":      chain.chain_id if chain else None,
        "chain_risk":    chain.aggregate_risk if chain else None,
        "chain_severity":chain.severity if chain else None,
    }


@router.get("/chains", summary="Get active causality chains")
async def get_chains(limit: int = Query(50, ge=1, le=200)):
    """أعد قائمة الـ causality chains النشطة"""
    builder = get_causality_builder()
    chains  = builder.get_active_chains()[-limit:]

    return {
        "chains": [
            {
                "chain_id":           c.chain_id,
                "summary":            c.summary,
                "severity":           c.severity,
                "aggregate_risk":     c.aggregate_risk,
                "event_count":        c.event_count,
                "duration_minutes":   round(c.duration_minutes, 1),
                "kill_chain_progress": c.kill_chain_progress,
                "affected_ips":       c.affected_ips,
                "mitre_tactics":      [
                    {"id": m.id, "name": m.name, "tactic": m.tactic}
                    for m in c.mitre_tactics
                ],
                "start_time": c.start_time,
                "end_time":   c.end_time,
            }
            for c in reversed(chains)
        ],
        "total": len(chains),
    }


@router.post("/risk/event", summary="Add risk event for RBA scoring")
async def add_risk_event(ev: RiskEventIn):
    """
    أضف حدث خطر لكيان معين.
    إذا تجاوز الـ risk score العتبة (75) → يُطلَق تنبيه تلقائياً.
    """
    engine = get_risk_engine()
    risk_ev = RiskEvent(
        entity_id   = ev.entity_id,
        event_type  = ev.event_type,
        score_delta = ev.score_delta,
        details     = ev.details,
    )
    alert = await engine.add_event(risk_ev)

    return {
        "status":          "processed",
        "entity_id":       ev.entity_id,
        "current_score":   engine.get_entity_score(ev.entity_id),
        "alert_triggered": alert is not None,
        "alert_severity":  alert.severity if alert else None,
    }


@router.get("/risk/top", summary="Get top risk entities")
async def get_top_risk(limit: int = Query(20, ge=1, le=100)):
    """أعد قائمة الكيانات الأعلى خطورة"""
    engine = get_risk_engine()
    top    = engine.get_top_risk_entities(limit)
    return {
        "entities": [{"entity_id": eid, "risk_score": score} for eid, score in top],
        "total": len(top),
    }


@router.get("/alerts/drain", summary="Drain pending risk alerts")
async def drain_alerts():
    """احصل على جميع التنبيهات المعلقة وأفرغ القائمة"""
    engine = get_risk_engine()
    alerts = await engine.drain_alerts()
    return {
        "alerts": [
            {
                "entity_id":  a.entity_id,
                "risk_score": a.risk_score,
                "severity":   a.severity,
                "top_events": a.top_events,
                "mitre_ids":  a.mitre_ids,
                "timestamp":  a.timestamp,
            }
            for a in alerts
        ],
        "count": len(alerts),
    }
