"""
Thor XDR — Risk-Based Alerting Engine
مستوحى من Splunk Risk-Based Alerting (RBA)

بدلاً من إطلاق 500 تنبيه منفصل، نجمعها في risk score واحد.
يقلل Alert Fatigue بنسبة 95%.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import structlog

log = structlog.get_logger("thor.xdr.risk")

# ── Risk Scores per event type ─────────────────────────────────────────────

RISK_SCORE_MAP: dict[str, int] = {
    # Network
    "port_scan":               15,
    "syn_flood":               30,
    "ddos":                    40,
    "brute_force_single":       5,   # per event
    "brute_force_sustained":   25,
    "new_external_connection": 10,
    "large_data_transfer":     25,
    "dns_tunneling":           50,
    "c2_beaconing":            70,
    "data_exfiltration":       90,
    # Lateral movement
    "lateral_movement":        60,
    "admin_share_access":      35,
    "rdp_connection":          20,
    # Host
    "privilege_escalation":    50,
    "credential_dump":         80,
    "process_injection":       70,
    "new_scheduled_task":      30,
    "registry_modification":   25,
    "log_deletion":            65,
    # Identity
    "failed_auth":              5,   # per event, caps at 50
    "successful_auth_unusual": 30,
    "new_user_created":        20,
    "admin_account_used":      15,
    # Compliance / UEBA
    "unusual_hour_access":     10,
    "geo_anomaly":             35,
    "data_volume_spike":       25,
    "peer_group_anomaly":      20,
}

ALERT_THRESHOLD    = 75    # إطلاق تنبيه عند تجاوز 75 نقطة
CRITICAL_THRESHOLD = 150   # حرج جداً
MAX_RISK_PER_EVENT_TYPE = 50   # حد أقصى من نفس النوع لمنع inflation
DECAY_HALF_LIFE_SECONDS = 3600  # نصف عمر التراكم


@dataclass
class RiskEvent:
    entity_id:   str          # IP أو username أو hostname
    event_type:  str
    score_delta: int
    timestamp:   float = field(default_factory=time.time)
    details:     dict  = field(default_factory=dict)


@dataclass
class RiskAlert:
    entity_id:    str
    risk_score:   int
    events:       List[RiskEvent]
    severity:     str           # low / medium / high / critical
    top_events:   List[str]
    mitre_ids:    List[str]
    timestamp:    float = field(default_factory=time.time)
    acknowledged: bool = False


class RiskEngine:
    """
    محرك تجميع نقاط الخطر لكل entity.
    كل entity تراكم نقاط بمرور الوقت، تتلاشى تدريجياً.
    """

    def __init__(self):
        # entity_id → [(timestamp, score_delta, event_type)]
        self._risk_history: dict[str, list] = defaultdict(list)
        self._pending_alerts: list[RiskAlert] = []
        self._lock = asyncio.Lock()

    async def add_event(self, event: RiskEvent) -> Optional[RiskAlert]:
        """
        أضف حدثاً لـ entity وأعد تنبيهاً إذا تجاوز العتبة.
        """
        async with self._lock:
            self._risk_history[event.entity_id].append((
                event.timestamp,
                min(event.score_delta, MAX_RISK_PER_EVENT_TYPE),
                event.event_type,
                event.details,
            ))
            # احذف الأحداث القديمة جداً (> 24 ساعة)
            cutoff = time.time() - 86400
            self._risk_history[event.entity_id] = [
                e for e in self._risk_history[event.entity_id] if e[0] > cutoff
            ]

            current_score = self._calculate_score(event.entity_id)
            log.debug("risk_update",
                      entity=event.entity_id,
                      event_type=event.event_type,
                      delta=event.score_delta,
                      total=current_score)

            if current_score >= ALERT_THRESHOLD:
                alert = self._build_alert(event.entity_id, current_score)
                self._pending_alerts.append(alert)
                log.warning("risk_alert_triggered",
                             entity=event.entity_id,
                             score=current_score,
                             severity=alert.severity)
                return alert
            return None

    def _calculate_score(self, entity_id: str) -> int:
        """
        احسب النقاط مع تطبيق exponential decay.
        الأحداث القديمة تُقلَّل تأثيرها بمرور الوقت.
        """
        now = time.time()
        total = 0
        event_type_totals: dict[str, int] = defaultdict(int)

        for ts, delta, etype, _ in self._risk_history[entity_id]:
            age_hours = (now - ts) / 3600
            decay = 0.5 ** (age_hours * 3600 / DECAY_HALF_LIFE_SECONDS)
            # تطبيق حد أقصى لكل نوع حدث
            if event_type_totals[etype] < MAX_RISK_PER_EVENT_TYPE:
                contribution = int(delta * decay)
                event_type_totals[etype] += contribution
                total += contribution

        return total

    def _build_alert(self, entity_id: str, score: int) -> RiskAlert:
        from .mitre_mapper import map_event_to_mitre

        events_data = self._risk_history[entity_id]
        severity = (
            "critical" if score >= CRITICAL_THRESHOLD
            else "high" if score >= 100
            else "medium" if score >= ALERT_THRESHOLD
            else "low"
        )
        # أبرز أنواع الأحداث
        type_counts: dict[str, int] = defaultdict(int)
        for _, _, etype, _ in events_data:
            type_counts[etype] += 1
        top_events = sorted(type_counts, key=lambda k: type_counts[k], reverse=True)[:5]

        # MITRE mapping
        mitre_ids = []
        for etype in top_events:
            tech = map_event_to_mitre(etype)
            if tech and tech.id not in mitre_ids:
                mitre_ids.append(tech.id)

        return RiskAlert(
            entity_id  = entity_id,
            risk_score = score,
            events     = [
                RiskEvent(
                    entity_id   = entity_id,
                    event_type  = e[2],
                    score_delta = e[1],
                    timestamp   = e[0],
                    details     = e[3],
                )
                for e in events_data[-20:]   # آخر 20 حدث
            ],
            severity   = severity,
            top_events = top_events,
            mitre_ids  = mitre_ids,
        )

    def get_entity_score(self, entity_id: str) -> int:
        return self._calculate_score(entity_id)

    def get_top_risk_entities(self, limit: int = 20) -> list[tuple[str, int]]:
        scored = [
            (eid, self._calculate_score(eid))
            for eid in self._risk_history
        ]
        return sorted(scored, key=lambda x: x[1], reverse=True)[:limit]

    async def drain_alerts(self) -> list[RiskAlert]:
        async with self._lock:
            alerts = self._pending_alerts.copy()
            self._pending_alerts.clear()
            return alerts


# Singleton
_engine = RiskEngine()

def get_risk_engine() -> RiskEngine:
    return _engine
