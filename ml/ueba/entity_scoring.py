"""
Thor Firewall — UEBA Entity Risk Scoring
حساب نقاط الخطر التراكمية لكل entity (مستخدم / جهاز / IP)

مستوحى من Splunk UBA + Microsoft Sentinel UEBA
نقاط تتراكم مع الوقت وتتلاشى بمعدل نصف-عمر.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("thor.ueba.scoring")

# ── Risk Score Configuration ──────────────────────────────────────────────────

ANOMALY_SCORE_MAP: dict[str, int] = {
    # Behavioral anomalies (from baseline deviations)
    "high_data_volume":         25,
    "unusual_login_time":       15,
    "geo_anomaly":              40,
    "new_device":               20,
    "peer_group_outlier":       30,
    "failed_auth_spike":        20,
    "privilege_escalation":     60,
    "lateral_movement":         70,
    "data_staging":             50,
    "large_upload":             45,
    # ML-detected threats
    "ml_anomaly_high":          35,
    "ml_anomaly_critical":      65,
    "ml_c2_beaconing":          80,
    "ml_data_exfiltration":     90,
    "ml_brute_force":           30,
    # Threat intel matches
    "ioc_ip_match":             50,
    "ioc_domain_match":         45,
    "ioc_file_hash_match":      70,
    # SOAR actions
    "soar_blocked":             10,
    "soar_quarantined":         20,
}

ALERT_THRESHOLD    = 75   # نقطة إطلاق تنبيه
CRITICAL_THRESHOLD = 150  # نقطة حرجة جداً
DECAY_HALF_LIFE    = 3600.0   # ثانية — نصف العمر لتلاشي النقاط
MAX_SCORE          = 200      # الحد الأقصى

# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class ScoringEvent:
    """حدث مُضاف لنقاط entity"""
    entity_id:    str
    anomaly_type: str
    score_delta:  int
    timestamp:    float = field(default_factory=time.time)
    details:      dict  = field(default_factory=dict)
    mitre_id:     str   = ""


@dataclass
class EntityRiskProfile:
    """ملف الخطر الكامل لـ entity"""
    entity_id:    str
    entity_type:  str   # "user" | "host" | "ip"
    current_score: int  = 0
    peak_score:    int  = 0
    alert_count:   int  = 0
    events:        List[ScoringEvent] = field(default_factory=list)
    last_alert_at: float = 0.0
    first_seen:    float = field(default_factory=time.time)
    last_seen:     float = field(default_factory=time.time)

    @property
    def severity(self) -> str:
        if self.current_score >= CRITICAL_THRESHOLD:
            return "critical"
        if self.current_score >= ALERT_THRESHOLD:
            return "high"
        if self.current_score >= 40:
            return "medium"
        return "low"

    @property
    def is_alert(self) -> bool:
        return self.current_score >= ALERT_THRESHOLD

    def top_anomalies(self, top_n: int = 5) -> List[str]:
        """أكثر أنواع الشذوذ تأثيراً"""
        score_by_type: dict[str, int] = defaultdict(int)
        for e in self.events[-100:]:
            score_by_type[e.anomaly_type] += e.score_delta
        return sorted(score_by_type, key=score_by_type.get, reverse=True)[:top_n]


# ── Entity Risk Scorer ────────────────────────────────────────────────────────

class EntityRiskScorer:
    """
    محرك نقاط الخطر التراكمي.
    - كل حدث يُضيف نقاطاً
    - النقاط تتلاشى تلقائياً بمرور الوقت (exponential decay)
    - عند تجاوز ALERT_THRESHOLD → تنبيه UEBA
    """

    def __init__(self):
        self._profiles: Dict[str, EntityRiskProfile] = {}
        self._history:  Dict[str, List[tuple]]       = defaultdict(list)
        # (timestamp, score_delta, anomaly_type)

    def add_event(self, event: ScoringEvent) -> EntityRiskProfile:
        """
        أضف حدثاً لـ entity واحسب النقاط التراكمية.
        أعد ملف الخطر المحدَّث.
        """
        profile = self._get_or_create(event.entity_id, "user")
        profile.last_seen = event.timestamp
        profile.events.append(event)
        if len(profile.events) > 500:
            profile.events = profile.events[-500:]

        self._history[event.entity_id].append(
            (event.timestamp, event.score_delta, event.anomaly_type)
        )

        score = self._compute_current_score(event.entity_id)
        profile.current_score = score
        profile.peak_score    = max(profile.peak_score, score)

        if profile.is_alert:
            profile.alert_count += 1
            profile.last_alert_at = time.time()
            logger.info("ueba_alert",
                        entity_id=event.entity_id,
                        score=score,
                        severity=profile.severity,
                        anomaly=event.anomaly_type)

        return profile

    def get_profile(self, entity_id: str) -> Optional[EntityRiskProfile]:
        p = self._profiles.get(entity_id)
        if p:
            p.current_score = self._compute_current_score(entity_id)
        return p

    def get_top_risk_entities(
        self, entity_type: Optional[str] = None, top_n: int = 50
    ) -> List[EntityRiskProfile]:
        """أعد قائمة أعلى entities خطراً"""
        profiles = list(self._profiles.values())
        if entity_type:
            profiles = [p for p in profiles if p.entity_type == entity_type]
        # تحديث الـ scores المُتلاشية
        for p in profiles:
            p.current_score = self._compute_current_score(p.entity_id)
        return sorted(profiles, key=lambda p: p.current_score, reverse=True)[:top_n]

    def get_active_alerts(self) -> List[EntityRiskProfile]:
        """أعد الـ entities التي تجاوزت عتبة التنبيه"""
        all_profiles = self.get_top_risk_entities()
        return [p for p in all_profiles if p.is_alert]

    def acknowledge_alert(self, entity_id: str, analyst_id: str) -> bool:
        """سجّل تأكيد المحقق للتنبيه"""
        p = self._profiles.get(entity_id)
        if p:
            logger.info("ueba_ack", entity_id=entity_id, analyst=analyst_id, score=p.current_score)
            return True
        return False

    def reset_entity(self, entity_id: str) -> None:
        """إعادة ضبط نقاط entity بعد التحقيق"""
        if entity_id in self._profiles:
            self._profiles[entity_id].current_score = 0
            self._history[entity_id] = []
            logger.info("ueba_reset", entity_id=entity_id)

    # ── Private ────────────────────────────────────────────────────────────────

    def _get_or_create(self, entity_id: str, entity_type: str) -> EntityRiskProfile:
        if entity_id not in self._profiles:
            self._profiles[entity_id] = EntityRiskProfile(
                entity_id   = entity_id,
                entity_type = entity_type,
            )
        return self._profiles[entity_id]

    def _compute_current_score(self, entity_id: str) -> int:
        """
        Exponential decay score:
        score = Σ delta_i * exp(-λ * (now - t_i))
        λ = ln(2) / half_life
        """
        history = self._history.get(entity_id, [])
        if not history:
            return 0
        now    = time.time()
        decay  = 0.693147 / DECAY_HALF_LIFE   # ln(2) / T½
        score  = sum(
            delta * pow(2.71828, -decay * (now - ts))
            for (ts, delta, _) in history
        )
        # Trim old history (> 7 days)
        cutoff = now - 7 * 86400
        self._history[entity_id] = [
            (ts, d, t) for (ts, d, t) in history if ts > cutoff
        ]
        return min(int(score), MAX_SCORE)


# Singleton
_risk_scorer = EntityRiskScorer()

def get_risk_scorer() -> EntityRiskScorer:
    return _risk_scorer


def add_ueba_event(
    entity_id:    str,
    anomaly_type: str,
    entity_type:  str = "user",
    details:      dict = None,
    mitre_id:     str = "",
) -> EntityRiskProfile:
    """Helper — أضف حدث UEBA مع score تلقائي"""
    delta   = ANOMALY_SCORE_MAP.get(anomaly_type, 10)
    event   = ScoringEvent(
        entity_id    = entity_id,
        anomaly_type = anomaly_type,
        score_delta  = delta,
        details      = details or {},
        mitre_id     = mitre_id,
    )
    scorer  = get_risk_scorer()
    profile = scorer.add_event(event)
    profile.entity_type = entity_type
    return profile
