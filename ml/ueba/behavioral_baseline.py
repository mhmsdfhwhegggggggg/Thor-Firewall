"""
Thor Firewall — UEBA Behavioral Baseline Engine
محرك تحليل سلوك المستخدمين والكيانات

يبني نمطاً سلوكياً طبيعياً لكل entity ثم يكشف الانحرافات.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
import numpy as np

logger = logging.getLogger("thor.ueba.baseline")

@dataclass
class EntityBaseline:
    entity_id: str
    entity_type: str  # "user" | "device" | "ip"
    # Temporal patterns
    active_hours: List[float] = field(default_factory=lambda: [0.0]*24)
    active_days: List[float] = field(default_factory=lambda: [0.0]*7)
    # Volume patterns
    avg_bytes_per_hour: float = 0.0
    std_bytes_per_hour: float = 0.0
    avg_connections_per_hour: float = 0.0
    std_connections_per_hour: float = 0.0
    # Peer patterns
    peer_group: Optional[str] = None
    # Geo patterns
    known_countries: List[str] = field(default_factory=list)
    known_asns: List[int] = field(default_factory=list)
    # Service patterns
    known_ports: List[int] = field(default_factory=list)
    known_protocols: List[str] = field(default_factory=list)
    # Metadata
    baseline_period_days: int = 30
    last_updated: float = field(default_factory=time.time)
    sample_count: int = 0

@dataclass
class BehaviorEvent:
    entity_id: str
    entity_type: str
    timestamp: float
    bytes_transferred: int
    connections: int
    dst_ports: List[int]
    protocols: List[str]
    countries: List[str]
    hour_of_day: int = field(init=False)
    day_of_week: int = field(init=False)

    def __post_init__(self):
        import datetime
        dt = datetime.datetime.utcfromtimestamp(self.timestamp)
        self.hour_of_day = dt.hour
        self.day_of_week = dt.weekday()

@dataclass
class AnomalyAlert:
    entity_id: str
    entity_type: str
    timestamp: float
    anomaly_type: str
    severity: str          # "low" | "medium" | "high" | "critical"
    risk_delta: float      # sigma deviation
    description: str
    evidence: Dict
    mitre_technique: Optional[str] = None


class WelfordOnlineStats:
    """حساب المتوسط والانحراف المعياري بشكل تدريجي (بدون تخزين كل البيانات)"""
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0

    def update(self, x: float):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.M2 / max(self.n - 1, 1)

    @property
    def std(self) -> float:
        return np.sqrt(self.variance)

    def zscore(self, x: float) -> float:
        if self.std < 1e-10:
            return 0.0
        return (x - self.mean) / self.std


class UEBABaselineEngine:
    """
    محرك بناء وتحديث baselines سلوكية

    يستخدم نافذة منزلقة (sliding window) مدتها 30 يوماً
    ويدعم تحديث تدريجي بدون إعادة حساب كامل.
    """

    def __init__(
        self,
        redis_client=None,
        baseline_window_days: int = 30,
        min_samples: int = 100,
    ):
        self.redis = redis_client
        self.baseline_window = baseline_window_days * 86400
        self.min_samples = min_samples

        # In-memory baselines (للسرعة)
        self._baselines: Dict[str, EntityBaseline] = {}
        # Online stats للتحديث التدريجي
        self._stats: Dict[str, Dict[str, WelfordOnlineStats]] = defaultdict(
            lambda: defaultdict(WelfordOnlineStats)
        )
        # Event buffer (آخر 1000 حدث لكل entity)
        self._event_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

    def update_baseline(self, event: BehaviorEvent) -> Optional[AnomalyAlert]:
        """
        تحديث الـ baseline بحدث جديد وإعادة alert إذا كان شاذاً.
        يُستدعى لكل حدث في الزمن الحقيقي.
        """
        eid = event.entity_id
        baseline = self._baselines.setdefault(eid, EntityBaseline(
            entity_id=eid,
            entity_type=event.entity_type,
        ))

        # تحديث إحصاءات الحجم
        self._stats[eid]["bytes"].update(event.bytes_transferred)
        self._stats[eid]["connections"].update(event.connections)

        # تحديث أنماط الوقت
        baseline.active_hours[event.hour_of_day] += 1
        baseline.active_days[event.day_of_week] += 1

        # تحديث معرفة المنافذ والبروتوكولات
        for port in event.dst_ports:
            if port not in baseline.known_ports:
                baseline.known_ports.append(port)
        for proto in event.protocols:
            if proto not in baseline.known_protocols:
                baseline.known_protocols.append(proto)
        for country in event.countries:
            if country not in baseline.known_countries:
                baseline.known_countries.append(country)

        baseline.sample_count += 1
        baseline.last_updated = time.time()

        # لا نفحص الشذوذ حتى نجمع عينات كافية
        if baseline.sample_count < self.min_samples:
            self._event_buffer[eid].append(event)
            return None

        # فحص الشذوذ
        alert = self._detect_anomaly(event, baseline)
        self._event_buffer[eid].append(event)
        return alert

    def _detect_anomaly(self, event: BehaviorEvent, baseline: EntityBaseline) -> Optional[AnomalyAlert]:
        """كشف الانحرافات عن السلوك الطبيعي"""
        eid = event.entity_id
        alerts = []

        # ── 1. حجم البيانات غير طبيعي ──
        bytes_z = self._stats[eid]["bytes"].zscore(event.bytes_transferred)
        if abs(bytes_z) > 3.0:
            severity = "critical" if abs(bytes_z) > 5.0 else "high" if abs(bytes_z) > 4.0 else "medium"
            alerts.append(AnomalyAlert(
                entity_id=eid,
                entity_type=event.entity_type,
                timestamp=event.timestamp,
                anomaly_type="volume_spike",
                severity=severity,
                risk_delta=bytes_z,
                description=f"Data transfer volume {event.bytes_transferred/1e6:.1f}MB is {bytes_z:.1f}σ above baseline",
                evidence={
                    "current_bytes": event.bytes_transferred,
                    "baseline_mean": self._stats[eid]["bytes"].mean,
                    "baseline_std": self._stats[eid]["bytes"].std,
                    "zscore": bytes_z,
                },
                mitre_technique="T1030",  # Data Transfer Size Limits
            ))

        # ── 2. ساعة غير معتادة ──
        hour_activity = baseline.active_hours[event.hour_of_day]
        total_activity = sum(baseline.active_hours)
        hour_ratio = hour_activity / max(total_activity, 1)
        if hour_ratio < 0.01 and total_activity > 200:
            alerts.append(AnomalyAlert(
                entity_id=eid,
                entity_type=event.entity_type,
                timestamp=event.timestamp,
                anomaly_type="unusual_time",
                severity="medium",
                risk_delta=3.0,
                description=f"Activity at hour {event.hour_of_day:02d}:00 UTC — only {hour_ratio*100:.1f}% of historical activity",
                evidence={"hour": event.hour_of_day, "historical_ratio": hour_ratio},
                mitre_technique="T1078",  # Valid Accounts
            ))

        # ── 3. دولة جديدة ──
        new_countries = [c for c in event.countries if c and c not in baseline.known_countries]
        if new_countries:
            alerts.append(AnomalyAlert(
                entity_id=eid,
                entity_type=event.entity_type,
                timestamp=event.timestamp,
                anomaly_type="new_geography",
                severity="high",
                risk_delta=4.0,
                description=f"New geographic location: {', '.join(new_countries)}",
                evidence={"new_countries": new_countries, "known_countries": baseline.known_countries},
                mitre_technique="T1078.004",  # Cloud Accounts
            ))

        # ── 4. عدد اتصالات غير طبيعي ──
        conn_z = self._stats[eid]["connections"].zscore(event.connections)
        if conn_z > 4.0:
            alerts.append(AnomalyAlert(
                entity_id=eid,
                entity_type=event.entity_type,
                timestamp=event.timestamp,
                anomaly_type="connection_spike",
                severity="high",
                risk_delta=conn_z,
                description=f"{event.connections} connections — {conn_z:.1f}σ above baseline",
                evidence={"connections": event.connections, "zscore": conn_z},
                mitre_technique="T1046",  # Network Service Discovery
            ))

        if not alerts:
            return None

        # إعادة أعلى تنبيه
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return max(alerts, key=lambda a: severity_order.get(a.severity, 0))

    def get_entity_risk_score(self, entity_id: str) -> float:
        """نقاط الخطر التراكمية للـ entity (0.0 – 1.0)"""
        baseline = self._baselines.get(entity_id)
        if not baseline or baseline.sample_count < self.min_samples:
            return 0.0

        events = list(self._event_buffer[entity_id])
        if not events:
            return 0.0

        recent_events = [e for e in events if time.time() - e.timestamp < 3600]
        if not recent_events:
            return 0.0

        recent_bytes = sum(e.bytes_transferred for e in recent_events)
        bytes_z = self._stats[entity_id]["bytes"].zscore(recent_bytes)
        risk = min(abs(bytes_z) / 10.0, 1.0)
        return round(risk, 3)

    def get_all_baselines(self) -> List[Dict]:
        return [asdict(b) for b in self._baselines.values()]
