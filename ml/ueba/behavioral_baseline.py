"""
Thor Firewall — UEBA Behavioral Baseline
خط الأساس السلوكي لكشف الشذوذ

يستخدم Welford's online algorithm لحساب mean/variance
بدون تخزين كل الملاحظات (memory efficient).

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import json, logging, time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("thor.ueba.baseline")


@dataclass
class WelfordStats:
    """Welford's algorithm لحساب الإحصاءات التدريجي"""
    n: int = 0
    mean: float = 0.0
    M2: float = 0.0    # Variance * (n-1)

    def update(self, x: float):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.M2 / self.n if self.n >= 2 else 0.0

    @property
    def std(self) -> float:
        return self.variance ** 0.5

    def zscore(self, x: float) -> float:
        if self.std < 1e-10:
            return 0.0
        return abs(x - self.mean) / self.std


@dataclass
class EntityBaseline:
    """خط الأساس السلوكي لـ entity واحد"""
    entity_id: str
    entity_type: str        # "user" | "host" | "service" | "ip"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # الإحصاءات السلوكية
    bytes_per_hour: WelfordStats = field(default_factory=WelfordStats)
    connections_per_hour: WelfordStats = field(default_factory=WelfordStats)
    unique_destinations: WelfordStats = field(default_factory=WelfordStats)
    failed_auth_per_hour: WelfordStats = field(default_factory=WelfordStats)
    dns_queries_per_hour: WelfordStats = field(default_factory=WelfordStats)

    # Active hours pattern (24 bins)
    hourly_activity: List[int] = field(default_factory=lambda: [0] * 24)

    def update(self, observation: Dict[str, float]):
        """تحديث خط الأساس بملاحظة جديدة"""
        self.updated_at = time.time()
        hour = int(time.localtime().tm_hour)
        self.hourly_activity[hour] += 1

        if "bytes" in observation:
            self.bytes_per_hour.update(observation["bytes"])
        if "connections" in observation:
            self.connections_per_hour.update(observation["connections"])
        if "unique_dsts" in observation:
            self.unique_destinations.update(observation["unique_dsts"])
        if "failed_auth" in observation:
            self.failed_auth_per_hour.update(observation["failed_auth"])
        if "dns_queries" in observation:
            self.dns_queries_per_hour.update(observation["dns_queries"])

    def anomaly_score(self, observation: Dict[str, float]) -> float:
        """
        نقطة الشذوذ (0.0–1.0)
        مبنية على Z-score لكل بُعد + معامل ترجيح
        """
        if self.bytes_per_hour.n < 10:
            return 0.0  # لا يوجد خط أساس كافٍ

        scores = []
        weights = []

        if "bytes" in observation and self.bytes_per_hour.n >= 10:
            z = self.bytes_per_hour.zscore(observation["bytes"])
            scores.append(min(z / 5.0, 1.0))
            weights.append(0.3)

        if "connections" in observation and self.connections_per_hour.n >= 10:
            z = self.connections_per_hour.zscore(observation["connections"])
            scores.append(min(z / 5.0, 1.0))
            weights.append(0.25)

        if "unique_dsts" in observation and self.unique_destinations.n >= 10:
            z = self.unique_destinations.zscore(observation["unique_dsts"])
            scores.append(min(z / 5.0, 1.0))
            weights.append(0.2)

        if "failed_auth" in observation and self.failed_auth_per_hour.n >= 10:
            z = self.failed_auth_per_hour.zscore(observation["failed_auth"])
            scores.append(min(z / 3.0, 1.0))  # أقل sigma للـ failed auth
            weights.append(0.25)

        if not scores:
            return 0.0

        total_w = sum(weights[:len(scores)])
        return sum(s * w for s, w in zip(scores, weights)) / total_w

    def is_off_hours(self) -> bool:
        """هل النشاط خارج ساعات العمل الطبيعية؟"""
        if sum(self.hourly_activity) < 100:
            return False  # لا يوجد نمط كافٍ
        normal_hours = sorted(range(24), key=lambda h: self.hourly_activity[h], reverse=True)[:10]
        current_hour = int(time.localtime().tm_hour)
        return current_hour not in normal_hours


class BehavioralBaselineStore:
    """مخزن خطوط الأساس لجميع الكيانات"""

    def __init__(self, persist_path: Optional[str] = None):
        self._baselines: Dict[str, EntityBaseline] = {}
        self._persist_path = Path(persist_path) if persist_path else None

    def get_or_create(self, entity_id: str, entity_type: str = "host") -> EntityBaseline:
        if entity_id not in self._baselines:
            self._baselines[entity_id] = EntityBaseline(entity_id=entity_id, entity_type=entity_type)
        return self._baselines[entity_id]

    def update(self, entity_id: str, observation: Dict[str, float], entity_type: str = "host"):
        baseline = self.get_or_create(entity_id, entity_type)
        baseline.update(observation)

    def score(self, entity_id: str, observation: Dict[str, float]) -> float:
        baseline = self._baselines.get(entity_id)
        if not baseline:
            return 0.0
        return baseline.anomaly_score(observation)

    def get_high_risk_entities(self, threshold: float = 0.7) -> List[Dict]:
        """قائمة الكيانات ذات المخاطر العالية"""
        results = []
        for eid, b in self._baselines.items():
            if b.bytes_per_hour.n < 10:
                continue
            # تقدير النقطة من آخر قراءة تقريبية
            score = min(b.bytes_per_hour.zscore(b.bytes_per_hour.mean * 3) / 5.0, 1.0)
            if score > threshold:
                results.append({
                    "entity_id": eid,
                    "entity_type": b.entity_type,
                    "risk_score": round(score, 3),
                    "observations": b.bytes_per_hour.n,
                    "off_hours": b.is_off_hours(),
                })
        return sorted(results, key=lambda x: x["risk_score"], reverse=True)
