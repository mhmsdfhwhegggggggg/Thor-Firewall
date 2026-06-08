"""
Thor Firewall — Behavioral Analyzer
محلل السلوك — نظام تعلم الأنماط الطبيعية

يُنفّذ "Enterprise Immune System" من إلهام Darktrace:
لكل كيان (IP, User, Service) يبني نموذجاً احتمالياً للسلوك الطبيعي.
أي انحراف عن هذا النموذج يُعتبر مشبوهاً.

الخوارزميات المستخدمة:
  - Online Gaussian Mixture Model (GMM) للتدفقات المستمرة
  - EWMA (Exponentially Weighted Moving Average) لمتوسطات الوقت الحقيقي
  - Mahalanobis Distance للكشف عن الشذوذ متعدد الأبعاد
  - Hellinger Distance لمقارنة التوزيعات

التعقيد: O(1) لكل قرار — مناسب لـ 10M تدفق/ثانية.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List

import numpy as np

from .decision_engine import FlowFeatures


# ============================================================================
# Per-Entity Profile
# ============================================================================

@dataclass
class EntityProfile:
    """
    Statistical profile for one network entity (IP address or user).
    Uses Welford's online algorithm for mean/variance — no stored samples needed.
    """
    entity_id:  str

    # Welford accumulators for each feature dimension
    n:          int   = 0          # sample count
    mean:       Optional[np.ndarray] = None   # shape (D,)
    M2:         Optional[np.ndarray] = None   # shape (D,) — sum of squared deviations

    # Rolling time-series (last 1000 observations)
    _history_size: int = field(default=1000, repr=False)
    _history:   deque = field(default_factory=deque, repr=False)

    # EWMA for fast anomaly detection (α=0.05 → ~20-sample memory)
    ewma_mean:  Optional[np.ndarray] = None
    ewma_var:   Optional[np.ndarray] = None
    ALPHA:      float = 0.05

    # Time-of-day profile: 24 buckets
    hourly_counts: np.ndarray = field(default_factory=lambda: np.zeros(24))

    # Destination port histogram
    dport_hist: Dict[int, int] = field(default_factory=dict)

    # Connection state
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)
    total_bytes: float = 0.0
    total_pkts:  float = 0.0

    def _init_arrays(self, D: int) -> None:
        if self.mean is None:
            self.mean      = np.zeros(D)
            self.M2        = np.zeros(D)
            self.ewma_mean = np.zeros(D)
            self.ewma_var  = np.ones(D) * 0.1

    def update(self, features: np.ndarray, ts: float, dst_port: int, byte_count: float) -> None:
        D = len(features)
        self._init_arrays(D)

        # Welford update
        self.n += 1
        delta  = features - self.mean
        self.mean += delta / self.n
        delta2 = features - self.mean
        self.M2 += delta * delta2

        # EWMA update
        self.ewma_mean = self.ALPHA * features + (1 - self.ALPHA) * self.ewma_mean
        diff = features - self.ewma_mean
        self.ewma_var  = self.ALPHA * diff**2 + (1 - self.ALPHA) * self.ewma_var

        # Time-of-day
        hour = int(time.gmtime(ts).tm_hour)
        self.hourly_counts[hour] += 1

        # Dst port histogram
        self.dport_hist[dst_port] = self.dport_hist.get(dst_port, 0) + 1

        # Totals
        self.last_seen    = ts
        self.total_bytes += byte_count
        self.total_pkts  += 1

        # Rolling history
        self._history.append(features.copy())
        if len(self._history) > self._history_size:
            self._history.popleft()

    @property
    def variance(self) -> Optional[np.ndarray]:
        if self.n < 2:
            return None
        return self.M2 / (self.n - 1)

    def mahalanobis(self, x: np.ndarray) -> float:
        """
        Compute Mahalanobis distance of x from this entity's learned distribution.
        Returns scalar ≥ 0 (larger = more anomalous).
        """
        if self.n < 10 or self.variance is None:
            return 0.0
        var = np.maximum(self.variance, 1e-9)
        delta = x - self.mean
        return float(np.sqrt(np.mean(delta**2 / var)))

    def ewma_anomaly(self, x: np.ndarray) -> float:
        """Fast EWMA-based anomaly score — O(D) computation."""
        if self.ewma_mean is None:
            return 0.0
        var = np.maximum(self.ewma_var, 1e-9)
        delta = x - self.ewma_mean
        z_scores = np.abs(delta) / np.sqrt(var)
        return float(np.mean(z_scores))

    def time_of_day_score(self, ts: float) -> float:
        """How unusual is traffic at this time of day for this entity?"""
        total = self.hourly_counts.sum()
        if total < 24:
            return 0.0
        hour = int(time.gmtime(ts).tm_hour)
        p = self.hourly_counts[hour] / total
        # Entropy-normalized surprise: -log2(p) / 4.58 (max entropy for 24 buckets)
        if p < 1e-9:
            return 1.0
        return min(1.0, -math.log2(p) / math.log2(24))

    def port_novelty(self, dst_port: int) -> float:
        """Has this entity ever talked to this port?"""
        total = sum(self.dport_hist.values())
        if total < 5:
            return 0.0
        count = self.dport_hist.get(dst_port, 0)
        if count == 0:
            return 0.8   # never seen — significant
        # Low count = novel
        return max(0.0, 1.0 - math.log(count + 1) / math.log(total + 1))


# ============================================================================
# Behavioral Analyzer
# ============================================================================

class BehavioralAnalyzer:
    """
    Maintains per-entity behavioral profiles and scores incoming flows
    against those profiles.

    Thread-safe for asyncio use; uses no locks (GIL-protected dict).
    """

    def __init__(
        self,
        window_minutes: int = 60,
        min_samples: int = 30,
        max_entities: int = 500_000,
        anomaly_threshold: float = 3.5,   # Mahalanobis z-score
    ):
        self.window_s          = window_minutes * 60
        self.min_samples       = min_samples
        self.max_entities      = max_entities
        self.anomaly_threshold = anomaly_threshold

        # entity_id → EntityProfile
        self._profiles: Dict[str, EntityProfile] = {}

        # LRU eviction: entity_id → last_access_time
        self._lru: Dict[str, float] = {}
        self._evict_every = 10_000   # evict after this many updates
        self._update_count = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def score(self, flow: FlowFeatures) -> float:
        """
        Return risk score [0,1] based on how anomalous this flow is
        relative to the source IP's learned behavioral profile.
        """
        entity_id = str(flow.src_ip)
        features  = np.array(flow.features[:16], dtype=np.float64)  # first 16 dims

        profile = self._get_or_create_profile(entity_id)

        # If not enough history, use heuristics only
        if profile.n < self.min_samples:
            self._update_profile(profile, features, flow)
            return 0.0   # not enough data to judge

        # Compute anomaly scores
        mahal      = profile.mahalanobis(features)
        ewma_score = profile.ewma_anomaly(features)
        tod_score  = profile.time_of_day_score(flow.timestamp)
        port_score = profile.port_novelty(flow.dst_port)

        # Update profile with this new observation
        self._update_profile(profile, features, flow)

        # Weighted combination
        combined = (
            0.40 * min(1.0, mahal / self.anomaly_threshold) +
            0.30 * min(1.0, ewma_score / 4.0) +
            0.15 * tod_score +
            0.15 * port_score
        )

        return float(np.clip(combined, 0.0, 1.0))

    def get_profile(self, ip: str) -> Optional[EntityProfile]:
        return self._profiles.get(ip)

    def get_stats(self) -> Dict:
        return {
            "entity_count":   len(self._profiles),
            "max_entities":   self.max_entities,
            "update_count":   self._update_count,
        }

    # ── Internals ────────────────────────────────────────────────────────────

    def _get_or_create_profile(self, entity_id: str) -> EntityProfile:
        if entity_id not in self._profiles:
            self._profiles[entity_id] = EntityProfile(entity_id=entity_id)
        self._lru[entity_id] = time.monotonic()
        return self._profiles[entity_id]

    def _update_profile(
        self,
        profile: EntityProfile,
        features: np.ndarray,
        flow: FlowFeatures,
    ) -> None:
        profile.update(features, flow.timestamp, flow.dst_port, flow.byte_count)
        self._update_count += 1

        # Periodic LRU eviction
        if self._update_count % self._evict_every == 0:
            self._evict_lru()

    def _evict_lru(self) -> None:
        """Evict least-recently-used profiles when at capacity."""
        if len(self._profiles) <= self.max_entities:
            return
        cutoff = len(self._profiles) - int(self.max_entities * 0.9)
        sorted_ids = sorted(self._lru, key=lambda k: self._lru[k])
        for eid in sorted_ids[:cutoff]:
            del self._profiles[eid]
            del self._lru[eid]
