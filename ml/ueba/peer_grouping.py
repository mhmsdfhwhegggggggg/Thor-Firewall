"""
Thor Firewall — UEBA Peer Group Analysis
تجميع الـ entities بسلوك مشابه وكشف الشذوذ داخل المجموعة

الخوارزمية: K-Means clustering + silhouette scoring
كل entity تُقارَن بأقرانها — شذوذ entity داخل مجموعتها = تنبيه عالي الدقة.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("thor.ueba.peer_grouping")

# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class EntityVector:
    """متجه الميزات لكل entity"""
    entity_id:   str
    entity_type: str   # "user" | "host" | "service"
    features:    np.ndarray   # shape (N_FEATURES,)
    last_updated: float = field(default_factory=time.time)

    # Feature names (must match order in features array)
    FEATURE_NAMES = [
        "bytes_per_hour_norm",       # 0
        "connections_per_hour_norm", # 1
        "unique_dsts_norm",          # 2
        "avg_flow_duration_norm",    # 3
        "failed_auth_rate",          # 4
        "unique_protocols",          # 5
        "dst_port_entropy",          # 6
        "external_ratio",            # 7
        "night_activity_ratio",      # 8
        "weekend_activity_ratio",    # 9
        "avg_risk_score",            # 10
        "blocked_ratio",             # 11
    ]
    N_FEATURES = len(FEATURE_NAMES)


@dataclass
class PeerGroup:
    """مجموعة entities بسلوك متشابه"""
    group_id:    int
    centroid:    np.ndarray
    members:     List[str]           # entity_ids
    entity_type: str
    label:       str = "unknown"     # "normal_users", "power_users", "servers", ...
    radius:      float = 0.0         # max distance from centroid (anomaly threshold)

    @property
    def size(self) -> int:
        return len(self.members)


@dataclass
class PeerAnomalyResult:
    """نتيجة مقارنة entity بمجموعتها"""
    entity_id:    str
    group_id:     int
    group_label:  str
    distance:     float          # المسافة عن مركز المجموعة
    peer_rank:    float          # الترتيب داخل المجموعة (0=أقرب، 1=أبعد)
    is_anomaly:   bool
    anomaly_score: float         # 0.0 - 1.0
    top_deviations: List[str]    # أكثر الميزات انحرافاً


# ── K-Means Peer Grouping ─────────────────────────────────────────────────────

class PeerGroupAnalyzer:
    """
    يحلل مجموعات الـ peers ويكشف الـ entities غير الطبيعية داخل مجموعتها.

    الفكرة: مدير IT يتصرف مختلفاً عن محاسب — لا نقارنهم ببعض.
    نكشف المدير الذي يتصرف كـ "attacker" داخل مجموعة المديرين.
    """

    def __init__(self, n_clusters: int = 5, anomaly_threshold: float = 2.5):
        self.n_clusters         = n_clusters
        self.anomaly_threshold  = anomaly_threshold   # عدد الانحرافات المعيارية
        self._groups:           Dict[str, List[PeerGroup]] = {}  # entity_type → groups
        self._entity_vectors:   Dict[str, EntityVector]   = {}
        self._last_fit:         float = 0.0
        self._fit_interval:     float = 3600.0  # إعادة clustering كل ساعة

    # ── Public API ─────────────────────────────────────────────────────────────

    def update_entity(self, vector: EntityVector) -> None:
        """حدّث متجه entity في المخزن المؤقت"""
        self._entity_vectors[vector.entity_id] = vector
        if time.time() - self._last_fit > self._fit_interval:
            self._fit_all()

    def analyze_entity(self, entity_id: str) -> Optional[PeerAnomalyResult]:
        """قارن entity بمجموعتها وأعد نتيجة الشذوذ"""
        vec = self._entity_vectors.get(entity_id)
        if vec is None:
            return None

        groups = self._groups.get(vec.entity_type)
        if not groups:
            self._fit_all()
            groups = self._groups.get(vec.entity_type, [])
        if not groups:
            return None

        # ابحث عن أقرب مجموعة
        best_group, best_dist = self._find_nearest_group(vec.features, groups)

        # احسب الترتيب داخل المجموعة
        peer_rank  = self._compute_peer_rank(entity_id, best_group, best_dist)
        is_anomaly = best_dist > best_group.radius * self.anomaly_threshold
        score      = min(best_dist / max(best_group.radius * self.anomaly_threshold, 1e-6), 1.0)
        deviations = self._top_deviations(vec.features, best_group.centroid)

        return PeerAnomalyResult(
            entity_id      = entity_id,
            group_id       = best_group.group_id,
            group_label    = best_group.label,
            distance       = round(float(best_dist), 4),
            peer_rank      = round(float(peer_rank), 3),
            is_anomaly     = is_anomaly,
            anomaly_score  = round(float(score), 4),
            top_deviations = deviations,
        )

    def get_groups(self, entity_type: str = "user") -> List[PeerGroup]:
        return self._groups.get(entity_type, [])

    def get_top_outliers(self, entity_type: str = "user", top_n: int = 20) -> List[PeerAnomalyResult]:
        """أعد قائمة الـ entities الأكثر شذوذاً"""
        results = []
        for eid, vec in self._entity_vectors.items():
            if vec.entity_type != entity_type:
                continue
            r = self.analyze_entity(eid)
            if r and r.is_anomaly:
                results.append(r)
        return sorted(results, key=lambda x: x.anomaly_score, reverse=True)[:top_n]

    # ── Private ────────────────────────────────────────────────────────────────

    def _fit_all(self) -> None:
        """أعد حساب مجموعات الـ peers لكل entity_type"""
        entity_types = set(v.entity_type for v in self._entity_vectors.values())
        for etype in entity_types:
            vecs = [v for v in self._entity_vectors.values() if v.entity_type == etype]
            if len(vecs) < self.n_clusters:
                continue
            X = np.stack([v.features for v in vecs])
            labels = self._kmeans(X, self.n_clusters)
            groups = []
            for k in range(self.n_clusters):
                mask    = labels == k
                members = [vecs[i].entity_id for i in range(len(vecs)) if mask[i]]
                if not members:
                    continue
                centroid = X[mask].mean(axis=0)
                dists    = np.linalg.norm(X[mask] - centroid, axis=1)
                radius   = float(np.percentile(dists, 90)) if len(dists) > 1 else 1.0
                group    = PeerGroup(
                    group_id    = k,
                    centroid    = centroid,
                    members     = members,
                    entity_type = etype,
                    label       = self._auto_label(centroid, etype),
                    radius      = max(radius, 0.01),
                )
                groups.append(group)
            self._groups[etype] = groups
            logger.info("peer_groups_fit", entity_type=etype, n_groups=len(groups),
                        n_entities=len(vecs))
        self._last_fit = time.time()

    def _kmeans(self, X: np.ndarray, k: int, max_iter: int = 100) -> np.ndarray:
        """K-Means بسيط بدون sklearn dependency"""
        n = len(X)
        if n <= k:
            return np.arange(n)
        rng       = np.random.default_rng(42)
        centroids = X[rng.choice(n, k, replace=False)]
        labels    = np.zeros(n, dtype=int)
        for _ in range(max_iter):
            dists     = np.stack([np.linalg.norm(X - c, axis=1) for c in centroids], axis=1)
            new_labels = dists.argmin(axis=1)
            if np.array_equal(new_labels, labels):
                break
            labels = new_labels
            for j in range(k):
                members = X[labels == j]
                if len(members):
                    centroids[j] = members.mean(axis=0)
        return labels

    def _find_nearest_group(
        self, features: np.ndarray, groups: List[PeerGroup]
    ) -> Tuple[PeerGroup, float]:
        best_group = groups[0]
        best_dist  = float("inf")
        for g in groups:
            d = float(np.linalg.norm(features - g.centroid))
            if d < best_dist:
                best_dist  = d
                best_group = g
        return best_group, best_dist

    def _compute_peer_rank(self, entity_id: str, group: PeerGroup, dist: float) -> float:
        """نسبة الـ entities في المجموعة التي هي أقرب من هذه الـ entity"""
        peer_dists = []
        for eid in group.members:
            if eid == entity_id:
                continue
            vec = self._entity_vectors.get(eid)
            if vec is not None:
                peer_dists.append(np.linalg.norm(vec.features - group.centroid))
        if not peer_dists:
            return 0.5
        return float(sum(1 for d in peer_dists if d < dist) / len(peer_dists))

    def _top_deviations(
        self, features: np.ndarray, centroid: np.ndarray, top_n: int = 3
    ) -> List[str]:
        """أعد أسماء الميزات الأكثر انحرافاً عن مركز المجموعة"""
        deviations = np.abs(features - centroid)
        top_indices = deviations.argsort()[-top_n:][::-1]
        names = EntityVector.FEATURE_NAMES
        return [names[i] for i in top_indices if i < len(names)]

    def _auto_label(self, centroid: np.ndarray, entity_type: str) -> str:
        """حدد label تلقائياً بناءً على خصائص المجموعة"""
        bytes_norm    = centroid[0] if len(centroid) > 0 else 0
        conn_norm     = centroid[1] if len(centroid) > 1 else 0
        risk_avg      = centroid[10] if len(centroid) > 10 else 0
        night_ratio   = centroid[8]  if len(centroid) > 8  else 0

        if risk_avg > 0.6:
            return "high_risk"
        if bytes_norm > 0.8 and entity_type == "host":
            return "high_volume_server"
        if conn_norm > 0.7:
            return "power_user" if entity_type == "user" else "active_service"
        if night_ratio > 0.6:
            return "night_shift_user"
        return "standard_user" if entity_type == "user" else "standard_host"


# Singleton
_peer_analyzer = PeerGroupAnalyzer()

def get_peer_analyzer() -> PeerGroupAnalyzer:
    return _peer_analyzer
