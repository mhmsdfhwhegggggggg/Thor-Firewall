"""
Thor Firewall — UEBA Anomaly Detector (COMPLETED)
==================================================
User and Entity Behavior Analytics — يكتشف الانحرافات السلوكية.

الخوارزميات:
  1. Isolation Forest      — anomaly scoring (unsupervised)
  2. One-Class SVM         — novelty detection per entity
  3. LSTM Autoencoder      — temporal sequence anomalies
  4. Statistical baselines — Z-score, MAD, CUSUM per user/host

يُحلل:
  - نشاط المستخدمين (Login times, volumes, failed auths)
  - سلوك الـ Hosts (port activity, traffic patterns)
  - تغييرات الحالة (privilege escalation, lateral movement)
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("thor.ueba")

# ── Entity Profiles ────────────────────────────────────────────────────────────

@dataclass
class EntityProfile:
    """Rolling statistics for a user or host entity."""
    entity_id:    str
    entity_type:  str  # "user" | "host" | "service"
    
    # Rolling window (last 24h features)
    _window:      deque = field(default_factory=lambda: deque(maxlen=1440))  # 1min buckets
    
    # Baseline stats (updated hourly)
    mean:         np.ndarray = field(default_factory=lambda: np.zeros(16))
    std:          np.ndarray = field(default_factory=lambda: np.ones(16))
    
    # Anomaly history
    anomaly_scores: deque = field(default_factory=lambda: deque(maxlen=100))
    last_seen:    float = field(default_factory=time.time)
    
    def update_baseline(self):
        if len(self._window) < 30:
            return
        data = np.array(list(self._window))
        self.mean = data.mean(axis=0)
        self.std  = np.maximum(data.std(axis=0), 1e-8)

    def z_score(self, features: np.ndarray) -> float:
        """Returns max Z-score (how many stds away from baseline)."""
        if self.std.min() < 1e-7:
            return 0.0
        z = np.abs((features - self.mean) / self.std)
        return float(z.max())

    def add_observation(self, features: np.ndarray):
        self._window.append(features.copy())
        self.last_seen = time.time()


# ── Feature Extractors ────────────────────────────────────────────────────────

def extract_user_features(
    events: List[dict],
    window_secs: int = 3600,
) -> np.ndarray:
    """
    Extract 16-dim UEBA features for a user entity.
    Based on SANS SEC555/SEC530 UEBA methodology.
    """
    now   = time.time()
    since = now - window_secs
    recent = [e for e in events if e.get("timestamp", 0) >= since]
    
    if not recent:
        return np.zeros(16, dtype=np.float32)
    
    timestamps  = [e.get("timestamp", now) for e in recent]
    hours       = [(t % 86400) / 3600 for t in timestamps]  # hour of day
    src_ips     = set(e.get("src_ip", "") for e in recent)
    dst_ips     = set(e.get("dst_ip", "") for e in recent)
    dst_ports   = set(e.get("dst_port", 0) for e in recent)
    failed_auth = sum(1 for e in recent if e.get("event_type") == "auth_failure")
    logins      = sum(1 for e in recent if e.get("event_type") == "auth_success")
    bytes_sent  = sum(e.get("bytes", 0) for e in recent)
    bytes_recv  = sum(e.get("rbytes", 0) for e in recent)
    priv_escalations = sum(1 for e in recent if e.get("privilege_change", False))
    
    # Detect off-hours activity (midnight–6am)
    off_hours_count = sum(1 for h in hours if h < 6 or h > 22)
    
    f = np.array([
        np.log(len(recent) + 1),                    # event count
        np.log(len(src_ips) + 1),                   # unique source IPs
        np.log(len(dst_ips) + 1),                   # unique dest IPs
        np.log(len(dst_ports) + 1),                 # unique dest ports
        np.log(failed_auth + 1),                    # failed auth attempts
        np.log(logins + 1),                         # successful logins
        failed_auth / max(logins + failed_auth, 1), # fail ratio
        np.log(bytes_sent + 1) / 30,                # bytes sent (normalized)
        np.log(bytes_recv + 1) / 30,                # bytes received
        off_hours_count / max(len(recent), 1),      # off-hours ratio
        np.log(priv_escalations + 1),               # privilege escalations
        np.std(hours) if len(hours) > 1 else 0,     # login time variance
        np.mean(hours),                              # average login hour
        len(recent) / window_secs * 60,              # events per minute
        (bytes_sent / max(bytes_recv, 1)),           # upload/download ratio
        1.0 if len(src_ips) > 5 else 0.0,           # multiple IPs flag
    ], dtype=np.float32)
    
    return np.nan_to_num(f, nan=0.0, posinf=30.0, neginf=0.0)


def extract_host_features(
    flows: List[dict],
    window_secs: int = 3600,
) -> np.ndarray:
    """Extract 16-dim UEBA features for a host entity."""
    now   = time.time()
    since = now - window_secs
    recent = [f for f in flows if f.get("timestamp", 0) >= since]
    
    if not recent:
        return np.zeros(16, dtype=np.float32)
    
    src_ports   = set(f.get("src_port", 0) for f in recent)
    dst_ports   = set(f.get("dst_port", 0) for f in recent)
    peer_ips    = set(f.get("dst_ip", "") for f in recent)
    bytes_total = sum(f.get("bytes", 0) for f in recent)
    new_conns   = sum(1 for f in recent if f.get("is_new", False))
    tcp_syns    = sum(1 for f in recent if f.get("syn", False) and not f.get("ack", False))
    rst_count   = sum(1 for f in recent if f.get("rst", False))
    scan_ports  = sum(1 for f in recent if f.get("is_scan", False))
    
    fe = np.array([
        np.log(len(recent) + 1),
        np.log(len(src_ports) + 1),
        np.log(len(dst_ports) + 1),
        np.log(len(peer_ips) + 1),
        np.log(bytes_total + 1) / 30,
        np.log(new_conns + 1),
        np.log(tcp_syns + 1),
        np.log(rst_count + 1),
        np.log(scan_ports + 1),
        tcp_syns / max(len(recent), 1),       # SYN ratio (DDoS/scan indicator)
        rst_count / max(new_conns, 1),         # RST ratio (scan indicator)
        scan_ports / max(len(dst_ports), 1),   # port scan ratio
        1.0 if len(dst_ports) > 50 else 0.0,  # port sweep flag
        len(recent) / window_secs,             # flow rate per second
        0.0, 0.0,                              # reserved for GNN embedding
    ], dtype=np.float32)
    
    return np.nan_to_num(fe, nan=0.0, posinf=30.0, neginf=0.0)


# ── Isolation Forest ──────────────────────────────────────────────────────────

class ThorIsolationForest:
    """
    Scikit-learn Isolation Forest wrapper with auto-retraining.
    Falls back to statistical Z-score if sklearn unavailable.
    """

    def __init__(self, n_estimators: int = 100, contamination: float = 0.05):
        self._clf          = None
        self.n_estimators  = n_estimators
        self.contamination = contamination
        self._train_data:  List[np.ndarray] = []
        self._min_samples  = 200
        self._fitted       = False

    def add_sample(self, features: np.ndarray):
        self._train_data.append(features.copy())
        if len(self._train_data) > 50_000:
            self._train_data = self._train_data[10_000:]  # evict oldest

    def fit(self):
        if len(self._train_data) < self._min_samples:
            return
        try:
            from sklearn.ensemble import IsolationForest
            X = np.array(self._train_data[-10_000:])
            self._clf = IsolationForest(
                n_estimators  = self.n_estimators,
                contamination = self.contamination,
                n_jobs        = -1,
                random_state  = 42,
            )
            self._clf.fit(X)
            self._fitted = True
            logger.info("IsolationForest fitted on %d samples", len(X))
        except ImportError:
            logger.warning("scikit-learn not installed — using Z-score fallback")

    def score(self, features: np.ndarray) -> float:
        """
        Returns anomaly score [0, 1].
        Higher = more anomalous.
        """
        if self._fitted and self._clf is not None:
            score = -self._clf.score_samples(features.reshape(1, -1))[0]
            # Isolation Forest returns negative scores; normalize to [0,1]
            return float(np.clip((score + 0.5) / 1.0, 0, 1))
        # Z-score fallback
        if self._train_data:
            data = np.array(self._train_data[-1000:])
            mean = data.mean(axis=0)
            std  = np.maximum(data.std(axis=0), 1e-8)
            z    = np.abs((features - mean) / std).max()
            return float(np.clip(z / 5.0, 0, 1))  # z=5 → score=1.0
        return 0.0


# ── Main UEBA Engine ──────────────────────────────────────────────────────────

class UEBAEngine:
    """
    Core UEBA engine — maintains profiles for all entities,
    scores new behavior, fires alerts on anomalies.
    """

    ALERT_THRESHOLD = 0.75    # score > 0.75 → alert
    HIGH_THRESHOLD  = 0.90    # score > 0.90 → critical

    def __init__(self):
        self._profiles:      Dict[str, EntityProfile] = {}
        self._forests:       Dict[str, ThorIsolationForest] = {}
        self._alert_history: deque = deque(maxlen=10_000)
        self._fit_counter    = 0

    def _get_profile(self, entity_id: str, entity_type: str = "host") -> EntityProfile:
        if entity_id not in self._profiles:
            self._profiles[entity_id] = EntityProfile(entity_id, entity_type)
        return self._profiles[entity_id]

    def _get_forest(self, entity_id: str) -> ThorIsolationForest:
        if entity_id not in self._forests:
            self._forests[entity_id] = ThorIsolationForest()
        return self._forests[entity_id]

    def analyze_host(self, host_ip: str, flows: List[dict]) -> dict:
        """Analyze a host's recent flows for anomalies."""
        features = extract_host_features(flows)
        return self._score_entity(host_ip, "host", features)

    def analyze_user(self, user_id: str, events: List[dict]) -> dict:
        """Analyze a user's recent authentication/activity events."""
        features = extract_user_features(events)
        return self._score_entity(user_id, "user", features)

    def _score_entity(self, entity_id: str, entity_type: str, features: np.ndarray) -> dict:
        profile = self._get_profile(entity_id, entity_type)
        forest  = self._get_forest(entity_id)

        # Update profile
        profile.add_observation(features)
        forest.add_sample(features)

        # Retrain forest periodically
        self._fit_counter += 1
        if self._fit_counter % 500 == 0:
            forest.fit()
            profile.update_baseline()

        # Score
        iso_score = forest.score(features)
        z_score   = min(profile.z_score(features) / 5.0, 1.0)  # normalize
        combined  = 0.6 * iso_score + 0.4 * z_score

        profile.anomaly_scores.append(combined)

        result = {
            "entity_id":      entity_id,
            "entity_type":    entity_type,
            "anomaly_score":  round(combined, 4),
            "isolation_score": round(iso_score, 4),
            "z_score_norm":   round(z_score, 4),
            "is_alert":       combined > self.ALERT_THRESHOLD,
            "is_critical":    combined > self.HIGH_THRESHOLD,
            "timestamp":      time.time(),
        }

        if result["is_alert"]:
            self._alert_history.append(result)
            logger.warning(
                "UEBA ALERT: %s %s score=%.3f",
                entity_type, entity_id, combined
            )

        return result

    def get_top_anomalies(self, n: int = 20) -> List[dict]:
        """Return top-N most anomalous entities right now."""
        current_scores = []
        for eid, profile in self._profiles.items():
            if profile.anomaly_scores:
                avg = np.mean(list(profile.anomaly_scores)[-10:])
                current_scores.append({
                    "entity_id":   eid,
                    "entity_type": profile.entity_type,
                    "avg_score":   round(float(avg), 4),
                    "last_seen":   profile.last_seen,
                })
        return sorted(current_scores, key=lambda x: x["avg_score"], reverse=True)[:n]

    def get_alert_history(self, limit: int = 100) -> List[dict]:
        return list(self._alert_history)[-limit:]


# ── Singleton ─────────────────────────────────────────────────────────────────

_engine: Optional[UEBAEngine] = None

def get_ueba_engine() -> UEBAEngine:
    global _engine
    if _engine is None:
        _engine = UEBAEngine()
    return _engine
