"""
Thor Firewall — Concept Drift Detector
يكتشف انجراف النموذج (Concept Drift) في بيانات حركة المرور الشبكية

Algorithms:
  1. ADWIN (Adaptive Windowing)   — يكتشف تغير توزيع المتغيرات
  2. DDM  (Drift Detection Method) — يكتشف تدهور دقة النموذج
  3. Page-Hinkley Test            — اختبار إحصائي للتغيير الفجائي

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

logger = logging.getLogger("thor.ml.drift")


class DriftStatus(Enum):
    STABLE  = "stable"
    WARNING = "warning"
    DRIFT   = "drift"


@dataclass
class DriftAlert:
    detector:   str          # "adwin" | "ddm" | "page_hinkley"
    status:     DriftStatus
    timestamp:  float
    metric:     str
    old_mean:   float
    new_mean:   float
    change_pct: float
    message:    str


# ── ADWIN Detector ────────────────────────────────────────────────────────────

class ADWINDetector:
    """
    ADWIN (Adaptive Windowing)
    يُقلّص نافذة البيانات تلقائياً عند اكتشاف تغيير إحصائي.
    O(log n) memory و O(n) time.
    """

    def __init__(self, delta: float = 0.002):
        self.delta  = delta   # confidence level
        self._width = 0
        self._total = 0.0
        self._variance  = 0.0
        self._buckets: list = []   # (n, total, variance)
        self._n_total    = 0
        self._last_mean  = 0.0

    def add_element(self, value: float) -> bool:
        """
        أضف عنصراً جديداً.
        Returns True إذا اكتُشف drift.
        """
        self._n_total += 1
        self._update_buckets(value)
        drift = self._detect_change()
        if drift:
            logger.info("adwin_drift_detected", mean_change=self._last_mean, n=self._n_total)
        return drift

    def get_mean(self) -> float:
        n = sum(b[0] for b in self._buckets)
        if n == 0:
            return 0.0
        return sum(b[1] for b in self._buckets) / n

    def _update_buckets(self, value: float) -> None:
        self._buckets.append((1, value, 0.0))
        # Merge buckets of same size (exponential histogram)
        i = len(self._buckets) - 1
        while i > 0 and self._buckets[i][0] == self._buckets[i-1][0]:
            b1 = self._buckets.pop(i-1)
            b2 = self._buckets.pop(i-1)
            n  = b1[0] + b2[0]
            t  = b1[1] + b2[1]
            v  = b1[2] + b2[2] + (b1[1]/b1[0] - b2[1]/b2[0])**2 * b1[0] * b2[0] / n
            self._buckets.insert(i-1, (n, t, v))
            i -= 1

    def _detect_change(self) -> bool:
        total_n = sum(b[0] for b in self._buckets)
        total_t = sum(b[1] for b in self._buckets)
        if total_n < 30:
            return False
        cumsum_n = 0
        cumsum_t = 0.0
        for b in self._buckets:
            cumsum_n += b[0]
            cumsum_t += b[1]
            n0 = cumsum_n
            n1 = total_n - cumsum_n
            if n1 == 0:
                continue
            m0 = cumsum_t / n0
            m1 = (total_t - cumsum_t) / n1
            eps = np.sqrt(np.log(2.0 / self.delta) * (1/(n0) + 1/(n1)) / 2.0)
            if abs(m0 - m1) >= eps:
                self._last_mean = abs(m0 - m1)
                # Trim old data
                self._buckets = self._buckets[len(self._buckets)//2:]
                return True
        return False


# ── DDM Detector (Gama et al.) ────────────────────────────────────────────────

class DDMDetector:
    """
    Drift Detection Method — يتتبع error rate النموذج.
    WARNING: error_rate + 2*std  > past_min + 2*std
    DRIFT:   error_rate + 3*std  > past_min + 3*std
    """

    def __init__(self):
        self._n      = 0
        self._p      = 0.0    # error rate
        self._s      = 0.0    # std
        self._p_min  = float("inf")
        self._s_min  = float("inf")

    def add_element(self, is_error: bool) -> DriftStatus:
        self._n += 1
        x = 1 if is_error else 0
        # Welford's online
        if self._n == 1:
            self._p = x
            self._s = 0.0
        else:
            delta   = x - self._p
            self._p += delta / self._n
            self._s  = np.sqrt(self._p * (1 - self._p) / self._n)

        if self._p + self._s < self._p_min + self._s_min:
            self._p_min = self._p
            self._s_min = self._s

        if self._n < 30:
            return DriftStatus.STABLE

        if self._p + self._s > self._p_min + 3 * self._s_min:
            self._p_min = float("inf")
            self._s_min = float("inf")
            self._n     = 0
            return DriftStatus.DRIFT

        if self._p + self._s > self._p_min + 2 * self._s_min:
            return DriftStatus.WARNING

        return DriftStatus.STABLE


# ── Page-Hinkley ─────────────────────────────────────────────────────────────

class PageHinkleyDetector:
    """
    اختبار Page-Hinkley — حساس للتغيرات المفاجئة في المتوسط.
    """

    def __init__(self, delta: float = 0.005, lambda_: float = 50, alpha: float = 0.9999):
        self.delta   = delta
        self.lambda_ = lambda_
        self.alpha   = alpha
        self._x_mean = 0.0
        self._sum    = 0.0
        self._n      = 0

    def add_element(self, value: float) -> bool:
        self._n += 1
        self._x_mean = self.alpha * self._x_mean + (1 - self.alpha) * value
        self._sum    = max(0, self._sum + value - self._x_mean - self.delta)
        return self._sum > self.lambda_


# ── Master Drift Monitor ──────────────────────────────────────────────────────

class DriftMonitor:
    """
    يُشغّل جميع detectors بالتوازي ويُصدر تنبيه موحّد.
    """

    def __init__(self):
        self._adwin   = ADWINDetector(delta=0.002)
        self._ddm     = DDMDetector()
        self._ph_risk = PageHinkleyDetector(delta=0.005, lambda_=40)
        self._alerts: List[DriftAlert] = []
        self._stats:  Dict[str, float] = {"mean_risk": 0.0, "ddm_error_rate": 0.0}
        self._n_flows = 0

    def process_flow(
        self,
        risk_score:  float,
        is_fp:       bool = False,   # False Positive (model mispredicted)
        features:    np.ndarray = None,
    ) -> Optional[DriftAlert]:
        """
        أرسل flow للـ detectors.
        أعد DriftAlert إذا اكتُشف drift.
        """
        self._n_flows += 1
        old_mean = self._adwin.get_mean()

        adwin_drift = self._adwin.add_element(risk_score)
        ddm_status  = self._ddm.add_element(is_fp)
        ph_drift    = self._ph_risk.add_element(risk_score)

        alert = None
        if adwin_drift:
            new_mean = self._adwin.get_mean()
            chg = abs(new_mean - old_mean) / max(abs(old_mean), 1e-6) * 100
            alert = DriftAlert(
                detector   = "adwin",
                status     = DriftStatus.DRIFT,
                timestamp  = time.time(),
                metric     = "risk_score_distribution",
                old_mean   = old_mean,
                new_mean   = new_mean,
                change_pct = round(chg, 2),
                message    = f"ADWIN detected drift: risk_score mean changed by {chg:.1f}%",
            )
        elif ddm_status == DriftStatus.DRIFT:
            alert = DriftAlert(
                detector   = "ddm",
                status     = DriftStatus.DRIFT,
                timestamp  = time.time(),
                metric     = "model_error_rate",
                old_mean   = self._ddm._p_min,
                new_mean   = self._ddm._p,
                change_pct = 0.0,
                message    = "DDM detected model error rate degradation",
            )
        elif ddm_status == DriftStatus.WARNING:
            alert = DriftAlert(
                detector   = "ddm",
                status     = DriftStatus.WARNING,
                timestamp  = time.time(),
                metric     = "model_error_rate",
                old_mean   = self._ddm._p_min,
                new_mean   = self._ddm._p,
                change_pct = 0.0,
                message    = "DDM warning: error rate rising",
            )

        if alert:
            self._alerts.append(alert)
            if alert.status == DriftStatus.DRIFT:
                logger.warning("concept_drift_detected",
                               detector=alert.detector,
                               metric=alert.metric,
                               change_pct=alert.change_pct)

        return alert

    def get_recent_alerts(self, last_n: int = 20) -> List[DriftAlert]:
        return self._alerts[-last_n:]

    def stats(self) -> Dict[str, Any]:
        return {
            "n_flows_processed": self._n_flows,
            "adwin_mean":        round(self._adwin.get_mean(), 4),
            "ddm_error_rate":    round(self._ddm._p, 4),
            "total_drift_events": len(self._alerts),
            "last_drift":        self._alerts[-1].timestamp if self._alerts else None,
        }


# Singleton
_drift_monitor: Optional[DriftMonitor] = None

def get_drift_monitor() -> DriftMonitor:
    global _drift_monitor
    if _drift_monitor is None:
        _drift_monitor = DriftMonitor()
    return _drift_monitor
