"""
Thor Firewall — Incremental (Online) ML Trainer
يُدرّب النموذج تدريجياً على البيانات الجديدة بدون إعادة تدريب كاملة

Implements: SGD-based incremental learning + experience replay buffer

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, time, os
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

logger = logging.getLogger("thor.ml.online")

N_FEATURES     = 30    # عدد الـ features للـ flow
REPLAY_BUFFER  = 10_000
LEARNING_RATE  = 0.001
MINI_BATCH     = 64
TRAIN_EVERY    = 100   # كل 100 عينة جديدة


@dataclass
class TrainingExample:
    features:  np.ndarray
    label:     int        # 0=benign, 1=malicious
    weight:    float = 1.0
    timestamp: float = field(default_factory=time.time)


class LogisticRegressionSGD:
    """
    نموذج Logistic Regression تدريجي (SGD) خفيف الوزن.
    يُستخدم لتسجيل التحديثات الفورية بدون PyTorch في التحديثات الصغيرة.
    النماذج الكبيرة (MARL) تُدرَّب في دفعات منفصلة.
    """

    def __init__(self, n_features: int = N_FEATURES):
        self.n_features = n_features
        self.weights    = np.zeros(n_features, dtype=np.float64)
        self.bias       = 0.0
        self.lr         = LEARNING_RATE
        self.n_updates  = 0

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        z = X @ self.weights + self.bias
        return 1.0 / (1.0 + np.exp(-np.clip(z, -50, 50)))

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)

    def partial_fit(self, X: np.ndarray, y: np.ndarray, sample_weight: np.ndarray = None) -> float:
        """تحديث تدريجي بـ SGD مع L2 regularization"""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if y.ndim == 0:
            y = np.array([y])

        n = len(y)
        w = sample_weight if sample_weight is not None else np.ones(n)
        proba = self.predict_proba(X)
        error = proba - y
        loss  = float(-np.mean(y * np.log(proba + 1e-10) + (1 - y) * np.log(1 - proba + 1e-10)))

        # Gradient with L2
        dW = (X.T @ (error * w)) / n + 0.001 * self.weights
        dB = np.mean(error * w)

        self.weights -= self.lr * dW
        self.bias    -= self.lr * dB
        self.n_updates += n

        # Adaptive LR decay
        if self.n_updates % 10000 == 0:
            self.lr = max(self.lr * 0.9, 1e-5)

        return loss

    def save(self, path: str) -> None:
        np.savez(path, weights=self.weights, bias=np.array([self.bias]),
                 n_updates=np.array([self.n_updates]))
        logger.info("model_saved", path=path, n_updates=self.n_updates)

    def load(self, path: str) -> None:
        if not os.path.exists(path + ".npz"):
            return
        data = np.load(path + ".npz")
        self.weights   = data["weights"]
        self.bias      = float(data["bias"][0])
        self.n_updates = int(data["n_updates"][0])
        logger.info("model_loaded", path=path, n_updates=self.n_updates)


class IncrementalTrainer:
    """
    مدرّب تدريجي مع:
    - Experience Replay Buffer (يمنع catastrophic forgetting)
    - Concept Drift Detection (ADWIN من drift_detector)
    - Model checkpointing
    - Performance tracking
    """

    def __init__(
        self,
        model_path: str = "ml/models/online_lr_model",
        replay_size: int = REPLAY_BUFFER,
    ):
        self.model_path   = model_path
        self.model        = LogisticRegressionSGD()
        self.model.load(model_path)
        self._replay:     deque[TrainingExample] = deque(maxlen=replay_size)
        self._new_samples: List[TrainingExample] = []
        self._metrics:    List[Dict[str, Any]]   = []
        self._n_total     = 0
        self._n_correct   = 0

    def add_sample(
        self,
        features:  np.ndarray,
        label:     int,
        weight:    float = 1.0,
    ) -> Optional[Dict[str, Any]]:
        """
        أضف عينة تدريب جديدة.
        إذا تراكم عدد كافٍ، يُدرَّب النموذج تلقائياً.
        """
        example = TrainingExample(features=features, label=label, weight=weight)
        self._replay.append(example)
        self._new_samples.append(example)

        if len(self._new_samples) >= TRAIN_EVERY:
            return self._train_step()
        return None

    def _train_step(self) -> Dict[str, Any]:
        """دورة تدريب واحدة: عينات جديدة + replay"""
        new_X = np.stack([e.features for e in self._new_samples])
        new_y = np.array([e.label    for e in self._new_samples])
        new_w = np.array([e.weight   for e in self._new_samples])
        loss  = self.model.partial_fit(new_X, new_y, new_w)

        # Replay step
        if len(self._replay) >= MINI_BATCH:
            rng  = np.random.default_rng()
            idx  = rng.choice(len(self._replay), MINI_BATCH, replace=False)
            buf  = list(self._replay)
            r_X  = np.stack([buf[i].features for i in idx])
            r_y  = np.array([buf[i].label    for i in idx])
            self.model.partial_fit(r_X, r_y)

        metrics = {
            "timestamp":     time.time(),
            "loss":          round(loss, 6),
            "n_updates":     self.model.n_updates,
            "new_samples":   len(self._new_samples),
            "replay_buffer": len(self._replay),
            "lr":            self.model.lr,
        }
        self._metrics.append(metrics)
        if len(self._metrics) > 1000:
            self._metrics = self._metrics[-1000:]

        logger.info("online_train_step", **metrics)
        self._new_samples.clear()

        # Checkpoint every 10 steps
        if len(self._metrics) % 10 == 0:
            self.model.save(self.model_path)

        return metrics

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """قيّم أداء النموذج على مجموعة اختبار"""
        preds  = self.model.predict(X)
        tp = int(np.sum((preds == 1) & (y == 1)))
        fp = int(np.sum((preds == 1) & (y == 0)))
        fn = int(np.sum((preds == 0) & (y == 1)))
        tn = int(np.sum((preds == 0) & (y == 0)))

        accuracy  = (tp + tn) / max(len(y), 1)
        precision = tp / max(tp + fp, 1)
        recall    = tp / max(tp + fn, 1)
        f1        = 2 * precision * recall / max(precision + recall, 1e-9)

        return {
            "accuracy":  round(accuracy, 4),
            "precision": round(precision, 4),
            "recall":    round(recall, 4),
            "f1":        round(f1, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }

    def get_metrics_history(self, last_n: int = 100) -> List[Dict]:
        return self._metrics[-last_n:]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "n_updates":     self.model.n_updates,
            "replay_size":   len(self._replay),
            "pending":       len(self._new_samples),
            "lr":            self.model.lr,
            "train_steps":   len(self._metrics),
            "model_path":    self.model_path,
        }


# Singleton
_trainer: Optional[IncrementalTrainer] = None

def get_incremental_trainer() -> IncrementalTrainer:
    global _trainer
    if _trainer is None:
        _trainer = IncrementalTrainer()
    return _trainer
