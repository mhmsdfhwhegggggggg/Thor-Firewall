"""
Thor Firewall — Zero-Day Detector
كاشف التهديدات المجهولة (Zero-Day)

يستخدم تقنيات Unsupervised Anomaly Detection لاكتشاف
الهجمات التي لم تُدرَّب عليها النماذج المُشرَف عليها.

الخوارزميات:
  1. Isolation Forest — يعزل الشذوذات عبر أقصر مسار في الشجرة
  2. Autoencoder Reconstruction Error — ارتفاع الخطأ = تهديد غير معروف
  3. Local Outlier Factor (online approximation)
  4. Statistical Z-score على النوافذ الزمنية

مرجع: "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection"
(Bar-Ad et al., NDSS 2018) — نفس المنهجية التي تستخدمها أنظمة EDR تجارية.

الفرق بين هذا وبين MARL:
  - MARL: يتعرف على الأنماط المُدرَّب عليها (Known-Known)
  - Zero-Day: يكتشف ما لم يُدرَّب عليه (Known-Unknown + Unknown-Unknown)

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

import numpy as np

from .decision_engine import FlowFeatures


# ============================================================================
# Mini Autoencoder (pure NumPy — no PyTorch dependency for production)
# ============================================================================

class NumpyAutoencoder:
    """
    Tiny 3-layer autoencoder trained online via SGD.
    Input dim D → hidden H → latent L → hidden H → output D.

    Uses ReLU activations and MSE reconstruction error.
    Trained incrementally — no batch required.
    """

    def __init__(self, input_dim: int = 16, latent_dim: int = 4, lr: float = 0.001):
        self.D  = input_dim
        self.L  = latent_dim
        H       = input_dim * 2

        # Xavier initialization
        self.W1 = np.random.randn(H, self.D) * math.sqrt(2 / self.D)
        self.b1 = np.zeros(H)
        self.W2 = np.random.randn(self.L, H) * math.sqrt(2 / H)
        self.b2 = np.zeros(self.L)
        self.W3 = np.random.randn(H, self.L) * math.sqrt(2 / self.L)
        self.b3 = np.zeros(H)
        self.W4 = np.random.randn(self.D, H) * math.sqrt(2 / H)
        self.b4 = np.zeros(self.D)

        self.lr        = lr
        self.n_trained = 0

    @staticmethod
    def _relu(x: np.ndarray) -> np.ndarray:
        return np.maximum(0, x)

    @staticmethod
    def _relu_grad(x: np.ndarray) -> np.ndarray:
        return (x > 0).astype(float)

    def forward(self, x: np.ndarray) -> np.ndarray:
        self._h1 = self._relu(self.W1 @ x + self.b1)
        self._z  = self._relu(self.W2 @ self._h1 + self.b2)
        self._h2 = self._relu(self.W3 @ self._z + self.b3)
        self._out = self.W4 @ self._h2 + self.b4
        return self._out

    def reconstruction_error(self, x: np.ndarray) -> float:
        """MSE reconstruction error — high = anomalous."""
        x_hat = self.forward(x)
        return float(np.mean((x - x_hat) ** 2))

    def train_step(self, x: np.ndarray) -> float:
        """One SGD step. Returns reconstruction error."""
        x_hat = self.forward(x)
        err   = x_hat - x

        # Backward pass (manual backprop)
        dL_dout = 2 * err / self.D
        dL_dh2  = (self.W4.T @ dL_dout) * self._relu_grad(self.W3 @ self._z + self.b3)
        dL_dz   = (self.W3.T @ dL_dh2) * self._relu_grad(self.W2 @ self._h1 + self.b2)
        dL_dh1  = (self.W2.T @ dL_dz) * self._relu_grad(self.W1 @ x + self.b1)

        # Gradient descent
        self.W4 -= self.lr * np.outer(dL_dout, self._h2)
        self.b4 -= self.lr * dL_dout
        self.W3 -= self.lr * np.outer(dL_dh2, self._z)
        self.b3 -= self.lr * dL_dh2
        self.W2 -= self.lr * np.outer(dL_dz, self._h1)
        self.b2 -= self.lr * dL_dz
        self.W1 -= self.lr * np.outer(dL_dh1, x)
        self.b1 -= self.lr * dL_dh1

        self.n_trained += 1
        return float(np.mean(err ** 2))


# ============================================================================
# Online Isolation Forest (approximate)
# ============================================================================

class OnlineIsolationForest:
    """
    Streaming approximation of Isolation Forest.
    Maintains a sliding window of samples and scores new points
    using path-length in random projection trees.

    Much lighter than scikit-learn's implementation — suitable for O(1) scoring.
    """

    def __init__(self, window_size: int = 2048, n_trees: int = 50, max_depth: int = 10):
        self.window_size = window_size
        self.n_trees     = n_trees
        self.max_depth   = max_depth
        self._window:    Deque[np.ndarray] = deque(maxlen=window_size)
        self._trained    = False
        self._forest     = []   # list of (feature_idx, split_val, left, right)

    def update(self, x: np.ndarray) -> None:
        self._window.append(x.copy())
        # Rebuild forest periodically
        if len(self._window) >= 256 and len(self._window) % 256 == 0:
            self._build_forest()

    def score(self, x: np.ndarray) -> float:
        """
        Anomaly score [0, 1].  1 = highly anomalous.
        Uses average path length normalization.
        """
        if not self._trained or len(self._forest) == 0:
            return 0.0

        path_lengths = [self._path_length(x, tree) for tree in self._forest]
        avg_path = np.mean(path_lengths)
        # Expected path length for a normal point in a tree of n samples
        n = len(self._window)
        c_n = 2 * (np.log(n - 1) + 0.5772) - 2 * (n - 1) / n if n > 1 else 1.0
        return float(2 ** (-avg_path / c_n))

    def _build_forest(self) -> None:
        data = np.array(list(self._window))
        self._forest = []
        for _ in range(self.n_trees):
            idx   = np.random.choice(len(data), min(256, len(data)), replace=False)
            sample = data[idx]
            tree  = self._build_tree(sample, 0)
            self._forest.append(tree)
        self._trained = True

    def _build_tree(self, data: np.ndarray, depth: int):
        if len(data) <= 1 or depth >= self.max_depth:
            return {"type": "leaf", "size": len(data)}
        feat_idx = np.random.randint(0, data.shape[1])
        col      = data[:, feat_idx]
        lo, hi   = col.min(), col.max()
        if lo >= hi:
            return {"type": "leaf", "size": len(data)}
        split = np.random.uniform(lo, hi)
        left_mask  = col < split
        right_mask = ~left_mask
        return {
            "type":     "split",
            "feat_idx": feat_idx,
            "split":    split,
            "left":     self._build_tree(data[left_mask],  depth + 1),
            "right":    self._build_tree(data[right_mask], depth + 1),
        }

    def _path_length(self, x: np.ndarray, node: dict, depth: int = 0) -> float:
        if node["type"] == "leaf":
            n = node["size"]
            return depth + (2 * (np.log(n - 1) + 0.5772) - 2 * (n-1)/n if n > 1 else 0)
        if x[node["feat_idx"]] < node["split"]:
            return self._path_length(x, node["left"],  depth + 1)
        return self._path_length(x, node["right"], depth + 1)


# ============================================================================
# Zero-Day Detector
# ============================================================================

class ZeroDayDetector:
    """
    Ensemble anomaly detector combining Autoencoder + Isolation Forest.

    Training phase: first 500 flows train the models in online fashion.
    Detection phase: after warmup, score all new flows.
    """

    WARMUP_SAMPLES  = 500
    AE_ERROR_SCALE  = 8.0    # normalize autoencoder error to [0,1]
    ENSEMBLE_WEIGHTS = (0.55, 0.45)  # (autoencoder, iforest)

    def __init__(self, contamination: float = 0.01, input_dim: int = 16):
        self.contamination = contamination
        self.input_dim     = input_dim

        self._ae      = NumpyAutoencoder(input_dim=input_dim, latent_dim=input_dim//4)
        self._iforest = OnlineIsolationForest()

        # Rolling error statistics for dynamic thresholding
        self._error_history: Deque[float] = deque(maxlen=10_000)
        self._n_processed = 0

        # Per-protocol sub-detectors
        self._proto_ae = {
            6:  NumpyAutoencoder(input_dim=input_dim, latent_dim=4),   # TCP
            17: NumpyAutoencoder(input_dim=input_dim, latent_dim=4),   # UDP
            1:  NumpyAutoencoder(input_dim=input_dim, latent_dim=4),   # ICMP
        }

    def score(self, flow: FlowFeatures) -> float:
        """
        Return zero-day anomaly score [0, 1].
        0 = normal (or not enough data), 1 = highly anomalous.
        """
        x = self._extract_features(flow)
        self._n_processed += 1

        if self._n_processed < self.WARMUP_SAMPLES:
            # Training phase — update models, return 0
            self._train(x, flow.proto)
            return 0.0

        # Detection phase
        ae_error   = self._ae.reconstruction_error(x)
        if_score   = self._iforest.score(x)

        # Also train on this sample (online learning)
        self._train(x, flow.proto)

        # Normalize AE error relative to historical distribution
        if len(self._error_history) > 50:
            mean_err = np.mean(self._error_history)
            std_err  = max(np.std(self._error_history), 1e-9)
            ae_norm  = float(np.clip((ae_error - mean_err) / (std_err * self.AE_ERROR_SCALE), 0, 1))
        else:
            ae_norm = min(1.0, ae_error / self.AE_ERROR_SCALE)

        self._error_history.append(ae_error)

        # Ensemble score
        score = (
            self.ENSEMBLE_WEIGHTS[0] * ae_norm +
            self.ENSEMBLE_WEIGHTS[1] * if_score
        )

        # Protocol-specific sub-score
        proto_ae = self._proto_ae.get(flow.proto)
        if proto_ae and proto_ae.n_trained > 100:
            proto_err  = proto_ae.reconstruction_error(x)
            proto_norm = min(1.0, proto_err / (self.AE_ERROR_SCALE * 0.5))
            # Mix in protocol-specific score
            score = 0.7 * score + 0.3 * proto_norm

        return float(np.clip(score, 0.0, 1.0))

    def _train(self, x: np.ndarray, proto: int) -> None:
        err = self._ae.train_step(x)
        self._iforest.update(x)
        if proto in self._proto_ae:
            self._proto_ae[proto].train_step(x)

    def _extract_features(self, flow: FlowFeatures) -> np.ndarray:
        features = np.array(flow.features[:self.input_dim], dtype=np.float32)
        # Min-max normalize to [0, 1]
        features = np.clip(features, 0.0, None)
        feat_max = features.max()
        if feat_max > 0:
            features /= feat_max
        return features

    def stats(self) -> Dict[str, Any]:
        return {
            "n_processed":    self._n_processed,
            "warmup_done":    self._n_processed >= self.WARMUP_SAMPLES,
            "ae_trained":     self._ae.n_trained,
            "iforest_ready":  self._iforest._trained,
            "error_history":  len(self._error_history),
        }
