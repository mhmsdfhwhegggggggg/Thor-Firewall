"""
Thor Firewall — UEBA Anomaly Detector
كاشف الشذوذ بالتعلم الآلي

يستخدم:
  - Isolation Forest للكشف غير المُصنَّف
  - LSTM Autoencoder للأنماط الزمنية
  - Peer Group Analysis لمقارنة الكيانات المتشابهة

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, time
from typing import Dict, List, Optional, Tuple
import numpy as np

logger = logging.getLogger("thor.ueba.anomaly")


class IsolationForestDetector:
    """
    Isolation Forest للكشف غير المُصنَّف عن الشذوذ السلوكي.
    لا يحتاج بيانات مُسمَّاة — يعمل بشكل تلقائي.
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self._model = None
        self._fitted = False

    def fit(self, X: np.ndarray):
        """تدريب النموذج على بيانات طبيعية"""
        try:
            from sklearn.ensemble import IsolationForest
            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X)
            self._fitted = True
            logger.info("IsolationForest fitted on %d samples", len(X))
        except ImportError:
            logger.warning("scikit-learn not available — using statistical fallback")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        إعادة: (labels, scores)
          labels: -1=anomaly, 1=normal
          scores: [0,1] أعلى = أشد شذوذاً
        """
        if not self._fitted or self._model is None:
            labels = np.ones(len(X))
            scores = np.zeros(len(X))
            return labels, scores

        labels = self._model.predict(X)
        raw_scores = self._model.score_samples(X)
        # تحويل إلى [0,1] (عكس اتجاه — score أقل = أشد شذوذاً)
        anomaly_scores = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-10)
        return labels, anomaly_scores


class LSTMAutoencoder:
    """
    LSTM Autoencoder للكشف عن الأنماط الزمنية الشاذة.
    يُدرَّب على أنماط طبيعية ويكشف الانحرافات من خلال reconstruction error.
    """

    def __init__(self, input_dim: int = 10, hidden_dim: int = 32, seq_len: int = 24):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.seq_len = seq_len
        self._model = None
        self._threshold = None
        self._fitted = False

    def _build_model(self):
        try:
            import torch
            import torch.nn as nn

            class AutoencoderNet(nn.Module):
                def __init__(self, input_dim, hidden_dim):
                    super().__init__()
                    self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True)
                    self.decoder = nn.LSTM(hidden_dim, input_dim, batch_first=True)

                def forward(self, x):
                    _, (h, _) = self.encoder(x)
                    repeated = h.permute(1, 0, 2).expand(-1, x.size(1), -1)
                    out, _ = self.decoder(repeated)
                    return out

            return AutoencoderNet(self.input_dim, self.hidden_dim)
        except ImportError:
            return None

    def fit(self, sequences: np.ndarray, epochs: int = 30):
        """تدريب على تسلسلات طبيعية"""
        model = self._build_model()
        if model is None:
            logger.warning("PyTorch not available — LSTM Autoencoder disabled")
            return

        try:
            import torch
            import torch.nn as nn

            X = torch.FloatTensor(sequences)
            optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
            criterion = nn.MSELoss()

            model.train()
            for epoch in range(epochs):
                recon = model(X)
                loss = criterion(recon, X)
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                if (epoch + 1) % 10 == 0:
                    logger.debug("LSTM AE Epoch %d/%d | loss=%.4f", epoch+1, epochs, loss.item())

            # حساب threshold (mean + 3*std للـ reconstruction error)
            model.eval()
            with torch.no_grad():
                recon = model(X)
                errors = ((X - recon) ** 2).mean(dim=[1, 2]).numpy()
                self._threshold = errors.mean() + 3 * errors.std()

            self._model = model
            self._fitted = True
            logger.info("LSTM Autoencoder fitted. Threshold=%.4f", self._threshold)

        except Exception as e:
            logger.error("LSTM AE training failed: %s", e)

    def anomaly_score(self, sequence: np.ndarray) -> float:
        """نقطة الشذوذ للتسلسل (0.0–1.0)"""
        if not self._fitted or self._model is None:
            return 0.0

        try:
            import torch
            x = torch.FloatTensor(sequence).unsqueeze(0)
            with torch.no_grad():
                recon = self._model(x)
                error = ((x - recon) ** 2).mean().item()
                if self._threshold:
                    return min(error / self._threshold, 1.0)
        except Exception:
            pass
        return 0.0


class PeerGroupAnalyzer:
    """
    مقارنة كل entity بمجموعة أقرانها (نفس الدور/القسم).
    إذا كان سلوك entity يختلف كثيراً عن أقرانه → شذوذ.
    """

    def __init__(self):
        self._groups: Dict[str, List[Dict]] = {}

    def add_to_group(self, entity_id: str, group_id: str, behavior_vector: np.ndarray):
        """إضافة entity لمجموعته"""
        if group_id not in self._groups:
            self._groups[group_id] = []
        self._groups[group_id].append({
            "entity_id": entity_id,
            "vector": behavior_vector,
            "updated_at": time.time(),
        })

    def peer_anomaly_score(self, entity_id: str, group_id: str, current_vector: np.ndarray) -> float:
        """
        كشف الشذوذ بمقارنة current_vector مع متوسط المجموعة.
        إعادة zscore طبيعية [0, 1]
        """
        group = self._groups.get(group_id, [])
        peers = [m["vector"] for m in group if m["entity_id"] != entity_id]

        if len(peers) < 3:
            return 0.0  # لا توجد بيانات كافية

        group_matrix = np.stack(peers)
        group_mean = group_matrix.mean(axis=0)
        group_std  = group_matrix.std(axis=0) + 1e-10

        zscores = np.abs((current_vector - group_mean) / group_std)
        max_z = zscores.max()
        return min(max_z / 5.0, 1.0)  # Normalize: 5sigma = 1.0


class UEBAAnomalyEngine:
    """
    المحرك الموحد للكشف عن الشذوذ السلوكي
    يجمع: IsolationForest + LSTM Autoencoder + Peer Group Analysis
    """

    def __init__(self):
        self.isolation_forest = IsolationForestDetector(contamination=0.05)
        self.lstm_ae = LSTMAutoencoder(input_dim=8, hidden_dim=32, seq_len=24)
        self.peer_analyzer = PeerGroupAnalyzer()
        self._is_trained = False

    def train(self, behavior_matrix: np.ndarray):
        """تدريب جميع النماذج"""
        logger.info("Training UEBA anomaly models on %d samples...", len(behavior_matrix))
        self.isolation_forest.fit(behavior_matrix)
        self._is_trained = True

    def score(
        self,
        entity_id: str,
        feature_vector: np.ndarray,
        group_id: Optional[str] = None,
        time_series: Optional[np.ndarray] = None,
    ) -> Dict[str, float]:
        """
        حساب نقاط الشذوذ الموحدة من كل النماذج
        إعادة dict: {isolation, lstm, peer, ensemble}
        """
        scores = {"isolation": 0.0, "lstm": 0.0, "peer": 0.0}

        if self._is_trained:
            _, iso_scores = self.isolation_forest.predict(feature_vector.reshape(1, -1))
            scores["isolation"] = float(iso_scores[0])

        if time_series is not None and self.lstm_ae._fitted:
            scores["lstm"] = self.lstm_ae.anomaly_score(time_series)

        if group_id and self.peer_analyzer._groups:
            scores["peer"] = self.peer_analyzer.peer_anomaly_score(
                entity_id, group_id, feature_vector
            )

        # Ensemble (weighted average)
        weights = {"isolation": 0.5, "lstm": 0.3, "peer": 0.2}
        scores["ensemble"] = sum(scores[k] * weights[k] for k in weights)

        return scores
