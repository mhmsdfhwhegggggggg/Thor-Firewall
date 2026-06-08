"""
Thor Firewall — ML Inference Server
خادم الاستنتاج الذكي — FastAPI

يستقبل طلبات تحليل الحزم ويُعيد القرارات مع نقاط الخطر.

Endpoints:
  POST /v1/analyze        — تحليل تدفق واحد
  POST /v1/analyze/batch  — تحليل دفعة (64 تدفق دفعة واحدة)
  GET  /health            — فحص صحة الخادم
  GET  /metrics           — Prometheus metrics
  GET  /v1/model/info     — معلومات النموذج الحالي

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logger = logging.getLogger("thor.ml.serving")

# ──────────────────────────────────────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────────────────────────────────────

class AnalysisRequest(BaseModel):
    flow_key_hash: int
    features: List[float] = Field(..., min_length=10, max_length=82)
    protocol: str = "tcp"
    gnn_embedding: Optional[List[float]] = None

class AnalysisResponse(BaseModel):
    flow_key_hash: int
    decision: str           # allow | block | throttle | mirror | redirect
    risk_score: float       # 0.0 – 1.0
    confidence: float       # 0.0 – 1.0
    explanation: Optional[str] = None
    agent_id: str
    inference_time_us: int

class BatchAnalysisRequest(BaseModel):
    requests: List[AnalysisRequest]

class BatchAnalysisResponse(BaseModel):
    responses: List[AnalysisResponse]
    total_time_us: int

class ModelInfo(BaseModel):
    version: str
    protocols: List[str]
    input_dim: int
    n_classes: int
    accuracy: Optional[float]
    loaded_at: str

# ──────────────────────────────────────────────────────────────────────────────
# Model Manager
# ──────────────────────────────────────────────────────────────────────────────

DECISION_MAP = {
    0: "allow",
    1: "block",
    2: "throttle",
    3: "mirror",
    4: "redirect",
}

ATTACK_EXPLANATIONS = {
    "block":    "High-risk flow detected. Pattern matches known attack signatures.",
    "throttle": "Suspicious traffic rate. Applying rate limiting as precaution.",
    "mirror":   "Anomalous behavior detected. Mirroring for deep inspection.",
    "redirect": "Sophisticated evasion technique detected. Redirecting to honeypot.",
    "allow":    None,
}


class ModelManager:
    """مدير النماذج — تحميل + inference + fallback"""

    def __init__(self, model_dir: str = "/models/marl"):
        self.model_dir = Path(model_dir)
        self.models: Dict[str, object] = {}
        self.model_info: Optional[ModelInfo] = None
        self._loaded = False

    def load(self):
        """تحميل نماذج PyTorch من الـ disk"""
        try:
            import torch
            from ml.training.train_marl import ActorCriticNetwork, ProtocolAgent

            loaded = 0
            for protocol in ["tcp", "udp", "icmp"]:
                model_path = self.model_dir / f"thor_{protocol}_agent.pt"
                if model_path.exists():
                    agent = ProtocolAgent(protocol=protocol, input_dim=50, device="cpu")
                    agent.load(str(model_path))
                    agent.network.eval()
                    self.models[protocol] = agent
                    loaded += 1
                    logger.info("Loaded %s model from %s", protocol, model_path)
                else:
                    logger.warning("Model not found: %s — using heuristic fallback", model_path)

            self._loaded = loaded > 0
            self.model_info = ModelInfo(
                version="1.0.0" if self._loaded else "heuristic-fallback",
                protocols=list(self.models.keys()) or ["tcp", "udp", "icmp"],
                input_dim=50,
                n_classes=5,
                accuracy=None,
                loaded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            logger.info("ModelManager: %d models loaded", loaded)

        except ImportError as e:
            logger.warning("PyTorch not available: %s — using heuristic mode", e)
            self._loaded = False
            self.model_info = ModelInfo(
                version="heuristic-fallback",
                protocols=["tcp", "udp", "icmp"],
                input_dim=50,
                n_classes=5,
                accuracy=None,
                loaded_at=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )

    def infer_single(self, req: AnalysisRequest) -> AnalysisResponse:
        """استنتاج لتدفق واحد"""
        t0 = time.perf_counter()
        features = np.array(req.features, dtype=np.float32)

        if len(features) < 50:
            features = np.pad(features, (0, 50 - len(features)))
        features = features[:50]

        decision, risk_score, confidence, explanation = self._run_inference(
            features, req.protocol
        )

        latency_us = int((time.perf_counter() - t0) * 1e6)
        return AnalysisResponse(
            flow_key_hash=req.flow_key_hash,
            decision=decision,
            risk_score=float(risk_score),
            confidence=float(confidence),
            explanation=explanation,
            agent_id=f"marl-{req.protocol}-agent",
            inference_time_us=latency_us,
        )

    def infer_batch(self, requests: List[AnalysisRequest]) -> List[AnalysisResponse]:
        """استنتاج دفعة — أسرع من استدعاءات فردية"""
        if not requests:
            return []

        try:
            import torch
        except ImportError:
            return [self.infer_single(r) for r in requests]

        t0 = time.perf_counter()

        # Group by protocol for efficient batching
        by_protocol: Dict[str, List] = {}
        for i, req in enumerate(requests):
            proto = req.protocol if req.protocol in self.models else "tcp"
            by_protocol.setdefault(proto, []).append((i, req))

        results = [None] * len(requests)

        for protocol, indexed_reqs in by_protocol.items():
            indices = [x[0] for x in indexed_reqs]
            batch_reqs = [x[1] for x in indexed_reqs]

            features_batch = np.stack([
                np.pad(np.array(r.features[:50], dtype=np.float32), (0, max(0, 50 - len(r.features))))
                for r in batch_reqs
            ])

            if protocol in self.models:
                import torch
                model = self.models[protocol].network
                with torch.no_grad():
                    x = torch.FloatTensor(features_batch)
                    logits, values = model(x)
                    probs = torch.softmax(logits, dim=1)
                    decisions_idx = logits.argmax(dim=1).numpy()
                    risk_scores = (1 - probs[:, 0]).numpy()  # P(not allow)
                    confidences = probs.max(dim=1).values.numpy()
            else:
                decisions_idx = np.array([self._heuristic_decision(f) for f in features_batch])
                risk_scores = np.array([self._heuristic_risk(f) for f in features_batch])
                confidences = np.full(len(features_batch), 0.65)

            for i, (orig_idx, req) in enumerate(indexed_reqs):
                decision = DECISION_MAP.get(int(decisions_idx[i]), "allow")
                explanation = ATTACK_EXPLANATIONS.get(decision)
                results[orig_idx] = AnalysisResponse(
                    flow_key_hash=req.flow_key_hash,
                    decision=decision,
                    risk_score=float(np.clip(risk_scores[i], 0, 1)),
                    confidence=float(np.clip(confidences[i], 0, 1)),
                    explanation=explanation,
                    agent_id=f"marl-{protocol}-agent",
                    inference_time_us=int((time.perf_counter() - t0) * 1e6),
                )

        return [r for r in results if r is not None]

    def _run_inference(self, features: np.ndarray, protocol: str):
        """تشغيل inference على تدفق واحد"""
        if self._loaded and protocol in self.models:
            try:
                import torch
                model = self.models[protocol].network
                with torch.no_grad():
                    x = torch.FloatTensor(features).unsqueeze(0)
                    logits, value = model(x)
                    probs = torch.softmax(logits, dim=1).numpy()[0]
                    decision_idx = probs.argmax()
                    decision = DECISION_MAP.get(int(decision_idx), "allow")
                    risk_score = float(1 - probs[0])  # 1 - P(allow)
                    confidence = float(probs.max())
                    explanation = ATTACK_EXPLANATIONS.get(decision)
                    return decision, risk_score, confidence, explanation
            except Exception as e:
                logger.error("Inference error: %s — falling back to heuristic", e)

        # Heuristic fallback
        decision_idx = self._heuristic_decision(features)
        risk = self._heuristic_risk(features)
        decision = DECISION_MAP.get(decision_idx, "allow")
        explanation = ATTACK_EXPLANATIONS.get(decision)
        return decision, risk, 0.65, explanation

    @staticmethod
    def _heuristic_decision(features: np.ndarray) -> int:
        """قواعد بسيطة كـ fallback"""
        # feature[20] = SYN flag, feature[21] = ACK flag
        if len(features) > 21 and features[20] > 0 and features[21] == 0:
            if len(features) > 2 and features[2] > 1000:  # high fwd packets
                return 1  # block (SYN flood)
        # feature[30] = payload entropy
        if len(features) > 30 and features[30] > 7.5:
            return 3  # mirror (possible encrypted C2)
        return 0  # allow

    @staticmethod
    def _heuristic_risk(features: np.ndarray) -> float:
        """حساب نقاط الخطر بشكل تقريبي"""
        risk = 0.05
        if len(features) > 30 and features[30] > 7.0:
            risk += 0.4
        if len(features) > 20 and features[20] > 0 and features[21] == 0:
            risk += 0.3
        return float(min(risk, 0.99))


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI App
# ──────────────────────────────────────────────────────────────────────────────

model_manager = ModelManager(
    model_dir=os.getenv("MODEL_PATH", "/models/marl")
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Loading ML models...")
    model_manager.load()
    logger.info("ML Inference Server ready")
    yield
    logger.info("ML Inference Server shutting down")

app = FastAPI(
    title="Thor ML Inference API",
    description="MARL + GNN Inference Server for Thor Firewall",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "model_loaded": model_manager._loaded,
        "model_version": model_manager.model_info.version if model_manager.model_info else "unknown",
        "timestamp": time.time(),
    }


@app.get("/v1/model/info", response_model=ModelInfo)
async def model_info():
    if not model_manager.model_info:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return model_manager.model_info


@app.post("/v1/analyze", response_model=AnalysisResponse)
async def analyze_single(req: AnalysisRequest):
    try:
        return model_manager.infer_single(req)
    except Exception as e:
        logger.exception("Inference error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/analyze/batch", response_model=BatchAnalysisResponse)
async def analyze_batch(req: BatchAnalysisRequest):
    if len(req.requests) > 256:
        raise HTTPException(status_code=400, detail="Batch size must be ≤ 256")

    t0 = time.perf_counter()
    try:
        responses = model_manager.infer_batch(req.requests)
        total_us = int((time.perf_counter() - t0) * 1e6)
        return BatchAnalysisResponse(responses=responses, total_time_us=total_us)
    except Exception as e:
        logger.exception("Batch inference error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8082")))
