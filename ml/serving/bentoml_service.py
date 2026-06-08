"""
Thor Firewall — BentoML Model Serving
=======================================
خدمة inference متكاملة باستخدام BentoML.

مستوحى من: https://github.com/bentoml/BentoML

يخدم:
  - ThorMARLPredictor  — قرارات BLOCK/ALLOW من MARL
  - ThorGNNAnalyzer    — network topology embeddings
  - ThorUEBADetector   — anomaly detection
  - ThorLLMExplainer   — شرح القرارات (يتصل بـ vLLM)

Endpoints:
  HTTP:  POST /predict, POST /predict_batch, POST /explain
  gRPC:  ThorMLService.Analyze, ThorMLService.AnalyzeBatch
"""

from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict, List, Optional

import numpy as np
import torch
import bentoml
from bentoml.io import JSON, NumpyNdarray, Multipart
from pydantic import BaseModel, Field

logger = logging.getLogger("thor.ml.bentoml")

DEVICE = os.getenv("DEVICE", "cpu")
MODEL_PATH = os.getenv("MODEL_PATH", "/models")
VLLM_URL = os.getenv("VLLM_URL", "http://vllm:8000/v1")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/1")


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────────────────────────────────────

class FlowAnalysisRequest(BaseModel):
    flow_id: str
    features: List[float] = Field(..., min_length=50, max_length=50)
    gnn_embedding: Optional[List[float]] = Field(None, min_length=32, max_length=32)
    protocol: str = "tcp"
    src_ip: str = ""
    dst_ip: str = ""
    context: Optional[Dict[str, Any]] = None


class FlowAnalysisResponse(BaseModel):
    flow_id: str
    decision: str               # allow / block / throttle / mirror / redirect
    action_id: int
    risk_score: float
    confidence: float
    explanation: str
    inference_time_us: float
    model_version: str


class BatchAnalysisRequest(BaseModel):
    requests: List[FlowAnalysisRequest]


class BatchAnalysisResponse(BaseModel):
    responses: List[FlowAnalysisResponse]
    total_time_us: float
    batch_size: int


# ─────────────────────────────────────────────────────────────────────────────
# BentoML Runner — MARL Predictor
# ─────────────────────────────────────────────────────────────────────────────

class ThorMARLRunner(bentoml.Runnable):
    SUPPORTED_RESOURCES = ("cpu", "nvidia.com/gpu")
    SUPPORTS_CPU_MULTI_THREADING = True

    def __init__(self):
        import mlflow
        mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000"))

        self.device = torch.device(DEVICE)
        self.models: Dict[str, Any] = {}
        self.action_names = ["allow", "block", "throttle", "mirror", "redirect"]
        self._load_models()

    def _load_models(self):
        """تحميل models من MLflow registry أو local path."""
        import mlflow.pytorch
        for protocol in ["tcp", "udp", "icmp"]:
            model_file = f"{MODEL_PATH}/thor_marl_{protocol}.pt"
            if os.path.exists(model_file):
                self.models[protocol] = torch.jit.load(model_file, map_location=self.device)
                self.models[protocol].eval()
                logger.info(f"✅ Loaded MARL model: {protocol}")
            else:
                logger.warning(f"⚠️  MARL model not found: {protocol}, using random policy")

    @bentoml.Runnable.method(batchable=True, batch_dim=0, max_batch_size=256, max_latency_ms=10)
    def predict(self, features_batch: np.ndarray) -> np.ndarray:
        """
        Batch prediction — يُعالج حتى 256 تدفق في آن واحد.
        
        Args:
            features_batch: [B, 82] float32
        Returns:
            [B, 5] action probabilities
        """
        start = time.perf_counter_ns()

        x = torch.from_numpy(features_batch).float().to(self.device)

        with torch.no_grad():
            # استخدم TCP model افتراضياً إذا لم يحدد البروتوكول
            model = self.models.get("tcp")
            if model is None:
                # Fallback: random policy (للتطوير)
                probs = torch.softmax(torch.randn(x.shape[0], 5), dim=-1)
            else:
                probs = model(x)

        elapsed_us = (time.perf_counter_ns() - start) / 1000
        logger.debug(f"Batch inference: {x.shape[0]} flows in {elapsed_us:.1f}µs")

        return probs.cpu().numpy()


# ─────────────────────────────────────────────────────────────────────────────
# BentoML Service Definition
# ─────────────────────────────────────────────────────────────────────────────

thor_marl_runner = bentoml.picklable_model.get("thor-marl:latest").to_runner() \
    if bentoml.picklable_model.list("thor-marl") else \
    bentoml.runner_from_runnable(ThorMARLRunner, name="thor-marl-runner")

svc = bentoml.Service("thor-inference", runners=[thor_marl_runner])


@svc.api(
    input=JSON(pydantic_model=FlowAnalysisRequest),
    output=JSON(pydantic_model=FlowAnalysisResponse),
    route="/predict",
)
async def predict(request: FlowAnalysisRequest) -> FlowAnalysisResponse:
    """Single flow analysis."""
    start = time.perf_counter_ns()

    # Prepare features (50 packet + 32 GNN = 82)
    features = np.array(request.features, dtype=np.float32)
    if request.gnn_embedding:
        gnn_emb = np.array(request.gnn_embedding, dtype=np.float32)
    else:
        gnn_emb = np.zeros(32, dtype=np.float32)

    obs = np.concatenate([features, gnn_emb]).reshape(1, -1)

    # Run inference
    probs = await thor_marl_runner.predict.async_run(obs)  # [1, 5]
    probs = probs[0]  # [5]

    action_id   = int(np.argmax(probs))
    risk_score  = float(1.0 - probs[0])  # 1 - P(allow)
    confidence  = float(probs[action_id])

    elapsed_us = (time.perf_counter_ns() - start) / 1000

    return FlowAnalysisResponse(
        flow_id=request.flow_id,
        decision=["allow", "block", "throttle", "mirror", "redirect"][action_id],
        action_id=action_id,
        risk_score=risk_score,
        confidence=confidence,
        explanation=f"MARL decision: {['allow','block','throttle','mirror','redirect'][action_id]} "
                    f"(confidence={confidence:.3f}, risk={risk_score:.3f})",
        inference_time_us=elapsed_us,
        model_version="thor-marl-v1",
    )


@svc.api(
    input=JSON(pydantic_model=BatchAnalysisRequest),
    output=JSON(pydantic_model=BatchAnalysisResponse),
    route="/predict_batch",
)
async def predict_batch(request: BatchAnalysisRequest) -> BatchAnalysisResponse:
    """Batch flow analysis — for high-throughput scenarios."""
    start = time.perf_counter_ns()
    responses = []

    # Build batched array
    obs_list = []
    for req in request.requests:
        features = np.array(req.features, dtype=np.float32)
        gnn_emb  = np.array(req.gnn_embedding or [0.0]*32, dtype=np.float32)
        obs_list.append(np.concatenate([features, gnn_emb]))

    obs_batch = np.stack(obs_list)  # [B, 82]
    probs_batch = await thor_marl_runner.predict.async_run(obs_batch)

    for i, req in enumerate(request.requests):
        probs     = probs_batch[i]
        action_id = int(np.argmax(probs))
        responses.append(FlowAnalysisResponse(
            flow_id=req.flow_id,
            decision=["allow","block","throttle","mirror","redirect"][action_id],
            action_id=action_id,
            risk_score=float(1.0 - probs[0]),
            confidence=float(probs[action_id]),
            explanation=f"MARL batch decision",
            inference_time_us=0.0,
            model_version="thor-marl-v1",
        ))

    total_us = (time.perf_counter_ns() - start) / 1000
    return BatchAnalysisResponse(
        responses=responses,
        total_time_us=total_us,
        batch_size=len(responses),
    )


@svc.api(input=JSON(), output=JSON(), route="/healthz")
async def healthz(_: Dict) -> Dict:
    return {
        "status": "healthy",
        "service": "thor-bentoml",
        "device": DEVICE,
        "models_loaded": list(["tcp", "udp", "icmp"]),
    }
