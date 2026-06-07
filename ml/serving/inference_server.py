"""
Thor Firewall — ML Inference Server
خادم الاستنتاج للنماذج الذكية

يوفر:
- REST API لـ MARL inference
- gRPC endpoint (يتوافق مع thor.proto)
- Batch processing
- Model hot-swap (بدون إيقاف)
- Prometheus metrics

الاستخدام:
    uvicorn ml.serving.inference_server:app --host 0.0.0.0 --port 8082
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.gzip import GZipMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field

from ml.marl.agents import MetaAgent, MARLConfig, ACTION_SPACE
from ml.gnn.network_analyzer import NetworkGraphBuilder, GNNConfig

logger = logging.getLogger("thor.inference")

# ============================================================================
# Global Model State
# ============================================================================

_meta_agent: Optional[MetaAgent] = None
_gnn_builder: Optional[NetworkGraphBuilder] = None
_model_version: str = "0.1.0-dev"
_inference_count: int = 0
_total_latency_ms: float = 0.0


def get_agent() -> MetaAgent:
    if _meta_agent is None:
        raise HTTPException(503, "ML model not loaded")
    return _meta_agent


# ============================================================================
# Request/Response Models
# ============================================================================

class InferenceRequest(BaseModel):
    flow_key_hash: int
    features: List[float] = Field(..., min_length=50, max_length=50)
    gnn_embedding: Optional[List[float]] = Field(None, max_length=32)
    protocol: str = Field("tcp", pattern="^(tcp|udp|icmp)$")


class InferenceResponse(BaseModel):
    flow_key_hash: int
    decision: str
    action_index: int
    risk_score: float
    confidence: float
    explanation: Optional[str]
    agent_id: str
    inference_time_us: int


class BatchInferenceRequest(BaseModel):
    requests: List[InferenceRequest]


class BatchInferenceResponse(BaseModel):
    responses: List[InferenceResponse]
    total_time_us: int
    batch_size: int


class ModelInfo(BaseModel):
    version: str
    loaded: bool
    device: str
    total_inferences: int
    avg_latency_us: float
    protocols: List[str]


class NetworkUpdate(BaseModel):
    src_ip: str
    dst_ip: str
    flow_stats: dict


# ============================================================================
# Lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _meta_agent, _gnn_builder

    logger.info("Loading ML models...")

    # تهيئة MARL
    config = MARLConfig()
    _meta_agent = MetaAgent(config)

    # محاولة تحميل نموذج مدرَّب
    import os
    checkpoint = os.environ.get("THOR_ML_CHECKPOINT", "ml/checkpoints/best")
    import pathlib
    if pathlib.Path(checkpoint).exists():
        try:
            _meta_agent.load_all(checkpoint)
            logger.info(f"Loaded checkpoint from {checkpoint}")
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}, using untrained model")
    else:
        logger.warning("No checkpoint found, using randomly initialized model")

    # تهيئة GNN
    gnn_config = GNNConfig()
    _gnn_builder = NetworkGraphBuilder(gnn_config)

    logger.info(f"ML Inference Server ready (device={config.device})")
    yield

    logger.info("ML Inference Server shutting down")


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="Thor Firewall ML Inference Server",
    description="Real-time AI inference for packet classification",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=500)
Instrumentator().instrument(app).expose(app)


# ============================================================================
# Routes
# ============================================================================

@app.get("/health")
async def health():
    return {
        "status": "healthy" if _meta_agent else "loading",
        "version": _model_version,
    }


@app.get("/model/info", response_model=ModelInfo)
async def model_info():
    global _inference_count, _total_latency_ms
    agent = get_agent()
    return ModelInfo(
        version=_model_version,
        loaded=True,
        device=agent.config.device,
        total_inferences=_inference_count,
        avg_latency_us=(_total_latency_ms * 1000 / max(1, _inference_count)),
        protocols=agent.config.protocols,
    )


@app.post("/infer", response_model=InferenceResponse)
async def infer(request: InferenceRequest):
    """
    تصنيف تدفق شبكي واحد

    الإدخال: 50 ميزة تدفق + 32 ميزة GNN (اختيارية)
    الإخراج: قرار + نقاط الخطر + شرح
    """
    global _inference_count, _total_latency_ms

    start = time.perf_counter()
    agent = get_agent()

    # بناء متجه الحالة (50 + 32 = 82)
    state = np.array(request.features, dtype=np.float32)
    gnn_emb = np.zeros(32, dtype=np.float32)

    if request.gnn_embedding:
        gnn_emb[:len(request.gnn_embedding)] = request.gnn_embedding
    elif _gnn_builder:
        # الحصول على تضمين GNN في الوقت الفعلي
        # gnn_emb = _gnn_builder.get_node_embedding(src_ip)
        pass

    full_state = np.concatenate([state, gnn_emb])

    # الاستنتاج
    action_idx, confidence = agent.make_decision(
        full_state, request.protocol, deterministic=True
    )

    decision_name = ACTION_SPACE.get(action_idx, "allow")
    risk_score = 1.0 - confidence if action_idx == 0 else confidence

    elapsed_us = int((time.perf_counter() - start) * 1_000_000)

    _inference_count += 1
    _total_latency_ms += elapsed_us / 1000.0

    return InferenceResponse(
        flow_key_hash=request.flow_key_hash,
        decision=decision_name,
        action_index=action_idx,
        risk_score=round(risk_score, 4),
        confidence=round(confidence, 4),
        explanation=None,  # LLM generates on-demand
        agent_id=f"marl-{request.protocol}-agent",
        inference_time_us=elapsed_us,
    )


@app.post("/infer/batch", response_model=BatchInferenceResponse)
async def infer_batch(request: BatchInferenceRequest):
    """
    تصنيف دفعة من التدفقات (أكثر كفاءة من الاستدعاء الفردي)
    """
    start = time.perf_counter()

    responses = await asyncio.gather(*[
        infer(req) for req in request.requests
    ])

    total_us = int((time.perf_counter() - start) * 1_000_000)

    return BatchInferenceResponse(
        responses=list(responses),
        total_time_us=total_us,
        batch_size=len(request.requests),
    )


@app.post("/network/update")
async def update_network(update: NetworkUpdate):
    """تحديث الرسم البياني للشبكة بتدفق جديد"""
    if _gnn_builder:
        _gnn_builder.update_flow(
            update.src_ip,
            update.dst_ip,
            update.flow_stats,
        )
    return {"status": "updated"}


@app.get("/network/threats")
async def get_network_threats():
    """الحصول على قائمة الأجهزة المشبوهة من GNN"""
    if not _gnn_builder:
        return {"threats": {}}
    threats = await asyncio.to_thread(_gnn_builder.analyze_network)
    return {"threats": threats, "count": len(threats)}


@app.post("/model/reload")
async def reload_model(checkpoint: str = "ml/checkpoints/best"):
    """إعادة تحميل النموذج بدون إيقاف (Hot-swap)"""
    global _meta_agent

    try:
        agent = get_agent()
        agent.load_all(checkpoint)
        logger.info(f"Model reloaded from {checkpoint}")
        return {"status": "reloaded", "checkpoint": checkpoint}
    except Exception as e:
        raise HTTPException(500, f"Failed to reload model: {e}")
