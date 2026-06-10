"""
Thor Firewall — ML Inference Server
======================================
خادم استدلال عالي الأداء يدعم:
  - تحميل النموذج المدرَّب من thor_marl_best.pt
  - Fallback إلى نموذج heuristic إذا لم يوجد الـ .pt بعد
  - Batch inference (< 1ms P99 على CPU)
  - Prometheus metrics
  - Health check مع معلومات النموذج
"""
from __future__ import annotations

import logging
import os
import time
from typing import Dict, List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Histogram, Counter, Gauge, make_asgi_app
from pydantic import BaseModel, Field

logger = logging.getLogger("thor.serving")

app = FastAPI(title="Thor ML Inference Server", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/metrics", make_asgi_app())

# ── Prometheus ────────────────────────────────────────────────────────────────
INFERENCE_LATENCY = Histogram("thor_ml_inference_latency_seconds", "Inference latency", ["mode"])
INFERENCE_TOTAL   = Counter("thor_ml_inferences_total", "Total inferences", ["decision"])
MODEL_LOADED      = Gauge("thor_ml_model_loaded", "1 if model is loaded")

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_PATH  = os.getenv("MODEL_PATH",  "/models/thor_marl_best.pt")
ONNX_PATH   = os.getenv("ONNX_PATH",  "/models/thor_actor.onnx")
DEVICE      = os.getenv("DEVICE",     "cpu")
INPUT_DIM   = 82    # Updated: 82-dim feature vector (was 50)
N_CLASSES   = 8
CLASS_NAMES = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Bot/C2", "Infiltration"]
RISK_SCORES = [0.02,      0.75,  0.85,   0.60,       0.70,         0.65,        0.90,      0.95]

# ── Model state ───────────────────────────────────────────────────────────────
_model       = None
_onnx_session = None
_model_type  = "none"
_model_info  = {}


def load_model():
    """Load model: try PyTorch → ONNX → fallback heuristic."""
    global _model, _onnx_session, _model_type, _model_info

    # 1. Try PyTorch
    if os.path.exists(MODEL_PATH):
        try:
            import torch
            import sys
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
            from ml.marl.brain.actor import ThorActor
            actor = ThorActor(input_dim=INPUT_DIM)
            ckpt  = torch.load(MODEL_PATH, map_location=DEVICE)
            if "actor" in ckpt:
                actor.load_state_dict(ckpt["actor"])
            else:
                actor.load_state_dict(ckpt)
            actor.eval()
            _model      = actor
            _model_type = "pytorch"
            _model_info = {
                "type":    "pytorch",
                "path":    MODEL_PATH,
                "step":    ckpt.get("step", 0),
                "classes": CLASS_NAMES,
                "input_dim": INPUT_DIM,
            }
            MODEL_LOADED.set(1)
            logger.info("PyTorch model loaded: %s (step %d)", MODEL_PATH, ckpt.get("step", 0))
            return
        except Exception as e:
            logger.warning("PyTorch load failed: %s", e)

    # 2. Try ONNX
    if os.path.exists(ONNX_PATH):
        try:
            import onnxruntime as ort
            _onnx_session = ort.InferenceSession(
                ONNX_PATH,
                providers=["CPUExecutionProvider"],
            )
            _model_type = "onnx"
            _model_info = {"type": "onnx", "path": ONNX_PATH, "input_dim": INPUT_DIM}
            MODEL_LOADED.set(1)
            logger.info("ONNX model loaded: %s", ONNX_PATH)
            return
        except Exception as e:
            logger.warning("ONNX load failed: %s", e)

    # 3. Heuristic fallback (works without a trained model)
    _model_type = "heuristic"
    _model_info = {"type": "heuristic", "note": "rule-based until model is trained"}
    MODEL_LOADED.set(0)
    logger.warning(
        "No trained model found. Using heuristic fallback.\n"
        "Train first: python -m ml.training.train_marl --data-dir ./data/CICIDS2017"
    )


def _heuristic_predict(features: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Rule-based heuristic for operation without a trained model.
    Based on known CICIDS feature signatures.
    Returns: (action_ids, risk_scores)
    """
    n = len(features)
    actions    = np.zeros(n, dtype=np.int32)
    risks      = np.full(n, 0.05, dtype=np.float32)

    for i, f in enumerate(features):
        # f shape: (INPUT_DIM,)
        # Feature indices from feature_engineering.py:
        # f[1]=tcp, f[2]=udp, f[3]=icmp, f[4]=duration_log
        # f[5]=fwd_pkts, f[6]=bwd_pkts, f[56]=bytes/s_log, f[57]=pkts/s_log
        # f[48..55]=TCP flags (FIN,SYN,RST,PSH,ACK,URG,ECE,CWE)

        # SYN flood: high SYN, no ACK, high pkt rate
        if (len(f) > 58 and f[49] > 0.5 and f[52] < 0.1 and f[57] > 6.0):
            actions[i] = 2   # DDoS
            risks[i]   = 0.88
        # Port scan: many diff dst ports, short duration
        elif (len(f) > 5 and f[4] < 1.5 and f[5] < 2.0 and f[6] < 0.5):
            actions[i] = 3   # PortScan
            risks[i]   = 0.65
        # Brute force: many pkts, short flows, high pkt rate
        elif (len(f) > 58 and f[57] > 7.0 and f[4] < 2.0):
            actions[i] = 4   # BruteForce
            risks[i]   = 0.72
        # DoS: huge bytes/s, few sources
        elif (len(f) > 57 and f[56] > 10.0):
            actions[i] = 1   # DoS
            risks[i]   = 0.80
        else:
            actions[i] = 0   # BENIGN
            risks[i]   = 0.03

    return actions, risks


@app.on_event("startup")
async def startup():
    load_model()


# ── Request / Response ────────────────────────────────────────────────────────

class FlowFeatures(BaseModel):
    flow_id:   str
    features:  List[float] = Field(..., min_length=50, max_length=82)


class BatchRequest(BaseModel):
    flows: List[FlowFeatures]


class FlowDecision(BaseModel):
    flow_id:     str
    action:      int
    action_name: str
    risk_score:  float
    confidence:  float
    class_probs: Optional[List[float]] = None


class BatchResponse(BaseModel):
    decisions:    List[FlowDecision]
    latency_ms:   float
    model_type:   str


# ── Inference ─────────────────────────────────────────────────────────────────

@app.post("/predict/batch", response_model=BatchResponse)
async def predict_batch(body: BatchRequest):
    if not body.flows:
        raise HTTPException(status_code=400, detail="Empty batch")

    t0 = time.perf_counter()

    # Pad features to INPUT_DIM
    features = []
    for flow in body.flows:
        f = list(flow.features)
        if len(f) < INPUT_DIM:
            f += [0.0] * (INPUT_DIM - len(f))
        elif len(f) > INPUT_DIM:
            f = f[:INPUT_DIM]
        features.append(f)

    X = np.array(features, dtype=np.float32)
    class_probs_all = None

    if _model_type == "pytorch":
        import torch
        with torch.no_grad():
            out    = _model(torch.from_numpy(X))
            probs  = out["probs"].numpy()
            acts   = probs.argmax(axis=1).astype(np.int32)
            risks  = np.array([RISK_SCORES[a] * probs[i, a] for i, a in enumerate(acts)], dtype=np.float32)
            class_probs_all = probs.tolist()

    elif _model_type == "onnx":
        outputs = _onnx_session.run(None, {"features": X})
        logits  = outputs[0]
        probs   = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
        acts    = probs.argmax(axis=1).astype(np.int32)
        risks   = np.array([RISK_SCORES[a] * probs[i, a] for i, a in enumerate(acts)], dtype=np.float32)
        class_probs_all = probs.tolist()

    else:
        acts, risks = _heuristic_predict(X)

    latency_ms = (time.perf_counter() - t0) * 1000
    INFERENCE_LATENCY.labels(mode=_model_type).observe(latency_ms / 1000)

    decisions = []
    for i, flow in enumerate(body.flows):
        action = int(acts[i])
        risk   = float(risks[i])
        INFERENCE_TOTAL.labels(decision=CLASS_NAMES[action]).inc()
        decisions.append(FlowDecision(
            flow_id     = flow.flow_id,
            action      = action,
            action_name = CLASS_NAMES[action],
            risk_score  = round(risk, 4),
            confidence  = round(float(class_probs_all[i][action]) if class_probs_all else (1.0 - risk), 4),
            class_probs = [round(p, 4) for p in class_probs_all[i]] if class_probs_all else None,
        ))

    return BatchResponse(decisions=decisions, latency_ms=round(latency_ms, 3), model_type=_model_type)


@app.post("/predict", response_model=FlowDecision)
async def predict_single(body: FlowFeatures):
    resp = await predict_batch(BatchRequest(flows=[body]))
    return resp.decisions[0]


@app.get("/health")
async def health():
    return {
        "status":       "ok",
        "model_loaded": _model_type in ("pytorch", "onnx"),
        "model_type":   _model_type,
        "model_info":   _model_info,
        "input_dim":    INPUT_DIM,
        "classes":      CLASS_NAMES,
    }


@app.get("/model/info")
async def model_info():
    return {**_model_info, "classes": CLASS_NAMES, "input_dim": INPUT_DIM}
