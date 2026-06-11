#!/usr/bin/env python3
"""
Thor Firewall — ML Inference Server
يُشغّل نموذج MARL (DQN) + GNN ويُجيب على طلبات /predict عبر HTTP
التشغيل: python ml/inference_server.py --port 8082 --device cpu
الإنتاج:  python ml/inference_server.py --port 8082 --model models/thor_marl_best.pt --device cuda
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import numpy as np
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# ── PyTorch (اختياري — يعمل بدونه في وضع القواعد rule-based) ──────────────────
try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("thor.inference")

# ═══════════════════════════════════════════════════════════════════════════════
# 1. تعريف النموذج (DQN بسيط — يُحمّل الأوزان عند توفرها)
# ═══════════════════════════════════════════════════════════════════════════════
FEATURE_DIM   = 20   # يجب أن يتطابق مع FlowFeatures في Rust
ACTION_DIM    = 5    # ALLOW, BLOCK, THROTTLE, INSPECT, RATE_LIMIT
HIDDEN_DIM    = 256

THREAT_CLASSES = [
    "benign", "syn_flood", "udp_flood", "http_flood",
    "port_scan", "brute_force", "sql_injection",
    "xss", "dns_amplification", "slowloris",
]

ACTION_NAMES = ["ALLOW", "BLOCK", "THROTTLE", "INSPECT", "RATE_LIMIT"]


class ThorDQN(nn.Module if HAS_TORCH else object):
    """
    Dueling DQN لاتخاذ قرارات الجدار الناري.
    Architecture: FC → ReLU → FC → ReLU → [Value head | Advantage head]
    """
    def __init__(self):
        if not HAS_TORCH:
            return
        super().__init__()
        self.shared = nn.Sequential(
            nn.Linear(FEATURE_DIM, HIDDEN_DIM),
            nn.ReLU(),
            nn.Linear(HIDDEN_DIM, HIDDEN_DIM),
            nn.ReLU(),
            nn.Linear(HIDDEN_DIM, HIDDEN_DIM // 2),
            nn.ReLU(),
        )
        # Value stream
        self.value_head = nn.Sequential(
            nn.Linear(HIDDEN_DIM // 2, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
        )
        # Advantage stream
        self.advantage_head = nn.Sequential(
            nn.Linear(HIDDEN_DIM // 2, 64),
            nn.ReLU(),
            nn.Linear(64, ACTION_DIM),
        )
        # Threat classifier
        self.threat_head = nn.Sequential(
            nn.Linear(HIDDEN_DIM // 2, 64),
            nn.ReLU(),
            nn.Linear(64, len(THREAT_CLASSES)),
        )

    def forward(self, x):
        shared = self.shared(x)
        value     = self.value_head(shared)
        advantage = self.advantage_head(shared)
        # Dueling: Q = V + A - mean(A)
        q_values  = value + advantage - advantage.mean(dim=-1, keepdim=True)
        threat_logits = self.threat_head(shared)
        return q_values, threat_logits


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ThorInferenceServer — محرك التنبؤ
# ═══════════════════════════════════════════════════════════════════════════════
class ThorInferenceServer:
    """
    يُحمّل النموذج ويُجري التنبؤ.
    إذا لم تكن أوزان مدربة متوفرة → يعمل بوضع rule-based تلقائياً.
    """

    def __init__(self, model_path: Optional[str] = None, device: str = "cpu"):
        self.device = device
        self.model = None
        self.model_version = "rule-based-v1.0"
        self._lock = threading.Lock()

        if HAS_TORCH:
            self.model = ThorDQN()
            if model_path and Path(model_path).exists():
                self._load_weights(model_path)
                self.model.eval()
                logger.info(f"✓ Model loaded from {model_path} on {device}")
            else:
                self.model.eval()
                if model_path:
                    logger.warning(
                        f"Model file not found: {model_path}. "
                        "Running in rule-based mode until training completes."
                    )
                else:
                    logger.info("No model path provided — rule-based mode active.")
        else:
            logger.warning("PyTorch not installed — using pure rule-based mode.")

    def _load_weights(self, path: str):
        checkpoint = torch.load(path, map_location=self.device, weights_only=True)
        # دعم حفظ checkpoint كامل أو state_dict مباشرة
        if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.model_version = checkpoint.get("version", "trained-v1.0")
        else:
            self.model.load_state_dict(checkpoint)
            self.model_version = "trained-v1.0"

    # ── التنبؤ الرئيسي ─────────────────────────────────────────────────────────

    def predict(self, features_batch: list[list[float]]) -> dict:
        """
        الإدخال: قائمة من مصفوفات، كل مصفوفة 20 قيمة عائمة [0.0, 1.0]
        الإخراج: dict مع actions, threat_scores, confidence, threat_classes, q_values
        """
        if not features_batch:
            return {
                "actions": [], "threat_scores": [], "confidence": [],
                "threat_classes": [], "q_values": None,
                "inference_ms": 0, "model_version": self.model_version,
            }

        t0 = time.perf_counter()

        if HAS_TORCH and self.model is not None:
            result = self._neural_predict(features_batch)
        else:
            result = self._rule_based_predict(features_batch)

        result["inference_ms"] = int((time.perf_counter() - t0) * 1000)
        result["model_version"] = self.model_version
        return result

    def _neural_predict(self, features_batch: list[list[float]]) -> dict:
        """تنبؤ بالنموذج العصبي"""
        with self._lock:
            x = torch.tensor(features_batch, dtype=torch.float32)
            with torch.no_grad():
                q_values, threat_logits = self.model(x)

            # اختيار الـ action ذو أعلى Q-value
            actions = q_values.argmax(dim=-1).tolist()
            q_vals_list = q_values.tolist()

            # threat score = max(softmax) * 10
            threat_probs = torch.softmax(threat_logits, dim=-1)
            max_probs, threat_ids = threat_probs.max(dim=-1)
            # score: benign → 0-2، غير benign → 3-10 بحسب الثقة
            threat_scores = []
            for i, (mid, prob) in enumerate(zip(threat_ids.tolist(), max_probs.tolist())):
                if mid == 0:  # benign
                    threat_scores.append(round(prob * 2.0, 2))
                else:
                    threat_scores.append(round(3.0 + prob * 7.0, 2))

            threat_classes = [THREAT_CLASSES[i] for i in threat_ids.tolist()]
            confidence     = max_probs.tolist()

        return {
            "actions":       actions,
            "threat_scores": threat_scores,
            "confidence":    confidence,
            "threat_classes": threat_classes,
            "q_values":      q_vals_list,
        }

    def _rule_based_predict(self, features_batch: list[list[float]]) -> dict:
        """
        وضع rule-based عندما لا يوجد نموذج مدرّب.
        الـ features: [src_ip, dst_ip, src_port, dst_port, proto,
                       pkt_count, byte_count, duration, pkt_rate, byte_rate,
                       flags, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes,
                       iat_mean, iat_std, payload_entropy, window_size, ttl]
        """
        actions, scores, confidence_list, classes = [], [], [], []

        for f in features_batch:
            if len(f) < 20:
                f = f + [0.0] * (20 - len(f))

            pkt_rate      = f[8]    # normalized [0,1]
            byte_rate     = f[9]
            flags         = f[10]   # TCP flags / 255.0
            bwd_pkts      = f[12]
            iat_mean      = f[15]
            entropy       = f[17]
            window_size   = f[18]

            # قاعدة SYN flood: pkt_rate عالي + bwd_pkts منخفض جداً + flags صغير
            syn_flood_score = (pkt_rate * 0.5 + (1 - min(bwd_pkts, 1)) * 0.3
                               + (1 - iat_mean) * 0.2)
            # قاعدة port scan: src_port يتغير كثيراً (نمثّلها بـ entropy عالي)
            port_scan_score = entropy * 0.7 + (1 - window_size) * 0.3
            # قاعدة حركة عادية
            normal_score = (1 - pkt_rate) * 0.4 + iat_mean * 0.3 + window_size * 0.3

            # تحديد أعلى تهديد
            threat_map = {
                "syn_flood":  syn_flood_score,
                "port_scan":  port_scan_score,
                "benign":     normal_score,
            }
            threat_class = max(threat_map, key=threat_map.get)
            raw_score    = threat_map[threat_class]
            conf         = min(0.9, max(0.4, raw_score))

            if threat_class == "benign":
                threat_score = round(raw_score * 2.5, 2)
                action = 0  # ALLOW
            elif threat_class == "syn_flood":
                threat_score = round(3.0 + raw_score * 7.0, 2)
                action = 1 if threat_score >= 7.0 else 2  # BLOCK / THROTTLE
            else:
                threat_score = round(3.0 + raw_score * 6.0, 2)
                action = 3  # INSPECT

            actions.append(action)
            scores.append(min(10.0, threat_score))
            confidence_list.append(round(conf, 4))
            classes.append(threat_class)

        return {
            "actions":       actions,
            "threat_scores": scores,
            "confidence":    confidence_list,
            "threat_classes": classes,
            "q_values":      None,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# 3. HTTP Server
# ═══════════════════════════════════════════════════════════════════════════════
class InferenceHandler(BaseHTTPRequestHandler):
    server_instance: ThorInferenceServer = None

    def log_message(self, format, *args):
        logger.debug(f"{self.address_string()} - {format % args}")

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        if self.path == "/health":
            self._send_json({
                "status": "ok",
                "model_version": self.server_instance.model_version,
                "has_torch": HAS_TORCH,
                "model_loaded": (
                    self.server_instance.model is not None and HAS_TORCH
                ),
                "mode": "neural" if (HAS_TORCH and self.server_instance.model_version != "rule-based-v1.0")
                        else "rule-based",
            })
        elif self.path == "/models":
            self._send_json({
                "models": [self.server_instance.model_version],
                "feature_dim": FEATURE_DIM,
                "action_dim": ACTION_DIM,
                "action_names": ACTION_NAMES,
                "threat_classes": THREAT_CLASSES,
            })
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        if self.path == "/predict":
            try:
                body = self._read_json()
                if not body or "features" not in body:
                    return self._send_json({"error": "Missing 'features' field"}, 400)

                features = body["features"]
                if not isinstance(features, list):
                    return self._send_json({"error": "'features' must be a list"}, 400)

                result = self.server_instance.predict(features)
                self._send_json(result)

            except json.JSONDecodeError as e:
                self._send_json({"error": f"JSON parse error: {e}"}, 400)
            except Exception as e:
                logger.error(f"Prediction error: {e}", exc_info=True)
                self._send_json({"error": str(e)}, 500)
        else:
            self._send_json({"error": "Not found"}, 404)


def make_handler(server_instance: ThorInferenceServer):
    class Handler(InferenceHandler):
        pass
    Handler.server_instance = server_instance
    return Handler


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Entry Point
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Thor Firewall ML Inference Server")
    parser.add_argument("--port",   type=int, default=8082,
                        help="HTTP port to listen on (default: 8082)")
    parser.add_argument("--model",  type=str,
                        default=os.getenv("THOR_MODEL_PATH",
                                          "ml/models/thor_marl_best.pt"),
                        help="Path to trained model (.pt file)")
    parser.add_argument("--device", type=str,
                        default=os.getenv("TORCH_DEVICE", "cpu"),
                        choices=["cpu", "cuda", "mps"],
                        help="Compute device")
    parser.add_argument("--host",   type=str, default="0.0.0.0")
    args = parser.parse_args()

    logger.info("╔══════════════════════════════════════╗")
    logger.info("║   Thor Firewall — Inference Server   ║")
    logger.info(f"║   Port: {args.port:<28} ║")
    logger.info(f"║   Device: {args.device:<27} ║")
    logger.info(f"║   Model: {args.model:<28} ║")
    logger.info("╚══════════════════════════════════════╝")

    server_instance = ThorInferenceServer(
        model_path=args.model,
        device=args.device,
    )
    handler = make_handler(server_instance)
    httpd = HTTPServer((args.host, args.port), handler)
    logger.info(f"Listening on {args.host}:{args.port} ...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down inference server.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
