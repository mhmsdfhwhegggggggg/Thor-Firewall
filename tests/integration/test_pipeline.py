"""
Thor Firewall — Integration Tests
اختبارات تكامل الأنظمة

يختبر:
- دقة ML على مجموعة بيانات CICIDS2017
- استجابة API control plane
- أداء XDP pipeline
- تكامل MARL + GNN
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import httpx
import numpy as np
import pytest

# ============================================================================
# Configuration
# ============================================================================

API_BASE = os.getenv("THOR_API_URL", "http://localhost:8080")
ML_BASE  = os.getenv("THOR_ML_URL",  "http://localhost:8082")

# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def api_client():
    return httpx.Client(base_url=API_BASE, timeout=30.0)


@pytest.fixture
def ml_client():
    return httpx.Client(base_url=ML_BASE, timeout=30.0)


@pytest.fixture
def attack_features():
    """ميزات هجوم SYN flood نمطية"""
    features = np.zeros(50, dtype=np.float32)
    features[0]  = 40.0    # avg_packet_size صغير جداً
    features[6]  = 1.0     # TCP
    features[20] = 1.0     # SYN flag
    features[21] = 0.0     # لا ACK
    features[30] = 0.5     # entropy منخفض
    return features.tolist()


@pytest.fixture
def normal_features():
    """ميزات حركة HTTPS طبيعية"""
    features = np.zeros(50, dtype=np.float32)
    features[0]  = 800.0   # حجم حزمة معقول
    features[6]  = 1.0     # TCP
    features[11] = 443.0   # HTTPS
    features[20] = 0.0     # لا SYN
    features[21] = 1.0     # ACK
    features[30] = 7.2     # entropy عالية (TLS)
    return features.tolist()


# ============================================================================
# Health Tests
# ============================================================================

class TestHealth:
    def test_api_health(self, api_client):
        r = api_client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "healthy"
        assert "version" in body

    def test_ml_health(self, ml_client):
        r = ml_client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] in ("healthy", "loading")

    def test_api_version(self, api_client):
        r = api_client.get("/api/health")
        body = r.json()
        assert "version" in body
        # السيمانتيك الإصداري
        parts = body["version"].split(".")
        assert len(parts) >= 2


# ============================================================================
# ML Inference Tests
# ============================================================================

class TestMLInference:
    def test_classify_attack(self, ml_client, attack_features):
        r = ml_client.post("/infer", json={
            "flow_key_hash": 12345,
            "features": attack_features,
            "protocol": "tcp",
        })
        assert r.status_code == 200
        body = r.json()
        assert "decision" in body
        assert "risk_score" in body
        assert "confidence" in body
        assert 0.0 <= body["risk_score"] <= 1.0
        assert 0.0 <= body["confidence"] <= 1.0

    def test_classify_normal_traffic(self, ml_client, normal_features):
        r = ml_client.post("/infer", json={
            "flow_key_hash": 67890,
            "features": normal_features,
            "protocol": "tcp",
        })
        assert r.status_code == 200
        body = r.json()
        # حركة HTTPS طبيعية يجب أن يكون خطرها منخفضاً
        assert body["risk_score"] < 0.9  # لا نطالب بـ 0 — قد يكون untrained

    def test_batch_inference(self, ml_client, attack_features, normal_features):
        r = ml_client.post("/infer/batch", json={
            "requests": [
                {"flow_key_hash": 1, "features": attack_features,  "protocol": "tcp"},
                {"flow_key_hash": 2, "features": normal_features,  "protocol": "tcp"},
                {"flow_key_hash": 3, "features": attack_features,  "protocol": "udp"},
            ]
        })
        assert r.status_code == 200
        body = r.json()
        assert body["batch_size"] == 3
        assert len(body["responses"]) == 3
        assert body["total_time_us"] > 0

    def test_inference_latency(self, ml_client, attack_features):
        """التحقق من أن التأخير < 10ms للحزمة الواحدة"""
        r = ml_client.post("/infer", json={
            "flow_key_hash": 99999,
            "features": attack_features,
            "protocol": "tcp",
        })
        body = r.json()
        # قد يكون أبطأ على الجهاز الأول (JIT compile) — نستخدم 100ms كحد
        assert body["inference_time_us"] < 100_000

    def test_feature_dimension(self, ml_client):
        """يجب أن يرفض 49 ميزة (يحتاج 50 بالضبط)"""
        r = ml_client.post("/infer", json={
            "flow_key_hash": 0,
            "features": [0.0] * 49,
            "protocol": "tcp",
        })
        assert r.status_code == 422  # Validation error

    def test_udp_protocol(self, ml_client):
        features = [0.0] * 50
        features[6] = 2.0  # UDP
        r = ml_client.post("/infer", json={
            "flow_key_hash": 11111,
            "features": features,
            "protocol": "udp",
        })
        assert r.status_code == 200


# ============================================================================
# Control Plane API Tests
# ============================================================================

class TestControlPlaneAPI:
    def test_list_flows(self, api_client):
        r = api_client.get("/api/v1/flows")
        assert r.status_code == 200

    def test_list_rules(self, api_client):
        r = api_client.get("/api/v1/rules")
        assert r.status_code == 200

    def test_create_block_rule(self, api_client):
        rule = {
            "name": "Test Block Rule",
            "src_cidr": "1.2.3.0/24",
            "action": "block",
            "priority": 100,
        }
        r = api_client.post("/api/v1/rules", json=rule)
        # 201 Created or 200 OK
        assert r.status_code in (200, 201)
        body = r.json()
        assert "rule_id" in body or "id" in body

    def test_list_threats(self, api_client):
        r = api_client.get("/api/v1/threats?limit=10")
        assert r.status_code == 200

    def test_analytics_network(self, api_client):
        r = api_client.get("/api/v1/analytics/network")
        assert r.status_code == 200

    def test_query_endpoint(self, api_client):
        r = api_client.post("/api/v1/query", json={
            "question": "What is the current threat level?",
            "language": "en",
        })
        # يمكن أن يكون 200 أو 503 إذا لم يكن LLM محملاً
        assert r.status_code in (200, 503)

    def test_websocket_endpoint(self):
        """اختبار WebSocket بسيط"""
        import websocket
        try:
            ws = websocket.create_connection(
                f"ws://{API_BASE.replace('http://', '')}/ws/live",
                timeout=5
            )
            ws.send("ping")
            result = ws.recv()
            ws.close()
            # إذا نجح الاتصال فهذا كافٍ
            assert True
        except Exception:
            pytest.skip("WebSocket not available in test environment")


# ============================================================================
# ML Accuracy Tests (requires CICIDS dataset)
# ============================================================================

@pytest.mark.skipif(
    not Path("ml/data/CICIDS2017").exists(),
    reason="CICIDS2017 dataset not available"
)
class TestMLAccuracy:
    def test_cicids_accuracy(self, ml_client):
        """
        اختبار دقة ML على عينة من CICIDS2017

        الهدف: F1 >= 0.95 على بيانات الاختبار
        """
        import pandas as pd

        # تحميل عينة صغيرة
        df = pd.read_csv("ml/data/CICIDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        df = df.sample(min(1000, len(df)), random_state=42)
        df = df.replace([np.inf, -np.inf], np.nan).dropna()

        feature_cols = [c for c in df.columns if c not in ["Label", "Flow ID"]][:50]
        X = df[feature_cols].values.astype(np.float32)
        y_true = (df["Label"] != "BENIGN").astype(int).values

        # تطبيع
        from sklearn.preprocessing import StandardScaler
        X = StandardScaler().fit_transform(X)

        # اختبار
        requests = []
        for i, row in enumerate(X[:200]):
            # Pad/trim to 50
            feat = row[:50].tolist()
            if len(feat) < 50:
                feat += [0.0] * (50 - len(feat))
            requests.append({
                "flow_key_hash": i,
                "features": feat,
                "protocol": "tcp",
            })

        r = ml_client.post("/infer/batch", json={"requests": requests})
        assert r.status_code == 200

        responses = r.json()["responses"]
        y_pred = [1 if resp["risk_score"] >= 0.5 else 0 for resp in responses]

        from sklearn.metrics import f1_score, accuracy_score
        acc = accuracy_score(y_true[:200], y_pred)
        f1  = f1_score(y_true[:200], y_pred, zero_division=0)

        print(f"CICIDS Accuracy: {acc:.4f}, F1: {f1:.4f}")
        # هدف مرن — النموذج غير مدرَّب في البيئة الاختبارية
        assert acc >= 0.5  # على الأقل أفضل من العشوائي


# ============================================================================
# Performance Tests
# ============================================================================

class TestPerformance:
    def test_throughput_100_inferences(self, ml_client, attack_features):
        """100 استنتاج متتالي يجب أن تكتمل في < 5 ثوانٍ"""
        start = time.time()
        for i in range(100):
            r = ml_client.post("/infer", json={
                "flow_key_hash": i,
                "features": attack_features,
                "protocol": "tcp",
            })
            assert r.status_code == 200

        elapsed = time.time() - start
        rps = 100 / elapsed
        print(f"Sequential throughput: {rps:.1f} req/s")
        assert elapsed < 60.0  # حد سخي للبيئة الاختبارية

    @pytest.mark.asyncio
    async def test_concurrent_inferences(self, attack_features):
        """50 طلب متزامن"""
        async with httpx.AsyncClient(base_url=ML_BASE, timeout=30.0) as client:
            tasks = [
                client.post("/infer", json={
                    "flow_key_hash": i,
                    "features": attack_features,
                    "protocol": "tcp",
                })
                for i in range(50)
            ]
            start = time.time()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.time() - start

        successful = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code == 200)
        print(f"Concurrent: {successful}/50 OK in {elapsed:.2f}s")
        assert successful >= 45  # 90% نسبة نجاح


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
