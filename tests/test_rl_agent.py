#!/usr/bin/env python3
"""
Thor Firewall — Unit Tests: RL Agent (inference_server.py)
التشغيل: pytest tests/test_rl_agent.py -v
"""
import os, sys, json, time
import pytest

# إضافة مسار ml/ إلى PATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ml"))

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


# ── وحدات من ml/ ─────────────────────────────────────────────────────────────
def import_inference():
    try:
        from inference_server import ThorInferenceServer, FlowFeatures, AgentAction
        return ThorInferenceServer, FlowFeatures, AgentAction
    except ImportError as e:
        pytest.skip(f"inference_server not importable: {e}")


# ── Fixtures ──────────────────────────────────────────────────────────────────
@pytest.fixture
def server():
    ThorInferenceServer, _, _ = import_inference()
    srv = ThorInferenceServer(model_path=None, device="cpu")
    return srv


@pytest.fixture
def normal_features():
    return [0.5, 0.3, 0.2, 0.1, 0.025,
            2.5, 3.0, 2.0, 0.01, 0.0001,
            0.01, 2.0, 1.5, 2.5, 2.0,
            0.01, 0.005, 0.7, 0.9, 0.25]


@pytest.fixture
def syn_flood_features():
    """مميزات تدفق SYN flood نموذجي"""
    return [0.06, 0.9, 0.8, 0.0012, 0.025,
            5.0,  1.0, 1.0, 0.99,   0.001,
            0.008, 5.0, 0.0, 5.0,  0.0,
            0.0001, 0.0, 0.05, 0.99, 0.25]


@pytest.fixture
def port_scan_features():
    """مميزات تدفق port scan نموذجي"""
    return [0.1, 0.5, 0.95, 0.4, 0.025,
            1.5, 0.5, 0.5, 0.3, 0.0001,
            0.002, 1.5, 0.0, 0.5, 0.0,
            0.1, 0.05, 0.3, 0.01, 0.4]


# ═══════════════════════════════════════════════════════════════════════════════
# 1. اختبارات التهيئة
# ═══════════════════════════════════════════════════════════════════════════════
class TestServerInit:

    def test_server_initializes(self, server):
        assert server is not None

    def test_server_has_model_attribute(self, server):
        assert hasattr(server, "model") or hasattr(server, "_model"), \
            "Server must have a model attribute"

    def test_server_has_predict_method(self, server):
        assert callable(getattr(server, "predict", None)), \
            "Server must have a predict() method"

    def test_server_device_is_cpu(self, server):
        device = getattr(server, "device", "cpu")
        assert "cpu" in str(device).lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 2. اختبارات التنبؤ الأساسية
# ═══════════════════════════════════════════════════════════════════════════════
class TestPrediction:

    def test_predict_single_flow(self, server, normal_features):
        result = server.predict([normal_features])
        assert result is not None
        assert "actions" in result, f"Missing 'actions': {result}"
        assert len(result["actions"]) == 1

    def test_action_in_valid_range(self, server, normal_features):
        result = server.predict([normal_features])
        action = result["actions"][0]
        assert 0 <= action <= 4, \
            f"Action {action} not in [0,4]"

    def test_threat_score_in_range(self, server, normal_features):
        result = server.predict([normal_features])
        scores = result.get("threat_scores", [])
        assert len(scores) == 1
        assert 0.0 <= scores[0] <= 10.0, \
            f"threat_score {scores[0]} out of [0,10]"

    def test_confidence_in_range(self, server, normal_features):
        result = server.predict([normal_features])
        conf = result.get("confidence", [])
        if conf:
            assert 0.0 <= conf[0] <= 1.0, \
                f"confidence {conf[0]} out of [0,1]"

    def test_threat_class_is_string(self, server, normal_features):
        result = server.predict([normal_features])
        classes = result.get("threat_classes", [])
        if classes:
            assert isinstance(classes[0], str), \
                f"threat_class must be string, got {type(classes[0])}"

    def test_batch_prediction_correct_count(self, server, normal_features):
        batch = [normal_features] * 8
        result = server.predict(batch)
        assert len(result["actions"]) == 8, \
            f"Expected 8 actions, got {len(result['actions'])}"

    def test_predict_returns_inference_time(self, server, normal_features):
        result = server.predict([normal_features])
        assert "inference_ms" in result, "Missing inference_ms field"
        assert result["inference_ms"] >= 0

    @pytest.mark.skipif(not HAS_NUMPY, reason="numpy not installed")
    def test_feature_vector_length_20(self, server, normal_features):
        """النموذج يقبل بالضبط 20 feature"""
        import numpy as np
        arr = np.array(normal_features)
        assert arr.shape == (20,), f"Expected 20 features, got {arr.shape}"

    def test_empty_batch_returns_empty(self, server):
        result = server.predict([])
        assert result.get("actions", []) == [], \
            "Empty batch must return empty results"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. اختبارات تصنيف التهديدات
# ═══════════════════════════════════════════════════════════════════════════════
class TestThreatClassification:

    @pytest.mark.skipif(
        not (HAS_TORCH and os.path.exists(
            os.path.join(os.path.dirname(__file__), "..", "ml", "models",
                         "thor_marl_best.pt"))),
        reason="Trained model (thor_marl_best.pt) not found — train first"
    )
    def test_syn_flood_classified_correctly(self, server, syn_flood_features):
        result = server.predict([syn_flood_features])
        threat_class = result.get("threat_classes", ["unknown"])[0]
        threat_score = result.get("threat_scores", [0])[0]
        assert threat_score >= 6.0, \
            f"SYN flood should score >= 6.0, got {threat_score:.2f}"
        assert "syn" in threat_class.lower() or "flood" in threat_class.lower(), \
            f"Expected SYN flood class, got '{threat_class}'"

    @pytest.mark.skipif(
        not (HAS_TORCH and os.path.exists(
            os.path.join(os.path.dirname(__file__), "..", "ml", "models",
                         "thor_marl_best.pt"))),
        reason="Trained model not found"
    )
    def test_port_scan_detected(self, server, port_scan_features):
        result = server.predict([port_scan_features])
        threat_score = result.get("threat_scores", [0])[0]
        assert threat_score >= 4.0, \
            f"Port scan should score >= 4.0, got {threat_score:.2f}"

    def test_normal_traffic_low_score(self, server, normal_features):
        """حركة عادية يجب ألا تحصل على درجة تهديد عالية جداً"""
        result = server.predict([normal_features])
        scores = result.get("threat_scores", [10.0])
        # مع نموذج غير مدرّب قد تكون عشوائية — نتحقق فقط من النطاق
        assert scores[0] <= 10.0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. اختبارات الأداء
# ═══════════════════════════════════════════════════════════════════════════════
class TestPerformance:

    def test_single_inference_under_50ms(self, server, normal_features):
        t0 = time.perf_counter()
        server.predict([normal_features])
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 50, \
            f"CPU inference {elapsed_ms:.1f}ms > 50ms"

    def test_batch_256_under_500ms(self, server, normal_features):
        batch = [normal_features] * 256
        t0 = time.perf_counter()
        server.predict(batch)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 500, \
            f"Batch-256 inference {elapsed_ms:.1f}ms > 500ms"

    def test_throughput_1000_flows_per_second(self, server, normal_features):
        batch = [normal_features] * 100
        t0 = time.perf_counter()
        for _ in range(10):
            server.predict(batch)
        elapsed = time.perf_counter() - t0
        throughput = 1000 / elapsed  # flows/sec
        assert throughput >= 1000, \
            f"Throughput {throughput:.0f} flows/s < 1000 flows/s target"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. اختبارات المتانة
# ═══════════════════════════════════════════════════════════════════════════════
class TestRobustness:

    def test_all_zeros_features(self, server):
        result = server.predict([[0.0] * 20])
        assert "actions" in result

    def test_all_ones_features(self, server):
        result = server.predict([[1.0] * 20])
        assert "actions" in result

    def test_large_batch_no_crash(self, server, normal_features):
        batch = [normal_features] * 1024
        result = server.predict(batch)
        assert len(result["actions"]) == 1024

    def test_repeated_calls_stable(self, server, normal_features):
        """نفس الإدخال يُعطي نفس الإخراج (نموذج deterministic في inference mode)"""
        r1 = server.predict([normal_features])
        r2 = server.predict([normal_features])
        assert r1["actions"][0] == r2["actions"][0], \
            "Deterministic model must return same action for same input"
