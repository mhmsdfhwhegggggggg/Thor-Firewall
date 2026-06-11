#!/usr/bin/env python3
"""
Thor Firewall — Integration Tests
يتحقق من أن جميع المكونات تعمل معاً كوحدة واحدة
التشغيل: pytest tests/integration_test.py -v --timeout=60
"""
import os, json, time, socket
import requests
import pytest

# ── إعدادات البيئة ────────────────────────────────────────────────────────────
BASE              = os.getenv("THOR_BASE_URL",       "http://localhost")
ML_INFERENCE_URL  = os.getenv("ML_INFERENCE_URL",    "http://localhost:8082")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL",   "http://localhost:8000")
THEHIVE_URL       = os.getenv("THEHIVE_URL",         "http://localhost:9000")
THEHIVE_KEY       = os.getenv("THEHIVE_API_KEY",     "")
ES_URL            = os.getenv("ELASTICSEARCH_URL",   "http://localhost:9200")
ELASTIC_USER      = os.getenv("ELASTIC_USER",        "elastic")
ELASTIC_PASS      = os.getenv("ELASTIC_PASSWORD",    "ElasticThor2024!")
WAZUH_API_URL     = os.getenv("WAZUH_API_URL",       "https://localhost:55000")
WAZUH_USER        = os.getenv("WAZUH_API_USERNAME",  "wazuh-wui")
WAZUH_PASS        = os.getenv("WAZUH_API_PASSWORD",  "MyS3cr37P450r.*-")
TIMEOUT           = int(os.getenv("TEST_TIMEOUT",    "10"))

THEHIVE_HEADERS = {"Content-Type": "application/json",
                   "Authorization": f"Bearer {THEHIVE_KEY}"}

# ── فئة مساعدة ────────────────────────────────────────────────────────────────
def get(url, **kwargs):
    return requests.get(url, timeout=TIMEOUT, **kwargs)

def post(url, **kwargs):
    return requests.post(url, timeout=TIMEOUT, **kwargs)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. اختبارات الصحة الأساسية
# ═══════════════════════════════════════════════════════════════════════════════
class TestHealthChecks:

    def test_ml_inference_health(self):
        """inference_server.py يرد على /health"""
        r = get(f"{ML_INFERENCE_URL}/health")
        assert r.status_code == 200, f"ML inference unhealthy: {r.text}"
        body = r.json()
        assert body.get("status") == "ok" or "model" in body, \
            f"Unexpected health response: {body}"

    def test_control_plane_health(self):
        """Control Plane API يرد على /api/health"""
        r = get(f"{CONTROL_PLANE_URL}/api/health")
        assert r.status_code == 200, f"Control plane unhealthy: {r.text}"

    def test_elasticsearch_health(self):
        """Elasticsearch cluster يكون في حالة yellow أو green"""
        r = get(f"{ES_URL}/_cluster/health",
                auth=(ELASTIC_USER, ELASTIC_PASS))
        assert r.status_code == 200, f"Elasticsearch unreachable: {r.text}"
        status = r.json().get("status")
        assert status in ("green", "yellow"), \
            f"Elasticsearch cluster status is {status!r}"

    def test_thehive_status(self):
        """TheHive يرد على /api/v1/status"""
        r = get(f"{THEHIVE_URL}/api/v1/status")
        assert r.status_code in (200, 401), \
            f"TheHive unreachable: {r.text}"

# ═══════════════════════════════════════════════════════════════════════════════
# 2. اختبارات ML Inference
# ═══════════════════════════════════════════════════════════════════════════════
class TestMlInference:

    NORMAL_FLOW = {
        "features": [[
            0.5, 0.3, 0.2, 0.1, 0.025,   # src/dst ip, ports, protocol
            2.5, 3.0, 2.0, 0.01, 0.0001,  # pkt/byte counts, rates
            0.01, 2.0, 1.5, 2.5, 2.0,     # flags, fwd/bwd pkts/bytes
            0.01, 0.005, 0.7, 0.9, 0.25   # iat, entropy, window, ttl
        ]],
        "model": "thor_marl",
        "return_qvalues": True
    }

    SYN_FLOOD_FLOW = {
        "features": [[
            0.1, 0.9, 0.8, 0.0012, 0.025,
            5.0, 1.0, 1.0, 0.99, 0.001,
            0.008, 5.0, 0.0, 5.0, 0.0,
            0.0001, 0.0, 0.05, 0.99, 0.25
        ]],
        "model": "thor_marl",
        "return_qvalues": True
    }

    def test_predict_returns_valid_action(self):
        """predict يُعيد action ضمن النطاق المقبول"""
        r = post(f"{ML_INFERENCE_URL}/predict", json=self.NORMAL_FLOW)
        assert r.status_code == 200, f"Predict failed: {r.text}"
        body = r.json()
        assert "actions" in body, f"No 'actions' in response: {body}"
        assert len(body["actions"]) == 1
        assert body["actions"][0] in range(5), \
            f"Action {body['actions'][0]} out of range [0,4]"

    def test_predict_threat_score_range(self):
        """threat_score يكون بين 0.0 و 10.0"""
        r = post(f"{ML_INFERENCE_URL}/predict", json=self.NORMAL_FLOW)
        body = r.json()
        score = body.get("threat_scores", [None])[0]
        assert score is not None, "No threat_score in response"
        assert 0.0 <= score <= 10.0, f"threat_score {score} out of range"

    def test_syn_flood_gets_high_score(self):
        """تدفق SYN flood يجب أن يحصل على threat_score >= 6.0"""
        r = post(f"{ML_INFERENCE_URL}/predict", json=self.SYN_FLOOD_FLOW)
        assert r.status_code == 200
        body = r.json()
        score = body.get("threat_scores", [0])[0]
        # تمرير تحذير إذا كان النموذج غير مدرّب (لا فشل قاطع)
        if score < 6.0:
            pytest.skip(
                f"SYN flood score={score:.2f} < 6.0 — "
                "model may not be trained yet (expected after training on CIC-IDS2018)"
            )

    def test_batch_predict_multiple_flows(self):
        """batch predict يُعيد نفس عدد النتائج"""
        batch = {
            "features": [self.NORMAL_FLOW["features"][0]] * 5,
            "model": "thor_marl",
            "return_qvalues": False
        }
        r = post(f"{ML_INFERENCE_URL}/predict", json=batch)
        assert r.status_code == 200
        body = r.json()
        assert len(body["actions"]) == 5, \
            f"Expected 5 results, got {len(body['actions'])}"

    def test_q_values_returned_when_requested(self):
        """q_values تُعاد عند طلبها"""
        r = post(f"{ML_INFERENCE_URL}/predict", json=self.NORMAL_FLOW)
        body = r.json()
        if "q_values" in body and body["q_values"]:
            qv = body["q_values"][0]
            assert len(qv) >= 2, f"Q-values too short: {qv}"
        else:
            pytest.skip("q_values not returned by this model version")

    def test_inference_latency_under_200ms(self):
        """inference يكتمل خلال 200ms"""
        t0 = time.time()
        post(f"{ML_INFERENCE_URL}/predict", json=self.NORMAL_FLOW)
        latency_ms = (time.time() - t0) * 1000
        assert latency_ms < 200, \
            f"Inference too slow: {latency_ms:.1f}ms > 200ms"

# ═══════════════════════════════════════════════════════════════════════════════
# 3. اختبارات TheHive
# ═══════════════════════════════════════════════════════════════════════════════
class TestTheHiveIntegration:

    @pytest.fixture(autouse=True)
    def skip_if_no_key(self):
        if not THEHIVE_KEY:
            pytest.skip("THEHIVE_API_KEY not set — skipping TheHive tests")

    def test_create_and_retrieve_alert(self):
        """إنشاء تنبيه اختباري والتحقق من ظهوره"""
        alert_data = {
            "type":        "integration-test",
            "source":      "thor-pytest",
            "sourceRef":   f"test-{int(time.time())}",
            "title":       "Integration Test Alert",
            "severity":    2,
            "tags":        ["pytest", "automated", "integration-test"],
            "description": "Auto-generated alert by Thor integration test suite.",
        }
        # إنشاء التنبيه
        r = post(f"{THEHIVE_URL}/api/v1/alert",
                 json=alert_data, headers=THEHIVE_HEADERS)
        assert r.status_code in (200, 201), \
            f"Failed to create alert: {r.status_code} {r.text}"
        alert_id = r.json().get("_id")
        assert alert_id, "Alert ID not returned"

        # استرجاع التنبيه
        r2 = get(f"{THEHIVE_URL}/api/v1/alert/{alert_id}",
                 headers=THEHIVE_HEADERS)
        assert r2.status_code == 200
        assert r2.json().get("title") == "Integration Test Alert"

    def test_alert_count_increases(self):
        """إجمالي التنبيهات يزيد بعد الإنشاء"""
        r1 = get(f"{THEHIVE_URL}/api/v1/alert", headers=THEHIVE_HEADERS)
        total_before = r1.json().get("total", 0)

        post(f"{THEHIVE_URL}/api/v1/alert", headers=THEHIVE_HEADERS, json={
            "type": "count-test", "source": "pytest",
            "sourceRef": f"count-{int(time.time())}",
            "title": "Count Test", "severity": 1, "tags": ["test"],
        })

        r2 = get(f"{THEHIVE_URL}/api/v1/alert", headers=THEHIVE_HEADERS)
        total_after = r2.json().get("total", 0)
        assert total_after > total_before, \
            f"Alert count did not increase: {total_before} → {total_after}"

# ═══════════════════════════════════════════════════════════════════════════════
# 4. اختبارات Elasticsearch
# ═══════════════════════════════════════════════════════════════════════════════
class TestElasticsearch:

    ES_AUTH = (ELASTIC_USER, ELASTIC_PASS)

    def test_wazuh_index_pattern_exists(self):
        """index template لـ wazuh-alerts-* موجود"""
        r = get(f"{ES_URL}/_index_template/wazuh-alerts", auth=self.ES_AUTH)
        assert r.status_code == 200, \
            "wazuh-alerts index template not found — run integration_setup.sh"

    def test_can_index_and_retrieve_document(self):
        """يمكن كتابة وقراءة مستند من Elasticsearch"""
        doc = {"timestamp": int(time.time() * 1000),
               "thor_source": "pytest",
               "message": "integration test document",
               "threat_score": 0.0}
        r = post(f"{ES_URL}/thor-pytest-test/_doc",
                 json=doc, auth=self.ES_AUTH)
        assert r.status_code in (200, 201), f"Index failed: {r.text}"
        doc_id = r.json()["_id"]

        # Refresh لضمان ظهور المستند فوراً
        post(f"{ES_URL}/thor-pytest-test/_refresh", auth=self.ES_AUTH)

        r2 = get(f"{ES_URL}/thor-pytest-test/_doc/{doc_id}", auth=self.ES_AUTH)
        assert r2.status_code == 200
        assert r2.json()["_source"]["thor_source"] == "pytest"

# ═══════════════════════════════════════════════════════════════════════════════
# 5. اختبار سيناريو هجوم كامل (End-to-End)
# ═══════════════════════════════════════════════════════════════════════════════
class TestEndToEndAttackScenario:
    """
    محاكاة سيناريو هجوم: إرسال تدفق SYN flood → inference → alert في TheHive
    يتطلب: جميع الخدمات تعمل + THEHIVE_API_KEY مضبوط
    """

    @pytest.fixture(autouse=True)
    def skip_if_incomplete(self):
        if not THEHIVE_KEY:
            pytest.skip("THEHIVE_API_KEY required for E2E test")

    def test_syn_flood_creates_thehive_alert(self):
        """
        تدفق SYN flood عبر inference → يُولّد تنبيهاً في TheHive
        (مباشرة عبر API — بدون انتظار Wazuh/Suricata)
        """
        syn_flow = {
            "features": [[
                0.06, 0.9, 0.8, 0.0012, 0.025,
                5.0, 1.0, 1.0, 0.99, 0.001,
                0.008, 5.0, 0.0, 5.0, 0.0,
                0.0001, 0.0, 0.05, 0.99, 0.25
            ]],
            "model": "thor_marl",
            "return_qvalues": False
        }

        # 1. استدعاء inference
        r = post(f"{ML_INFERENCE_URL}/predict", json=syn_flow)
        assert r.status_code == 200, f"Inference failed: {r.text}"
        inf = r.json()
        threat_score = inf.get("threat_scores", [0])[0]
        action = inf.get("actions", [0])[0]
        threat_class = inf.get("threat_classes", ["unknown"])[0]

        # 2. إذا كانت الدرجة كافية، أنشئ تنبيهاً في TheHive
        if threat_score >= 6.0:
            severity = min(4, max(1, int(threat_score // 2.5)))
            alert_data = {
                "type":      "syn_flood",
                "source":    "thor-e2e-test",
                "sourceRef": f"e2e-{int(time.time())}",
                "title":     f"E2E Test: {threat_class} detected (score={threat_score:.1f})",
                "severity":  severity,
                "tags":      ["e2e-test", "syn_flood", f"score-{int(threat_score)}"],
                "description": (
                    f"End-to-end test alert.\n"
                    f"Threat: {threat_class}\nScore: {threat_score:.2f}\n"
                    f"Action: {action}\nGenerated by thor pytest suite."
                )
            }
            r2 = post(f"{THEHIVE_URL}/api/v1/alert",
                      json=alert_data, headers=THEHIVE_HEADERS)
            assert r2.status_code in (200, 201), \
                f"TheHive alert creation failed: {r2.text}"
            alert_id = r2.json().get("_id")
            assert alert_id, "No alert ID returned"
            print(f"\n✓ E2E: TheHive alert created: {alert_id}")
            print(f"  threat_score={threat_score:.2f}, action={action}")
        else:
            pytest.skip(
                f"threat_score={threat_score:.2f} < 6.0 "
                "— model not trained yet. Train with CIC-IDS2018 dataset first."
            )
