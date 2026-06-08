"""
Thor Firewall — vLLM LLM Explainer Integration
================================================
يتصل بـ vLLM server (OpenAI-compatible API) لشرح قرارات MARL.

مستوحى من: https://github.com/vllm-project/vllm
مستوحى من: https://github.com/huggingface/text-generation-inference

النموذج: Mistral-7B-Instruct-v0.2 (LoRA fine-tuned على بيانات أمنية)
الهدف: شرح كل قرار BLOCK بالعربية والإنجليزية في < 500ms

يدعم:
  - PagedAttention (vLLM) للكفاءة العالية
  - RAG من MISP + CVE database
  - MITRE ATT&CK mapping
  - Streaming responses عبر WebSocket
"""

from __future__ import annotations

import os
import time
import logging
import asyncio
from typing import AsyncIterator, Dict, List, Optional

import httpx
from pydantic import BaseModel

logger = logging.getLogger("thor.ml.vllm_explainer")

VLLM_BASE_URL = os.getenv("VLLM_URL", "http://vllm:8000/v1")
VLLM_MODEL    = os.getenv("VLLM_MODEL", "mistralai/Mistral-7B-Instruct-v0.2")
MAX_TOKENS    = int(os.getenv("VLLM_MAX_TOKENS", "512"))
TEMPERATURE   = float(os.getenv("VLLM_TEMPERATURE", "0.1"))


# ─────────────────────────────────────────────────────────────────────────────
# Prompt Templates
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """أنت محلل أمني خبير في نظام Thor Firewall.
مهمتك: شرح قرارات الجدار الناري للمحللين الأمنيين (SOC).
كن دقيقاً، موجزاً، وعملياً. أذكر تقنية MITRE ATT&CK إن وجدت.
الرد بالعربية أولاً ثم الإنجليزية."""

EXPLANATION_TEMPLATE = """قرار الجدار الناري:
- القرار: {decision} (risk={risk_score:.2f}, confidence={confidence:.2f})
- المصدر: {src_ip}:{src_port} → {dst_ip}:{dst_port} [{protocol}]
- الإحصاء: {packets} حزمة، {bytes} بايت، {pps:.1f} pps
- entropy الحمولة: {entropy:.3f}
- العوامل الرئيسية: {top_features}
{threat_context}

اشرح هذا القرار بإيجاز (3-4 جمل) مع ذكر:
1. سبب القرار
2. نوع الهجوم المحتمل (إن وجد)
3. التوصية للمحلل"""


# ─────────────────────────────────────────────────────────────────────────────
# vLLM Client
# ─────────────────────────────────────────────────────────────────────────────

class VLLMExplainer:
    """
    يتصل بـ vLLM (OpenAI-compatible API) لتوليد الشروحات.
    
    يستخدم async HTTP client مع connection pooling.
    Fallback إلى template-based explanation إذا كان vLLM غير متاح.
    """

    def __init__(
        self,
        base_url: str = VLLM_BASE_URL,
        model: str = VLLM_MODEL,
        max_tokens: int = MAX_TOKENS,
        temperature: float = TEMPERATURE,
        timeout: float = 10.0,
    ):
        self.base_url   = base_url.rstrip("/")
        self.model      = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
        self._available: Optional[bool] = None  # lazy health check

    async def check_health(self) -> bool:
        """التحقق من توفر vLLM server."""
        try:
            resp = await self._client.get("/health", timeout=2.0)
            self._available = resp.status_code == 200
        except Exception:
            self._available = False
        return self._available

    async def explain_decision(
        self,
        flow_data: Dict,
        rag_context: Optional[str] = None,
    ) -> str:
        """
        يُولّد شرحاً للقرار باستخدام Mistral-7B.
        
        Args:
            flow_data: بيانات التدفق + قرار MARL
            rag_context: معلومات من MISP/CVE (RAG)
            
        Returns:
            str: شرح مفهوم للمحلل الأمني
        """
        if self._available is None:
            await self.check_health()

        if not self._available:
            return self._fallback_explanation(flow_data)

        # Build prompt
        threat_context = f"معلومات التهديد (MISP): {rag_context}" if rag_context else ""
        user_prompt = EXPLANATION_TEMPLATE.format(
            decision=flow_data.get("decision", "block"),
            risk_score=flow_data.get("risk_score", 0.0),
            confidence=flow_data.get("confidence", 0.0),
            src_ip=flow_data.get("src_ip", "?"),
            src_port=flow_data.get("src_port", 0),
            dst_ip=flow_data.get("dst_ip", "?"),
            dst_port=flow_data.get("dst_port", 0),
            protocol=flow_data.get("protocol", "tcp"),
            packets=flow_data.get("packets", 0),
            bytes=flow_data.get("bytes", 0),
            pps=flow_data.get("pps", 0.0),
            entropy=flow_data.get("payload_entropy", 0.0),
            top_features=flow_data.get("top_features", "N/A"),
            threat_context=threat_context,
        )

        try:
            start = time.perf_counter_ns()
            resp = await self._client.post(
                "/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": user_prompt},
                    ],
                    "max_tokens":  self.max_tokens,
                    "temperature": self.temperature,
                    "stream":      False,
                },
            )
            resp.raise_for_status()
            elapsed_ms = (time.perf_counter_ns() - start) / 1e6

            data    = resp.json()
            content = data["choices"][0]["message"]["content"]
            logger.info(f"LLM explanation in {elapsed_ms:.1f}ms")
            return content

        except Exception as e:
            logger.warning(f"vLLM unavailable: {e}. Using fallback.")
            self._available = False
            return self._fallback_explanation(flow_data)

    async def stream_explanation(
        self,
        flow_data: Dict,
        rag_context: Optional[str] = None,
    ) -> AsyncIterator[str]:
        """يبث الشرح token بـ token (للـ WebSocket)."""
        if not self._available:
            yield self._fallback_explanation(flow_data)
            return

        threat_context = f"معلومات التهديد: {rag_context}" if rag_context else ""
        user_prompt = EXPLANATION_TEMPLATE.format(**{
            **flow_data,
            "threat_context": threat_context,
            "top_features": flow_data.get("top_features", "N/A"),
        })

        async with self._client.stream(
            "POST",
            "/chat/completions",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                "max_tokens":  self.max_tokens,
                "temperature": self.temperature,
                "stream":      True,
            },
        ) as response:
            async for line in response.aiter_lines():
                if line.startswith("data: ") and not line.endswith("[DONE]"):
                    try:
                        import json
                        data = json.loads(line[6:])
                        token = data["choices"][0]["delta"].get("content", "")
                        if token:
                            yield token
                    except Exception:
                        continue

    def _fallback_explanation(self, flow_data: Dict) -> str:
        """شرح قالبي عندما يكون vLLM غير متاح."""
        decision  = flow_data.get("decision", "block")
        risk      = flow_data.get("risk_score", 0.0)
        src_ip    = flow_data.get("src_ip", "?")
        dst_port  = flow_data.get("dst_port", 0)
        entropy   = flow_data.get("payload_entropy", 0.0)

        reasons = []
        if risk > 0.8:  reasons.append("درجة خطورة عالية")
        if entropy > 0.9: reasons.append("entropy مرتفعة (محتوى مشفر/مضغوط)")
        if dst_port in [22, 23, 3389, 445]: reasons.append(f"منفذ حساس ({dst_port})")

        reason_str = "، ".join(reasons) if reasons else "نشاط غير اعتيادي"

        return (
            f"🚫 قرار {decision.upper()} للتدفق من {src_ip} — {reason_str}. "
            f"درجة الخطورة: {risk:.2f}. "
            f"يُنصح المحلل بالتحقق من سجلات الجهاز المصدر وفحص حركة المرور المشابهة.\n\n"
            f"[EN] {decision.upper()} decision for flow from {src_ip} — {reason_str}. "
            f"Risk: {risk:.2f}. Analyst should review source host logs."
        )

    async def close(self) -> None:
        await self._client.aclose()


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_explainer: Optional[VLLMExplainer] = None

def get_explainer() -> VLLMExplainer:
    global _explainer
    if _explainer is None:
        _explainer = VLLMExplainer()
    return _explainer
