"""
Thor Firewall — LLM Security Explainer
نموذج اللغة الكبير لتفسير القرارات الأمنية

يستخدم Mistral-7B أو Llama-3-8B مع LoRA Fine-tuning
على مجموعة ضخمة من تقارير التهديدات ووثائق الهجمات

الوضائف:
1. شرح سبب حظر اتصال معين بلغة طبيعية
2. الإجابة على استفسارات المسؤولين الأمنيين
3. توليد تقارير تهديدات مفصلة
4. RAG من قواعد Threat Intelligence (MISP, CVEs, AlienVault)
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

@dataclass
class LLMConfig:
    """إعدادات نموذج LLM"""
    # عنوان خادم llama.cpp
    server_url: str = "http://localhost:8081"
    # اسم النموذج المستخدم
    model_name: str = "mistral-7b-security-lora"
    # الحد الأقصى للرموز المولّدة
    max_tokens: int = 512
    # درجة الإبداعية (0 = حتمي، 1 = إبداعي)
    temperature: float = 0.1
    # Top-P sampling
    top_p: float = 0.9
    # مهلة الطلب (ثوانٍ)
    timeout: float = 30.0
    # تفعيل RAG
    enable_rag: bool = True
    # مستودع Threat Intelligence
    threat_intel_url: str = "http://localhost:5000/api/threat-intel"
    # اللغة الافتراضية للتفسير
    default_language: str = "ar"  # العربية

# ============================================================================
# Threat Intelligence RAG
# ============================================================================

class ThreatIntelRAG:
    """
    استرجاع معلومات التهديدات ذات الصلة (Retrieval-Augmented Generation)
    يبحث في: MISP، AlienVault OTX، قائمة CVEs
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = httpx.AsyncClient(timeout=10.0)

    async def retrieve_context(
        self,
        src_ip: str,
        dst_port: int,
        protocol: str,
        risk_indicators: List[str],
    ) -> str:
        """
        استرجاع سياق التهديدات ذات الصلة بالحزمة المشبوهة
        """
        context_parts = []

        try:
            # البحث عن IP في قوائم التهديدات
            resp = await self._client.get(
                f"{self.config.threat_intel_url}/lookup/ip/{src_ip}"
            )
            if resp.status_code == 200:
                intel = resp.json()
                if intel.get("is_malicious"):
                    context_parts.append(
                        f"IP {src_ip} معروف في قوائم التهديدات: "
                        f"{', '.join(intel.get('threat_types', []))}"
                    )
                    if intel.get("country"):
                        context_parts.append(f"البلد الأصلي: {intel['country']}")

            # البحث عن CVEs ذات الصلة بالمنفذ
            if dst_port in [22, 23, 3389, 445, 1433]:
                resp = await self._client.get(
                    f"{self.config.threat_intel_url}/cves/port/{dst_port}",
                    params={"limit": 3}
                )
                if resp.status_code == 200:
                    cves = resp.json().get("cves", [])
                    for cve in cves[:2]:
                        context_parts.append(
                            f"CVE ذات صلة: {cve['id']} — {cve['summary'][:100]}"
                        )

        except Exception as e:
            logger.warning(f"RAG retrieval failed: {e}")

        return "\n".join(context_parts) if context_parts else "لا توجد معلومات استخباراتية إضافية"

    async def close(self):
        await self._client.aclose()


# ============================================================================
# LLM Explainer
# ============================================================================

class SecurityExplainer:
    """
    نظام تفسير القرارات الأمنية بلغة طبيعية
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = httpx.AsyncClient(timeout=config.timeout)
        self.rag = ThreatIntelRAG(config) if config.enable_rag else None

        # قوالب المطالبات (Prompts) المعيارية
        self._system_prompt = """أنت محلل أمن سيبراني خبير في نظام Thor Firewall.
مهمتك شرح قرارات النظام الأمني بوضوح ودقة.

عند شرح قرار الحظر:
1. اذكر السبب الرئيسي بجملة واضحة
2. اذكر الأدلة التقنية (بالأرقام إن وجدت)
3. اذكر التوصية للمسؤول الأمني
4. اذكر مستوى الخطورة: منخفض/متوسط/عالٍ/حرج

كن دقيقاً ومختصراً. لا تتجاوز 200 كلمة."""

    async def explain_block_decision(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        risk_score: float,
        risk_indicators: List[str],
        ml_decision: str,
    ) -> str:
        """
        توليد تفسير لقرار حظر اتصال

        Args:
            src_ip: عنوان IP المصدر
            dst_ip: عنوان IP الوجهة
            src_port: منفذ المصدر
            dst_port: منفذ الوجهة
            protocol: البروتوكول
            risk_score: نقاط الخطر [0, 1]
            risk_indicators: قائمة مؤشرات الخطر
            ml_decision: قرار نموذج ML

        Returns:
            التفسير النصي
        """
        # استرجاع سياق التهديدات
        threat_context = ""
        if self.rag:
            threat_context = await self.rag.retrieve_context(
                src_ip, dst_port, protocol, risk_indicators
            )

        # بناء المطالبة
        severity = self._risk_to_severity(risk_score)

        prompt = f"""قرار الحظر التالي صدر من نظام Thor Firewall:

المعلومات التقنية:
- IP المصدر: {src_ip}:{src_port}
- IP الوجهة: {dst_ip}:{dst_port}
- البروتوكول: {protocol.upper()}
- نقاط الخطر: {risk_score:.2%}
- مستوى الخطورة: {severity}
- قرار الذكاء الاصطناعي: {ml_decision}
- مؤشرات الخطر: {', '.join(risk_indicators) if risk_indicators else 'لا يوجد'}

معلومات استخباراتية إضافية:
{threat_context}

اشرح هذا القرار للمسؤول الأمني."""

        return await self._generate(prompt)

    async def explain_suspicious_behavior(
        self,
        ip: str,
        behavior_summary: Dict[str, Any],
    ) -> str:
        """تفسير سلوك مشبوه لجهاز معين"""
        prompt = f"""رصد نظام Thor Firewall سلوكاً مشبوهاً للجهاز {ip}:

إحصاءات السلوك:
{json.dumps(behavior_summary, ensure_ascii=False, indent=2)}

حلّل هذا السلوك وحدد:
1. نوع التهديد المحتمل
2. مستوى الخطورة
3. التوصية الفورية"""

        return await self._generate(prompt)

    async def answer_security_query(self, query: str, context: str = "") -> str:
        """
        الإجابة على استفسار أمني من المسؤول

        Args:
            query: سؤال المسؤول
            context: سياق إضافي (بيانات من لوحة التحكم)
        """
        prompt = f"""استفسار من مسؤول أمن شبكات:

{f'السياق: {context}' if context else ''}

السؤال: {query}

أجب بدقة وإيجاز بناءً على خبرتك في أمن الشبكات."""

        return await self._generate(prompt)

    async def generate_threat_report(
        self,
        time_period: str,
        stats: Dict[str, Any],
        top_threats: List[Dict],
    ) -> str:
        """توليد تقرير تهديدات شامل"""
        prompt = f"""قم بإعداد تقرير تهديدات أمنية للفترة: {time_period}

الإحصاءات الكلية:
{json.dumps(stats, ensure_ascii=False, indent=2)}

أبرز التهديدات:
{json.dumps(top_threats[:5], ensure_ascii=False, indent=2)}

اكتب تقريراً احترافياً يتضمن:
1. ملخص تنفيذي
2. أبرز التهديدات المرصودة
3. التوصيات
4. الإجراءات الفورية المطلوبة"""

        return await self._generate(prompt, max_tokens=1024)

    async def _generate(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        استدعاء نموذج LLM (llama.cpp server أو Ollama)
        """
        try:
            response = await self._client.post(
                f"{self.config.server_url}/v1/chat/completions",
                json={
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": self._system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens or self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "top_p": self.config.top_p,
                },
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()

        except httpx.ConnectError:
            logger.error("LLM server not available, returning fallback explanation")
            return self._fallback_explanation(prompt)
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return f"تعذّر توليد التفسير: {str(e)}"

    def _risk_to_severity(self, risk_score: float) -> str:
        if risk_score >= 0.85:
            return "🔴 حرج"
        elif risk_score >= 0.6:
            return "🟠 عالٍ"
        elif risk_score >= 0.35:
            return "🟡 متوسط"
        else:
            return "🟢 منخفض"

    def _fallback_explanation(self, prompt: str) -> str:
        """تفسير احتياطي عند عدم توفر خادم LLM"""
        return (
            "⚠️ خادم LLM غير متاح حالياً. "
            "القرار صدر بناءً على نموذج الذكاء الاصطناعي MARL "
            "نظراً لتجاوز نقاط الخطر الحد المسموح به. "
            "يُرجى مراجعة السجلات التفصيلية في لوحة التحكم."
        )

    async def close(self):
        await self._client.aclose()
        if self.rag:
            await self.rag.close()
