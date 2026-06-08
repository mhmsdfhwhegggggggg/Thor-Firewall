"""
Thor Firewall — AI Security Query Route  (Production-Complete)
تحليل الأسئلة الأمنية بواسطة LLM + RAG

التغييرات عن النسخة السابقة:
  ✅ لا DEMO_ANSWERS — كل الإجابات من LLM أو بيانات حقيقية
  ✅ RAG حقيقي: يسحب بيانات من Redis (flows, threats, stats) قبل السؤال
  ✅ Ollama REST API أولاً (Mistral-7B)، fallback Groq Cloud، fallback local context
  ✅ Context builder: يُنشئ سياقاً من حالة الشبكة الفعلية
  ✅ Streaming support (SSE)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import AsyncGenerator, Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger("thor.query")

LLM_SERVER_URL = os.environ.get("LLM_SERVER_URL", "http://localhost:11434")  # Ollama
LLM_MODEL      = os.environ.get("LLM_MODEL", "mistral:7b-instruct-q4_K_M")
GROQ_API_KEY   = os.environ.get("GROQ_API_KEY", "")

_ollama_ok: Optional[bool] = None


class SecurityQuery(BaseModel):
    question: str = Field(..., min_length=3, max_length=2000)
    context: Optional[str] = None
    max_tokens: int = Field(512, ge=64, le=4096)
    stream: bool = False


class SecurityQueryResponse(BaseModel):
    answer: str
    model: str
    latency_ms: float
    context_used: Optional[str] = None
    data_sources: list[str] = []


# ============================================================================
# Context Builder — RAG from Real Data
# ============================================================================

async def _build_network_context(request: Request) -> dict:
    """
    يبني سياقاً حقيقياً من الشبكة:
    - أحدث التهديدات من Redis
    - إحصاءات اللحظة
    - أكثر IPs خطورة
    """
    context_parts = {}
    sources = []

    try:
        redis = request.app.state.redis

        # إحصاءات الشبكة الحالية
        stats_raw = await redis.hgetall("thor:stats:current")
        if stats_raw:
            context_parts["network_stats"] = stats_raw
            sources.append("redis:stats")

        # آخر 10 تهديدات
        recent_threats = await redis.lrange("thor:threats:recent", 0, 9)
        if recent_threats:
            threats_parsed = []
            for t in recent_threats:
                try:
                    threats_parsed.append(json.loads(t))
                except Exception:
                    pass
            context_parts["recent_threats"] = threats_parsed
            sources.append("redis:threats")

        # أكثر IPs خطورة (من sorted set)
        top_ips = await redis.zrevrangebyscore(
            "thor:ip_risk_scores", "+inf", "0.5",
            start=0, num=10, withscores=True,
        )
        if top_ips:
            context_parts["top_malicious_ips"] = [
                {"ip": ip, "risk_score": float(score)}
                for ip, score in top_ips
            ]
            sources.append("redis:ip_scores")

        # بيانات BPF counters
        bpf_stats = await redis.hgetall("thor:bpf:counters")
        if bpf_stats:
            context_parts["bpf_counters"] = bpf_stats
            sources.append("redis:bpf")

        # عدد القواعد النشطة
        rule_count = await redis.scard("thor:rules:active")
        context_parts["active_rules"] = rule_count
        sources.append("redis:rules")

    except Exception as e:
        logger.debug("Redis context fetch error: %s", e)

    return {"data": context_parts, "sources": sources}


def _format_context_for_llm(ctx: dict) -> str:
    """تحويل البيانات الخام إلى نص منسَّق للـ LLM prompt"""
    parts = ["## Current Thor Firewall Network Status\n"]
    data = ctx.get("data", {})

    if stats := data.get("network_stats"):
        pps = stats.get("packets_per_second", "N/A")
        flows = stats.get("active_flows", "N/A")
        blocked = stats.get("blocked_total", "N/A")
        parts.append(f"**Traffic:** {pps} pps | {flows} active flows | {blocked} blocked total\n")

    if bpf := data.get("bpf_counters"):
        xdp_pass = bpf.get("xdp_pass", 0)
        xdp_drop = bpf.get("xdp_drop", 0)
        parts.append(f"**eBPF:** {xdp_pass} passed | {xdp_drop} dropped at XDP layer\n")

    if threats := data.get("recent_threats"):
        parts.append("**Recent Threats (last 10):**\n")
        for t in threats[:5]:
            src = t.get("src_ip", "?")
            typ = t.get("threat_type", "unknown")
            score = t.get("risk_score", 0)
            parts.append(f"  - {src} → {typ} (risk={score:.2f})\n")

    if ips := data.get("top_malicious_ips"):
        parts.append("**Top Malicious IPs:**\n")
        for item in ips[:5]:
            parts.append(f"  - {item['ip']} (score={item['risk_score']:.2f})\n")

    if not parts[1:]:
        parts.append("*No live data available — Redis may be empty*\n")

    return "".join(parts)


# ============================================================================
# LLM Backends
# ============================================================================

async def _check_ollama() -> bool:
    global _ollama_ok
    if _ollama_ok is not None:
        return _ollama_ok
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            r = await c.get(f"{LLM_SERVER_URL}/api/tags")
            _ollama_ok = r.status_code == 200
    except Exception:
        _ollama_ok = False
    return _ollama_ok


async def _query_ollama(prompt: str, max_tokens: int) -> Optional[str]:
    """Ollama REST API — يعمل محلياً مع Mistral-7B"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as c:
            resp = await c.post(
                f"{LLM_SERVER_URL}/api/generate",
                json={
                    "model": LLM_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": max_tokens,
                        "temperature": 0.4,
                        "top_p": 0.9,
                        "stop": ["</s>", "[INST]", "User:", "Human:"],
                    },
                },
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
    except Exception as e:
        logger.debug("Ollama query failed: %s", e)
    return None


async def _stream_ollama(prompt: str, max_tokens: int) -> AsyncGenerator[str, None]:
    """Ollama streaming"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as c:
            async with c.stream(
                "POST",
                f"{LLM_SERVER_URL}/api/generate",
                json={
                    "model": LLM_MODEL,
                    "prompt": prompt,
                    "stream": True,
                    "options": {"num_predict": max_tokens, "temperature": 0.4},
                },
            ) as resp:
                async for line in resp.aiter_lines():
                    if line:
                        try:
                            chunk = json.loads(line)
                            token = chunk.get("response", "")
                            if token:
                                yield f"data: {json.dumps({'token': token})}\n\n"
                            if chunk.get("done"):
                                yield "data: [DONE]\n\n"
                                break
                        except json.JSONDecodeError:
                            pass
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"


async def _query_groq(prompt: str, max_tokens: int) -> Optional[str]:
    """Groq Cloud API — fallback عند غياب Ollama"""
    if not GROQ_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=30.0) as c:
            resp = await c.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
                json={
                    "model": "mixtral-8x7b-32768",
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are Thor Firewall's AI security analyst. "
                                "Answer concisely in Markdown. Use real data provided."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.4,
                },
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.debug("Groq query failed: %s", e)
    return None


def _context_aware_fallback(question: str, network_ctx: dict) -> str:
    """
    Fallback إذا لم يتوفر أي LLM — يبني إجابة من البيانات الحقيقية.
    أفضل بكثير من DEMO_ANSWERS الثابتة.
    """
    data = network_ctx.get("data", {})
    q = question.lower()
    lines = []

    # محاولة الإجابة بناءً على السؤال + البيانات الحقيقية
    if any(w in q for w in ("threat", "attack", "malicious", "تهديد", "هجوم")):
        threats = data.get("recent_threats", [])
        ips = data.get("top_malicious_ips", [])
        if threats:
            lines.append("**Recent Threats Detected:**\n")
            for t in threats[:5]:
                lines.append(
                    f"- `{t.get('src_ip', '?')}` — {t.get('threat_type', 'unknown')} "
                    f"(risk={float(t.get('risk_score', 0)):.2%})\n"
                )
        if ips:
            lines.append("\n**Top Risk IPs:**\n")
            for item in ips[:5]:
                lines.append(f"- `{item['ip']}` score={item['risk_score']:.2%}\n")
        if not threats and not ips:
            lines.append("No active threats in the current Redis data. System appears clean.\n")

    elif any(w in q for w in ("stat", "traffic", "flow", "pps", "إحصاء", "حركة")):
        stats = data.get("network_stats", {})
        bpf = data.get("bpf_counters", {})
        if stats:
            lines.append("**Current Network Statistics:**\n")
            for k, v in stats.items():
                lines.append(f"- {k}: {v}\n")
        if bpf:
            lines.append("\n**eBPF Counters:**\n")
            for k, v in bpf.items():
                lines.append(f"- {k}: {v}\n")
        if not stats and not bpf:
            lines.append("No live statistics available in Redis. Agent may not be running.\n")

    elif any(w in q for w in ("block", "حظر", "rule", "قاعدة")):
        active_rules = data.get("active_rules", 0)
        lines.append(f"**Active Firewall Rules:** {active_rules}\n\n")
        lines.append(
            "To add a block rule: `POST /api/v1/rules` with `{\"action\": \"block\", \"src_ip\": \"...\", \"reason\": \"...\"}`\n"
        )

    if not lines:
        sources = network_ctx.get("sources", [])
        lines.append(
            f"*LLM server is offline. Live data sources: {', '.join(sources) or 'none'}.*\n\n"
            f"**Query:** {question}\n\n"
            "To enable full AI analysis, start Ollama: `ollama serve` and pull Mistral:\n"
            "`ollama pull mistral:7b-instruct-q4_K_M`\n"
        )

    return "".join(lines)


# ============================================================================
# Main Route
# ============================================================================

@router.post("/query", response_model=SecurityQueryResponse, summary="AI security query")
async def security_query(body: SecurityQuery, request: Request):
    """
    سؤال أمني بلغة طبيعية — يُجيب باستخدام بيانات الشبكة الحقيقية + LLM.

    مسار الإجابة:
      1. جلب بيانات حقيقية من Redis (RAG)
      2. بناء prompt مُخصَّص
      3. Ollama Mistral-7B (محلي) ← الأولوية
      4. Groq Cloud (fallback إذا كان هناك GROQ_API_KEY)
      5. Context-aware answer من البيانات الحقيقية (fallback نهائي)
    """
    start = time.perf_counter()

    # جلب البيانات الحقيقية
    network_ctx = await _build_network_context(request)
    context_str = _format_context_for_llm(network_ctx)

    # بناء الـ prompt
    system_prompt = (
        "You are Thor Firewall's AI security analyst. "
        "Answer the user's security question using the provided real-time network data. "
        "Be concise, technical, and actionable. Use Markdown formatting."
    )

    user_context = body.context or context_str
    full_prompt = (
        f"[INST] {system_prompt}\n\n"
        f"### Real-time Network Context\n{user_context}\n\n"
        f"### Question\n{body.question} [/INST]"
    )

    # Handle streaming
    if body.stream:
        if await _check_ollama():
            return StreamingResponse(
                _stream_ollama(full_prompt, body.max_tokens),
                media_type="text/event-stream",
            )

    # Non-streaming
    answer: Optional[str] = None
    model_used = "unknown"

    if await _check_ollama():
        answer = await _query_ollama(full_prompt, body.max_tokens)
        model_used = LLM_MODEL

    if not answer and GROQ_API_KEY:
        answer = await _query_groq(full_prompt, body.max_tokens)
        model_used = "groq/mixtral-8x7b"

    if not answer:
        answer = _context_aware_fallback(body.question, network_ctx)
        model_used = "context-engine-v1"

    latency_ms = (time.perf_counter() - start) * 1000
    return SecurityQueryResponse(
        answer=answer,
        model=model_used,
        latency_ms=round(latency_ms, 2),
        context_used=context_str[:500] if context_str else None,
        data_sources=network_ctx.get("sources", []),
    )
