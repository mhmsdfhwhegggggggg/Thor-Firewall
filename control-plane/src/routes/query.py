"""Thor Firewall — Natural Language Security Query (LLM)"""
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class SecurityQuery(BaseModel):
    question: str
    context: Optional[str] = None
    language: str = "ar"


class QueryResponse(BaseModel):
    question: str
    answer: str
    model: str
    latency_ms: float


@router.post("/query", response_model=QueryResponse, summary="Natural language security query")
async def security_query(query: SecurityQuery, request: Request):
    """
    Ask Thor's AI (LLM) a natural language security question.

    Examples:
    - "ما هي أكثر الهجمات شيوعاً في آخر 24 ساعة؟"
    - "هل 192.168.1.100 تصرف بشكل مشبوه؟"
    - "اشرح لي آخر هجوم SYN flood"
    """
    import time
    start = time.time()

    try:
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "http://localhost:8081/v1/chat/completions",
                json={
                    "messages": [
                        {"role": "system", "content": "أنت محلل أمن سيبراني خبير في نظام Thor Firewall."},
                        {"role": "user", "content": query.question},
                    ],
                    "max_tokens": 512,
                    "temperature": 0.1,
                }
            )
            answer = resp.json()["choices"][0]["message"]["content"]
            model = "mistral-7b-security"
    except Exception:
        # Fallback when LLM not available
        answer = (
            "⚠️ خادم LLM غير متاح حالياً. "
            f"سؤالك: '{query.question}' — "
            "يُرجى التحقق من تشغيل خادم llama.cpp على المنفذ 8081."
        )
        model = "fallback"

    return QueryResponse(
        question=query.question,
        answer=answer,
        model=model,
        latency_ms=(time.time() - start) * 1000,
    )
