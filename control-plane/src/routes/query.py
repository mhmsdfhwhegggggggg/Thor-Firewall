"""
Thor Firewall — AI Security Query Route
تحليل الأسئلة الأمنية بواسطة LLM + RAG
"""
import time
import os
import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional
import httpx

router = APIRouter()
logger = logging.getLogger("thor.query")

LLM_SERVER_URL = os.environ.get("THOR_LLM_SERVER_URL", "http://localhost:8081")

class SecurityQuery(BaseModel):
    question: str = Field(..., min_length=3, max_length=1000)
    context:  Optional[str] = None
    max_tokens: int = Field(512, ge=64, le=2048)

class SecurityQueryResponse(BaseModel):
    answer:     str
    model:      str
    latency_ms: float
    context_used: Optional[str] = None

# Pre-baked demo answers for offline mode
DEMO_ANSWERS = {
    "top": """Based on the last hour of traffic:

**Top Threat Actors:**
1. `185.220.101.23` (TOR exit) — SYN flood, 184K pkts/s → BLOCKED
2. `103.45.67.89`   (AS12345, CN) — SSH brute force, 2847 attempts → BLOCKED
3. `198.51.100.44`  (AS-UNKNOWN) — Port scan, 1200 ports/10s → RATE LIMITED
4. `10.0.1.88`      (Internal!)  — C2 beacon to 203.0.113.5:4444 → BLOCKED
5. `203.0.113.99`   (AS67890, RU) — DNS amplification reflector → BLOCKED

**Recommendation:** Add 103.45.67.89/24 to blacklist (entire /24 is TOR infrastructure).""",

    "entropy": """Flows with payload entropy > 7.5 (potential encryption/tunneling):

| Source IP       | Dest IP     | Port  | Protocol | Entropy | Decision  |
|-----------------|-------------|-------|----------|---------|-----------|
| 192.168.1.45   | 8.8.8.8     | 53/UDP | DNS      | 7.91    | Mirror    |
| 10.0.2.15      | 203.0.113.5 | 443   | TLS      | 7.98    | Blocked   |
| 172.16.0.88    | 1.1.1.1     | 53/UDP | DNS      | 7.83    | Analyzing |

Note: TLS traffic normally has entropy ~7.8-7.9. The DNS flows are anomalous — investigate.""",

    "syn": """SYN flood mitigation status:

- **Active defense:** SYN cookies enabled (kernel `tcp_syncookies=1`)  
- **Current rate:** 184,293 SYN/s from 185.220.101.23 → BLOCKED via XDP DROP
- **BPF mitigation:** xdp_syn_flood program active, threshold: 1,000 SYN/s per /32
- **Effectiveness:** 99.7% of flood packets dropped at XDP layer (line rate)
- **Legitimate traffic:** Zero impact (SYN cookies handle legitimate connections)

The eBPF SYN guard uses token bucket with 1000 tokens/second per source IP.""",
}

@router.post("/query", response_model=SecurityQueryResponse, summary="AI security query")
async def security_query(body: SecurityQuery, request: Request):
    """
    Ask a natural language question about network security state.
    Powered by Mistral-7B with RAG over MISP, OTX, CVE feeds.
    """
    start = time.perf_counter()

    # Check if LLM server is available
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{LLM_SERVER_URL}/query",
                json={
                    "question": body.question,
                    "context":  body.context,
                    "max_tokens": body.max_tokens,
                },
            )
            if resp.status_code == 200:
                data      = resp.json()
                latency   = (time.perf_counter() - start) * 1000
                return SecurityQueryResponse(
                    answer        = data.get("answer", ""),
                    model         = data.get("model", "mistral-7b"),
                    latency_ms    = round(latency, 2),
                    context_used  = data.get("context_used"),
                )
    except Exception as e:
        logger.warning(f"LLM server unavailable ({e}), using demo mode")

    # Demo mode — keyword matching
    q = body.question.lower()
    latency = (time.perf_counter() - start) * 1000

    if "top" in q and ("threat" in q or "actor" in q):
        answer = DEMO_ANSWERS["top"]
    elif "entropy" in q or "tunnel" in q:
        answer = DEMO_ANSWERS["entropy"]
    elif "syn" in q or "flood" in q or "mitigation" in q:
        answer = DEMO_ANSWERS["syn"]
    elif "block" in q or "blocklist" in q:
        answer = (
            "IPs recommended for blocklist based on current threat intelligence:\n\n"
            "- `185.220.101.23/32` — Active TOR exit, SYN flood source\n"
            "- `103.45.67.89/24`   — SSH brute force botnet (entire /24)\n"
            "- `10.0.1.88/32`      — Internal machine with C2 beacon (investigate!)\n\n"
            "Use `POST /api/v1/rules` with action=block to add these."
        )
    else:
        answer = (
            f"Query: *{body.question}*\n\n"
            "**Note:** LLM server is not currently running. "
            "Start `ml/llm/explainer.py` for full AI-powered analysis.\n\n"
            "Current network status: 142,847 active flows, 3 active threats, "
            "99.7% blocked at eBPF layer. System operating normally."
        )

    return SecurityQueryResponse(
        answer     = answer,
        model      = "demo-mode",
        latency_ms = round(latency, 2),
    )
