"""
Thor Firewall — Integrations API Routes
واجهة برمجية للتكاملات الخارجية: VirusTotal, Shodan, Slack
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/integrations", tags=["Integrations"])


# ── Models ────────────────────────────────────────────────────────────────────

class IPLookupRequest(BaseModel):
    ip: str

class HashLookupRequest(BaseModel):
    hash: str
    hash_type: str = "sha256"

class DomainLookupRequest(BaseModel):
    domain: str

class SlackAlertRequest(BaseModel):
    threat_type: str
    severity:    str
    src_ip:      str
    risk_score:  float
    mitre_id:    str = ""
    details:     dict = {}

# ── VirusTotal ────────────────────────────────────────────────────────────────

@router.get("/virustotal/ip/{ip}", summary="VirusTotal IP reputation")
async def vt_ip_lookup(ip: str):
    try:
        from ..integrations.virustotal import get_virustotal
        vt     = get_virustotal()
        raw    = await vt.lookup_ip(ip)
        result = vt.parse_ip_result(raw)
        return {"source": "virustotal", "ip": ip, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/virustotal/domain/{domain}", summary="VirusTotal domain reputation")
async def vt_domain_lookup(domain: str):
    try:
        from ..integrations.virustotal import get_virustotal
        vt     = get_virustotal()
        result = await vt.lookup_domain(domain)
        return {"source": "virustotal", "domain": domain, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/virustotal/hash/{file_hash}", summary="VirusTotal file hash lookup")
async def vt_hash_lookup(file_hash: str):
    try:
        from ..integrations.virustotal import get_virustotal
        result = await get_virustotal().lookup_hash(file_hash)
        return {"source": "virustotal", "hash": file_hash, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Shodan ────────────────────────────────────────────────────────────────────

@router.get("/shodan/host/{ip}", summary="Shodan host intelligence")
async def shodan_host(ip: str):
    try:
        from ..integrations.shodan_api import get_shodan
        result = await get_shodan().host_info(ip)
        return {"source": "shodan", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/shodan/dns-resolve", summary="Shodan DNS resolution")
async def shodan_dns(body: dict):
    try:
        from ..integrations.shodan_api import get_shodan
        hostnames = body.get("hostnames", [])
        result    = await get_shodan().dns_resolve(hostnames)
        return {"source": "shodan", "resolved": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Comprehensive IP Investigation ────────────────────────────────────────────

@router.get("/investigate/{ip}", summary="Full IP investigation (VT + Shodan)")
async def investigate_ip(ip: str):
    """
    تحقيق شامل في IP واحد عبر جميع المصادر الاستخباراتية.
    يجمع بيانات من: VirusTotal + Shodan
    """
    from ..integrations.virustotal import get_virustotal
    from ..integrations.shodan_api  import get_shodan
    import asyncio

    vt_task     = get_virustotal().lookup_ip(ip)
    shodan_task = get_shodan().host_info(ip)

    try:
        vt_raw, shodan_raw = await asyncio.gather(vt_task, shodan_task, return_exceptions=True)
        vt_parsed = {}
        if not isinstance(vt_raw, Exception):
            vt_parsed = get_virustotal().parse_ip_result(vt_raw)

        combined_risk = 0.0
        tags: list[str] = []

        if vt_parsed.get("is_malicious"):
            combined_risk += 0.5
            tags.append("vt_malicious")
        if isinstance(shodan_raw, dict) and shodan_raw.get("cve_count", 0) > 0:
            combined_risk += min(shodan_raw["cve_count"] * 0.05, 0.4)
            tags.append(f"cves:{shodan_raw['cve_count']}")
        if isinstance(shodan_raw, dict) and shodan_raw.get("is_tor"):
            combined_risk += 0.2
            tags.append("tor_exit")

        combined_risk = min(combined_risk, 1.0)

        return {
            "ip":           ip,
            "combined_risk": round(combined_risk, 3),
            "threat_tags":  tags,
            "virustotal":   vt_parsed if not isinstance(vt_raw, Exception) else {"error": str(vt_raw)},
            "shodan":       shodan_raw if not isinstance(shodan_raw, Exception) else {"error": str(shodan_raw)},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Slack ─────────────────────────────────────────────────────────────────────

@router.post("/slack/alert", summary="Send security alert to Slack")
async def slack_alert(req: SlackAlertRequest):
    try:
        from ..integrations.slack_bot import get_slack_bot
        ok = await get_slack_bot().send_threat_alert(
            threat_type = req.threat_type,
            severity    = req.severity,
            src_ip      = req.src_ip,
            risk_score  = req.risk_score,
            mitre_id    = req.mitre_id,
            details     = req.details,
        )
        return {"status": "sent" if ok else "failed", "channel": "#security-alerts"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status", summary="Integration health status")
async def integrations_status():
    import os
    return {
        "virustotal": {
            "configured": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "status":     "active" if os.getenv("VIRUSTOTAL_API_KEY") else "needs_api_key",
        },
        "shodan": {
            "configured": bool(os.getenv("SHODAN_API_KEY")),
            "status":     "active" if os.getenv("SHODAN_API_KEY") else "needs_api_key",
        },
        "slack": {
            "configured": bool(os.getenv("SLACK_WEBHOOK_URL")),
            "status":     "active" if os.getenv("SLACK_WEBHOOK_URL") else "needs_webhook_url",
        },
    }
