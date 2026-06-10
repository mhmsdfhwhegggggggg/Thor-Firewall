"""
Thor Firewall — VirusTotal Integration
استعلام VirusTotal عن IPs، Domains، File Hashes

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, os, time
from typing import Any, Dict, Optional
import httpx

logger = logging.getLogger("thor.integrations.virustotal")

VT_BASE    = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
CACHE_TTL  = 3600   # ثانية


class VirusTotalClient:
    """
    VirusTotal v3 API Client
    - IP lookup
    - Domain lookup
    - File hash lookup
    - URL scan
    """

    def __init__(self, api_key: str = VT_API_KEY):
        self.api_key   = api_key
        self._cache: Dict[str, tuple] = {}   # key → (result, timestamp)
        self._client   = httpx.AsyncClient(
            base_url=VT_BASE,
            headers={"x-apikey": self.api_key},
            timeout=15.0,
        )

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """استعلم عن IP في VirusTotal"""
        return await self._cached_get(f"/ip_addresses/{ip}", f"ip:{ip}")

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """استعلم عن Domain"""
        return await self._cached_get(f"/domains/{domain}", f"domain:{domain}")

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """استعلم عن File Hash (MD5/SHA1/SHA256)"""
        return await self._cached_get(f"/files/{file_hash}", f"hash:{file_hash}")

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """استعلم عن URL (يحتاج base64 encoding)"""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._cached_get(f"/urls/{url_id}", f"url:{url_id}")

    def parse_ip_result(self, result: Dict) -> Dict[str, Any]:
        """استخرج ملخصاً من نتيجة IP lookup"""
        if "error" in result:
            return {"error": result["error"]}
        attrs   = result.get("data", {}).get("attributes", {})
        stats   = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        harmless  = stats.get("harmless", 0)
        suspicious = stats.get("suspicious", 0)
        total   = max(malicious + harmless + suspicious + stats.get("undetected", 0), 1)
        return {
            "ip":               result.get("data", {}).get("id", ""),
            "malicious_votes":  malicious,
            "suspicious_votes": suspicious,
            "harmless_votes":   harmless,
            "detection_rate":   round(malicious / total, 3),
            "reputation":       attrs.get("reputation", 0),
            "country":          attrs.get("country", ""),
            "asn":              attrs.get("asn", ""),
            "owner":            attrs.get("as_owner", ""),
            "categories":       attrs.get("categories", {}),
            "is_malicious":     malicious >= 3,
            "tags":             attrs.get("tags", []),
        }

    async def _cached_get(self, path: str, cache_key: str) -> Dict[str, Any]:
        # Cache check
        cached = self._cache.get(cache_key)
        if cached and time.time() - cached[1] < CACHE_TTL:
            return cached[0]

        if not self.api_key:
            logger.warning("virustotal_api_key_missing")
            return {"error": "VIRUSTOTAL_API_KEY not configured", "source": "virustotal"}

        try:
            resp = await self._client.get(path)
            if resp.status_code == 200:
                result = resp.json()
            elif resp.status_code == 404:
                result = {"error": "not_found", "status_code": 404}
            elif resp.status_code == 429:
                result = {"error": "rate_limited", "status_code": 429}
            else:
                result = {"error": f"HTTP {resp.status_code}", "status_code": resp.status_code}
            self._cache[cache_key] = (result, time.time())
            return result
        except Exception as e:
            logger.error("virustotal_request_failed", path=path, error=str(e))
            return {"error": str(e), "source": "virustotal"}

    async def close(self):
        await self._client.aclose()


# Singleton
_vt_client: Optional[VirusTotalClient] = None

def get_virustotal() -> VirusTotalClient:
    global _vt_client
    if _vt_client is None:
        _vt_client = VirusTotalClient()
    return _vt_client
