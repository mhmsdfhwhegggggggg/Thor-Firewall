"""
Thor Firewall — Shodan Integration
استعلام Shodan عن IPs (open ports, CVEs, banners)

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, os, time
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("thor.integrations.shodan")

SHODAN_BASE    = "https://api.shodan.io"
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
CACHE_TTL      = 7200   # ثانية (2 ساعة)


class ShodanClient:
    """
    Shodan Internet Intelligence Client
    - IP info (ports, banners, CVEs, tags)
    - Host search
    - DNS lookup
    """

    def __init__(self, api_key: str = SHODAN_API_KEY):
        self.api_key = api_key
        self._cache: Dict[str, tuple] = {}
        self._client = httpx.AsyncClient(
            base_url=SHODAN_BASE,
            timeout=20.0,
        )

    async def host_info(self, ip: str) -> Dict[str, Any]:
        """معلومات كاملة عن IP من Shodan"""
        cache_key = f"host:{ip}"
        cached    = self._cache.get(cache_key)
        if cached and time.time() - cached[1] < CACHE_TTL:
            return cached[0]

        if not self.api_key:
            return {"error": "SHODAN_API_KEY not configured"}

        try:
            resp = await self._client.get(f"/shodan/host/{ip}", params={"key": self.api_key})
            if resp.status_code == 200:
                raw    = resp.json()
                result = self._parse_host(raw)
            elif resp.status_code == 404:
                result = {"error": "no_results", "ip": ip}
            else:
                result = {"error": f"HTTP {resp.status_code}"}
            self._cache[cache_key] = (result, time.time())
            return result
        except Exception as e:
            logger.error("shodan_request_failed", ip=ip, error=str(e))
            return {"error": str(e)}

    async def dns_resolve(self, hostnames: List[str]) -> Dict[str, str]:
        """حوّل أسماء النطاقات إلى IPs"""
        if not self.api_key:
            return {}
        try:
            resp = await self._client.get(
                "/dns/resolve",
                params={"key": self.api_key, "hostnames": ",".join(hostnames)},
            )
            if resp.status_code == 200:
                return resp.json()
            return {}
        except Exception as e:
            logger.error("shodan_dns_failed", error=str(e))
            return {}

    def _parse_host(self, raw: Dict) -> Dict[str, Any]:
        """استخرج ملخصاً من نتيجة Shodan host"""
        ports   = raw.get("ports", [])
        vulns   = raw.get("vulns", {})
        tags    = raw.get("tags", [])
        return {
            "ip":           raw.get("ip_str", ""),
            "hostnames":    raw.get("hostnames", []),
            "country":      raw.get("country_name", ""),
            "country_code": raw.get("country_code", ""),
            "city":         raw.get("city", ""),
            "org":          raw.get("org", ""),
            "isp":          raw.get("isp", ""),
            "asn":          raw.get("asn", ""),
            "open_ports":   ports,
            "port_count":   len(ports),
            "cves":         list(vulns.keys())[:20],
            "cve_count":    len(vulns),
            "high_cves":    [k for k, v in vulns.items() if v.get("cvss", 0) >= 7.0],
            "tags":         tags,
            "is_tor":       "tor" in tags,
            "is_honeypot":  "honeypot" in tags,
            "is_cloud":     any(t in tags for t in ["cloud", "aws", "azure", "gcp"]),
            "last_update":  raw.get("last_update", ""),
            "os":           raw.get("os"),
        }

    async def close(self):
        await self._client.aclose()


_shodan_client: Optional[ShodanClient] = None

def get_shodan() -> ShodanClient:
    global _shodan_client
    if _shodan_client is None:
        _shodan_client = ShodanClient()
    return _shodan_client
