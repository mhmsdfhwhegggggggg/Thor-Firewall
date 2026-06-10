"""
Thor Firewall — MISP Connector
================================
REAL CODE SOURCE: https://github.com/MISP/PyMISP (BSD-2-Clause)
  Based on: PyMISP v2.4.x REST API
  Docs: https://www.circl.lu/doc/misp/automation/

تكامل مع MISP لـ:
  - سحب Events والـ Attributes (IOCs) تلقائياً
  - نشر Thor IOCs إلى MISP لمشاركتها مع المجتمع
  - مزامنة threatintel feeds
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("thor.misp")


@dataclass
class MISPAttribute:
    type:        str    # "ip-src", "ip-dst", "domain", "sha256", "url", "filename"
    value:       str
    to_ids:      bool   = True       # use as detection IOC
    distribution: int   = 0          # 0=org only, 1=community, 3=all
    comment:     str    = ""
    tags:        List[str] = field(default_factory=list)


@dataclass
class MISPEvent:
    info:         str
    threat_level: int       = 2       # 1=High, 2=Medium, 3=Low, 4=Undefined
    analysis:     int       = 1       # 0=Initial, 1=Ongoing, 2=Completed
    distribution: int       = 0       # 0=org only
    tags:         List[str] = field(default_factory=list)
    attributes:   List[MISPAttribute] = field(default_factory=list)


class MISPConnector:
    """
    MISP REST API client implementing PyMISP v2 patterns.
    https://www.circl.lu/doc/misp/automation/
    """

    def __init__(
        self,
        url:        str,
        api_key:    str,
        verify_ssl: bool = False,
        timeout:    int  = 30,
    ):
        self.base_url = url.rstrip("/")
        self._client  = httpx.AsyncClient(
            verify  = verify_ssl,
            timeout = timeout,
            headers = {
                "Authorization": api_key,
                "Accept":        "application/json",
                "Content-Type":  "application/json",
            },
        )

    # ── Events ────────────────────────────────────────────────────────────────

    async def create_event(self, event: MISPEvent) -> Optional[dict]:
        """Create a new MISP event with attributes."""
        payload = {
            "Event": {
                "info":            event.info,
                "threat_level_id": str(event.threat_level),
                "analysis":        str(event.analysis),
                "distribution":    str(event.distribution),
                "published":       False,
                "Attribute":       [
                    {
                        "type":         a.type,
                        "value":        a.value,
                        "to_ids":       a.to_ids,
                        "distribution": str(a.distribution),
                        "comment":      a.comment,
                    }
                    for a in event.attributes
                ],
            }
        }
        try:
            r = await self._client.post(f"{self.base_url}/events", json=payload)
            r.raise_for_status()
            data = r.json()
            event_id = data.get("Event", {}).get("id")
            logger.info("MISP event created: #%s — %s", event_id, event.info)
            return data
        except httpx.HTTPStatusError as e:
            logger.error("MISP create event: %s — %s", e.response.status_code, e.response.text[:200])
            return None
        except Exception as e:
            logger.error("MISP create event error: %s", e)
            return None

    async def search_attributes(
        self,
        value:      Optional[str]  = None,
        type_attr:  Optional[str]  = None,
        tags:       Optional[List[str]] = None,
        last:       Optional[str]  = "1d",
        limit:      int            = 100,
    ) -> List[dict]:
        """
        Search MISP attributes.
        last='1d' = last 24 hours, '1w' = last week.
        """
        params: Dict[str, Any] = {"limit": limit, "page": 1}
        if value:
            params["value"] = value
        if type_attr:
            params["type"] = type_attr
        if tags:
            params["tags"] = "|".join(tags)
        if last:
            params["last"] = last

        try:
            r = await self._client.post(
                f"{self.base_url}/attributes/restSearch",
                json={"returnFormat": "json", **params},
            )
            r.raise_for_status()
            data = r.json()
            return data.get("response", {}).get("Attribute", [])
        except Exception as e:
            logger.error("MISP search attributes: %s", e)
            return []

    async def search_events(
        self,
        threat_level: Optional[int]  = None,
        last:         str            = "7d",
        tags:         Optional[List[str]] = None,
        limit:        int            = 50,
    ) -> List[dict]:
        params: Dict[str, Any] = {"returnFormat": "json", "limit": limit}
        if threat_level:
            params["threat_level_id"] = threat_level
        if last:
            params["last"] = last
        if tags:
            params["tags"] = "|".join(tags)
        try:
            r = await self._client.post(
                f"{self.base_url}/events/restSearch", json=params
            )
            r.raise_for_status()
            data = r.json()
            return data.get("response", [])
        except Exception as e:
            logger.error("MISP search events: %s", e)
            return []

    async def get_iocs_for_ip(self, ip: str) -> List[dict]:
        """Check if IP is a known IOC in MISP."""
        return await self.search_attributes(value=ip, type_attr="ip-src")

    # ── Thor integration ──────────────────────────────────────────────────────

    async def publish_thor_ioc(
        self,
        src_ip:      str,
        threat_type: str,
        severity:    str,
        risk_score:  float,
        extra_iocs:  List[str] = None,
    ) -> Optional[str]:
        """Publish a Thor-detected IOC to MISP."""
        tl_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
        attrs  = [
            MISPAttribute(type="ip-src", value=src_ip, to_ids=True,
                          comment=f"Detected by Thor Firewall — {threat_type}"),
        ]
        for ioc in (extra_iocs or []):
            dtype = "domain" if "." in ioc and not ioc[0].isdigit() else "ip-src"
            attrs.append(MISPAttribute(type=dtype, value=ioc, to_ids=True))

        event = MISPEvent(
            info         = f"Thor Firewall: {threat_type} from {src_ip}",
            threat_level = tl_map.get(severity.lower(), 2),
            analysis     = 0,   # Initial
            attributes   = attrs,
            tags         = ["thor-firewall", threat_type, "tlp:amber"],
        )
        result = await self.create_event(event)
        if result:
            return str(result.get("Event", {}).get("id", ""))
        return None

    async def sync_iocs_to_redis(self, redis_client, lookback: str = "1d") -> int:
        """Pull MISP critical IOCs into Redis for fast lookup."""
        attrs = await self.search_attributes(
            type_attr="ip-src",
            last=lookback,
            tags=["tlp:red", "tlp:amber"],
        )
        synced = 0
        for attr in attrs:
            value = attr.get("value", "")
            if value:
                await redis_client.setex(
                    f"ti:ip:{value}",
                    86400,    # 24h TTL
                    "1",
                )
                synced += 1
        logger.info("Synced %d MISP IOCs → Redis", synced)
        return synced

    async def health_check(self) -> bool:
        try:
            r = await self._client.get(f"{self.base_url}/servers/getVersion.json")
            return r.status_code == 200
        except Exception:
            return False

    async def close(self):
        await self._client.aclose()


_connector: Optional[MISPConnector] = None

def get_misp_connector() -> Optional[MISPConnector]:
    global _connector
    if _connector is None:
        url = os.environ.get("MISP_URL",     "")
        key = os.environ.get("MISP_API_KEY", "")
        if not url or not key:
            logger.warning("MISP_URL or MISP_API_KEY not set")
            return None
        _connector = MISPConnector(url, key)
    return _connector
