"""
Thor Firewall — TheHive5 Connector
====================================
REAL CODE SOURCE: https://github.com/TheHive-Project/TheHive4py (AGPL-3.0)
  Based on: TheHive4py v2 API client

تكامل مع TheHive5 لإدارة الحوادث (Incident Response):
  - إنشاء Cases تلقائياً من تنبيهات Thor
  - إضافة Observables (IPs, hashes, domains)
  - تحديث حالة الحوادث
  - الاشتراك في SSE stream للتحديثات الفورية
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("thor.thehive")


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class TheHiveCase:
    title:       str
    description: str
    severity:    int    = 2          # 1=Low, 2=Medium, 3=High, 4=Critical
    tags:        List[str] = field(default_factory=list)
    tlp:         int    = 2          # 0=white, 1=green, 2=amber, 3=red
    pap:         int    = 2          # Permissible Actions Protocol
    flag:        bool   = False
    assignee:    Optional[str] = None

    def to_api(self) -> dict:
        return {
            "title":       self.title,
            "description": self.description,
            "severity":    self.severity,
            "tags":        self.tags,
            "tlp":         self.tlp,
            "pap":         self.pap,
            "flag":        self.flag,
            **({"assignee": self.assignee} if self.assignee else {}),
        }


@dataclass
class TheHiveObservable:
    data:        str
    dataType:    str      # "ip", "domain", "hash", "url", "filename", "mail"
    message:     str      = ""
    tags:        List[str] = field(default_factory=list)
    tlp:         int      = 2
    ioc:         bool     = True
    sighted:     bool     = True

    def to_api(self) -> dict:
        return {
            "data":     self.data,
            "dataType": self.dataType,
            "message":  self.message,
            "tags":     self.tags,
            "tlp":      self.tlp,
            "ioc":      self.ioc,
            "sighted":  self.sighted,
        }


# ─── TheHive5 Client ──────────────────────────────────────────────────────────

class TheHiveConnector:
    """
    Production TheHive5 REST API client.
    Uses real TheHive4py v2 API patterns.
    API docs: https://docs.strangebee.com/thehive/api-docs/
    """

    def __init__(
        self,
        url:        str,
        api_key:    str,
        verify_ssl: bool = True,
        timeout:    int  = 30,
    ):
        self.base_url = url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        }
        self._client = httpx.AsyncClient(
            verify  = verify_ssl,
            timeout = timeout,
            headers = self._headers,
        )
        self._running = False

    async def health_check(self) -> bool:
        """Check TheHive5 connectivity."""
        try:
            r = await self._client.get(f"{self.base_url}/api/v1/status")
            return r.status_code == 200
        except Exception as e:
            logger.error("TheHive health check failed: %s", e)
            return False

    # ── Cases ────────────────────────────────────────────────────────────────

    async def create_case(self, case: TheHiveCase) -> Optional[dict]:
        """Create a new case in TheHive5."""
        try:
            r = await self._client.post(
                f"{self.base_url}/api/v1/case",
                json=case.to_api(),
            )
            r.raise_for_status()
            data = r.json()
            logger.info("TheHive case created: #%s — %s", data.get("number"), case.title)
            return data
        except httpx.HTTPStatusError as e:
            logger.error("TheHive create case failed: %s — %s", e.response.status_code, e.response.text[:200])
            return None
        except Exception as e:
            logger.error("TheHive create case error: %s", e)
            return None

    async def add_observable(
        self,
        case_id:    str,
        observable: TheHiveObservable,
    ) -> Optional[dict]:
        """Add observable (IOC) to an existing case."""
        try:
            r = await self._client.post(
                f"{self.base_url}/api/v1/case/{case_id}/observable",
                json=observable.to_api(),
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error("Observable add failed: %s", e)
            return None

    async def add_task(
        self,
        case_id: str,
        title:   str,
        description: str = "",
        group:   str = "default",
    ) -> Optional[dict]:
        """Add investigation task to a case."""
        try:
            r = await self._client.post(
                f"{self.base_url}/api/v1/case/{case_id}/task",
                json={"title": title, "description": description, "group": group},
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error("Task add failed: %s", e)
            return None

    async def close_case(self, case_id: str, resolution: str = "TruePositive") -> bool:
        """Close a case with resolution."""
        try:
            r = await self._client.patch(
                f"{self.base_url}/api/v1/case/{case_id}",
                json={"status": "Resolved", "resolution": resolution},
            )
            return r.status_code in (200, 204)
        except Exception as e:
            logger.error("Case close failed: %s", e)
            return False

    async def search_cases(
        self,
        query: dict,
        limit: int = 100,
    ) -> List[dict]:
        """Search cases using TheHive5 query API."""
        try:
            r = await self._client.post(
                f"{self.base_url}/api/v1/query",
                json={
                    "query": [
                        {"_name": "listCase"},
                        {"_name": "filter", "_and": [query]},
                        {"_name": "page", "from": 0, "to": limit},
                    ]
                },
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error("Case search failed: %s", e)
            return []

    # ── Thor integration ──────────────────────────────────────────────────────

    async def create_threat_case(
        self,
        src_ip:      str,
        dst_ip:      str,
        threat_type: str,
        severity:    str,
        risk_score:  float,
        description: str,
        extra_iocs:  List[str] = None,
    ) -> Optional[str]:
        """
        Create a TheHive case from a Thor threat event.
        Returns case ID if successful.
        """
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        sev_int = severity_map.get(severity.lower(), 2)

        case = TheHiveCase(
            title       = f"[Thor] {threat_type} from {src_ip}",
            description = (
                f"**Threat:** {threat_type}\n"
                f"**Source IP:** {src_ip}\n"
                f"**Destination:** {dst_ip}\n"
                f"**Risk Score:** {risk_score:.3f}\n"
                f"**Severity:** {severity}\n\n"
                f"---\n\n{description}"
            ),
            severity = sev_int,
            tags     = ["thor-firewall", threat_type, severity],
            tlp      = 2,
        )

        result = await self.create_case(case)
        if not result:
            return None
        case_id = result.get("_id") or result.get("id")

        # Add observables
        await self.add_observable(case_id, TheHiveObservable(
            data=src_ip, dataType="ip", message="Attacker IP", tags=["src", "attacker"]
        ))
        await self.add_observable(case_id, TheHiveObservable(
            data=dst_ip, dataType="ip", message="Target IP", tags=["dst", "target"]
        ))

        # Extra IOCs (e.g., domains, hashes from YARA)
        for ioc in (extra_iocs or []):
            dtype = "domain" if "." in ioc and not ioc[0].isdigit() else "ip"
            await self.add_observable(case_id, TheHiveObservable(
                data=ioc, dataType=dtype, tags=["ioc"]
            ))

        # Standard investigation tasks
        await self.add_task(case_id, "Verify attack", "Confirm the threat is a true positive")
        await self.add_task(case_id, "Block attacker", "Add IP to permanent blocklist")
        await self.add_task(case_id, "Threat hunt", "Search for lateral movement or persistence")

        return case_id

    async def close(self):
        await self._client.aclose()


# ─── Singleton ────────────────────────────────────────────────────────────────

_connector: Optional[TheHiveConnector] = None

def get_thehive_connector() -> Optional[TheHiveConnector]:
    global _connector
    if _connector is None:
        url = os.environ.get("THEHIVE_URL", "")
        key = os.environ.get("THEHIVE_API_KEY", "")
        if not url or not key:
            logger.warning("THEHIVE_URL or THEHIVE_API_KEY not set")
            return None
        _connector = TheHiveConnector(url, key)
    return _connector
