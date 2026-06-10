"""
Thor Firewall — Wazuh SIEM/XDR Connector
==========================================
REAL CODE SOURCE: https://github.com/wazuh/wazuh (GPL-2.0)
  Based on: Wazuh REST API v4.x
  Docs: https://documentation.wazuh.com/current/user-manual/api/

تكامل مع Wazuh لـ:
  - جلب تنبيهات Wazuh وتحويلها لـ Thor threats
  - إرسال active responses (block IP عبر Wazuh agents)
  - مزامنة vulnerability data من الـ agents
  - الحصول على قائمة الـ agents المتصلة
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("thor.wazuh")


class WazuhConnector:
    """
    Wazuh Manager REST API client.
    Authenticates via JWT (Wazuh's native API auth).
    """

    def __init__(
        self,
        url:        str,
        username:   str = "wazuh-wui",
        password:   str = "",
        verify_ssl: bool = False,   # Wazuh uses self-signed by default
        timeout:    int  = 30,
    ):
        self.base_url  = url.rstrip("/")
        self.username  = username
        self.password  = password
        self._token:   Optional[str] = None
        self._token_ts: float = 0
        self._client   = httpx.AsyncClient(verify=verify_ssl, timeout=timeout)

    async def _authenticate(self) -> str:
        """Get Wazuh JWT token (valid 900s)."""
        if self._token and (time.time() - self._token_ts) < 800:
            return self._token

        r = await self._client.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.username, self.password),
        )
        r.raise_for_status()
        self._token    = r.json()["data"]["token"]
        self._token_ts = time.time()
        return self._token

    async def _get(self, path: str, params: dict = None) -> dict:
        token = await self._authenticate()
        r     = await self._client.get(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
        )
        r.raise_for_status()
        return r.json()

    async def _put(self, path: str, body: dict) -> dict:
        token = await self._authenticate()
        r     = await self._client.put(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            json=body,
        )
        r.raise_for_status()
        return r.json()

    # ── Alerts ────────────────────────────────────────────────────────────────

    async def get_alerts(
        self,
        limit:       int = 100,
        min_level:   int = 7,        # Wazuh alert level (0-15)
        agent_id:    Optional[str] = None,
    ) -> List[dict]:
        """
        Get recent Wazuh alerts.
        Level 7+ = medium severity, 12+ = critical.
        """
        params: Dict[str, Any] = {
            "limit":        limit,
            "sort":         "-timestamp",
            "level":        f"{min_level}-15",
        }
        if agent_id:
            params["agents_list"] = agent_id

        try:
            data = await self._get("/alerts", params)
            return data.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("Get alerts failed: %s", e)
            return []

    async def get_alert_by_id(self, alert_id: str) -> Optional[dict]:
        try:
            data = await self._get(f"/alerts/{alert_id}")
            items = data.get("data", {}).get("affected_items", [])
            return items[0] if items else None
        except Exception as e:
            logger.error("Get alert %s failed: %s", alert_id, e)
            return None

    # ── Agents ────────────────────────────────────────────────────────────────

    async def get_agents(self, status: str = "active") -> List[dict]:
        """Get all Wazuh agents (endpoints being monitored)."""
        try:
            data = await self._get("/agents", {"status": status, "limit": 500})
            return data.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("Get agents failed: %s", e)
            return []

    async def get_agent_info(self, agent_id: str) -> Optional[dict]:
        try:
            data = await self._get(f"/agents/{agent_id}")
            items = data.get("data", {}).get("affected_items", [])
            return items[0] if items else None
        except Exception as e:
            logger.error("Get agent %s failed: %s", agent_id, e)
            return None

    # ── Active Response ───────────────────────────────────────────────────────

    async def active_response_block_ip(
        self,
        agent_ids:   List[str],
        ip:          str,
        duration:    int = 3600,
    ) -> bool:
        """
        Send active response to block IP on Wazuh agents.
        Uses Wazuh's built-in firewall-drop active response.
        """
        try:
            body = {
                "command":    "firewall-drop",
                "arguments":  [ip],
                "custom":     False,
                "alert": {
                    "data": {
                        "srcip": ip,
                        "action": "block",
                        "duration": str(duration),
                    }
                }
            }
            for agent_id in agent_ids:
                await self._put(f"/active-response?agents_list={agent_id}", body)
            logger.info("Wazuh active response: blocked %s on %d agents", ip, len(agent_ids))
            return True
        except Exception as e:
            logger.error("Active response failed for %s: %s", ip, e)
            return False

    # ── Vulnerability data ────────────────────────────────────────────────────

    async def get_vulnerabilities(
        self,
        agent_id:  str,
        severity:  str = "critical",
        limit:     int = 100,
    ) -> List[dict]:
        """Get vulnerabilities detected by Wazuh Vulnerability Detection."""
        try:
            data = await self._get(
                f"/vulnerability/{agent_id}",
                {"severity": severity, "limit": limit},
            )
            return data.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("Get vulnerabilities for %s: %s", agent_id, e)
            return []

    # ── Statistics ────────────────────────────────────────────────────────────

    async def get_stats(self) -> dict:
        """Manager statistics — events processed, alert counts."""
        try:
            data = await self._get("/manager/stats")
            return data.get("data", {})
        except Exception as e:
            logger.error("Get stats failed: %s", e)
            return {}

    async def health_check(self) -> bool:
        try:
            await self._get("/manager/status")
            return True
        except Exception:
            return False

    # ── Thor integration ──────────────────────────────────────────────────────

    async def sync_alerts_to_threats(self, redis_client) -> int:
        """
        Pull Wazuh critical alerts and push to Redis threats:timeline.
        Returns count of new alerts synced.
        """
        alerts = await self.get_alerts(limit=200, min_level=10)
        synced = 0
        import json as _json, time as _time
        for alert in alerts:
            rule  = alert.get("rule", {})
            agent = alert.get("agent", {})
            data  = alert.get("data", {})

            threat = {
                "event_id":   alert.get("id", ""),
                "timestamp":  _time.time(),
                "src_ip":     data.get("srcip", "0.0.0.0"),
                "dst_ip":     data.get("dstip", "0.0.0.0"),
                "dst_port":   int(data.get("dstport", 0)),
                "protocol":   data.get("protocol", "unknown"),
                "threat_type": rule.get("groups", ["unknown"])[0] if rule.get("groups") else "unknown",
                "severity":   "critical" if rule.get("level", 0) >= 12 else "high",
                "risk_score": rule.get("level", 0) / 15.0,
                "confidence": 0.9,
                "explanation": rule.get("description", ""),
                "blocked":    False,
                "agent_id":   agent.get("id", "wazuh"),
                "source":     "wazuh",
            }

            key = f"threats:timeline"
            score = threat["timestamp"]
            await redis_client.zadd(key, {_json.dumps(threat): score})
            synced += 1

        logger.info("Synced %d Wazuh alerts → Redis", synced)
        return synced

    async def close(self):
        await self._client.aclose()


# ─── Singleton ────────────────────────────────────────────────────────────────

_connector: Optional[WazuhConnector] = None

def get_wazuh_connector() -> Optional[WazuhConnector]:
    global _connector
    if _connector is None:
        url  = os.environ.get("WAZUH_URL",      "https://wazuh-manager:55000")
        user = os.environ.get("WAZUH_USER",     "wazuh-wui")
        pw   = os.environ.get("WAZUH_PASSWORD", "")
        if not pw:
            logger.warning("WAZUH_PASSWORD not set")
            return None
        _connector = WazuhConnector(url, user, pw)
    return _connector
