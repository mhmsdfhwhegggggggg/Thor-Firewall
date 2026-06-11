"""
PagerDuty Integration — Events API v2 + REST API
Send alerts, trigger incidents, manage escalations
"""
from __future__ import annotations
import asyncio, json, logging, os, time
import aiohttp

logger = logging.getLogger("thor.integrations.pagerduty")

EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"
REST_API_URL   = "https://api.pagerduty.com"

class PagerDutyConnector:
    """
    PagerDuty Events v2 + REST API connector.
    Env vars: PD_ROUTING_KEY (Events API), PD_API_TOKEN (REST API), PD_SERVICE_ID
    """

    def __init__(self):
        self.routing_key = os.getenv("PD_ROUTING_KEY", "")
        self.api_token   = os.getenv("PD_API_TOKEN", "")
        self.service_id  = os.getenv("PD_SERVICE_ID", "")
        self.timeout     = aiohttp.ClientTimeout(total=10)

    async def trigger_incident(
        self,
        title:     str,
        severity:  str = "critical",   # critical | error | warning | info
        details:   dict | None = None,
        dedup_key: str = "",
        source:    str = "Thor Firewall",
        links:     list[dict] | None = None,
    ) -> dict:
        """
        Send trigger event to PagerDuty Events API v2.
        Returns the dedup_key for future acknowledge/resolve calls.
        """
        payload = {
            "routing_key":  self.routing_key,
            "event_action": "trigger",
            "dedup_key":    dedup_key or f"thor_{int(time.time())}",
            "payload": {
                "summary":   title,
                "source":    source,
                "severity":  severity,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "custom_details": details or {},
            },
            "links": links or [
                {"href": "https://thor-dashboard/incidents", "text": "Thor Dashboard"}
            ],
        }

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.post(
                EVENTS_API_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as resp:
                body = await resp.json()
                if resp.status not in (200, 202):
                    logger.error("PagerDuty trigger failed %d: %s", resp.status, body)
                    return {"error": body}
                logger.info("PagerDuty incident triggered: %s", body.get("dedup_key"))
                return body

    async def resolve_incident(self, dedup_key: str) -> dict:
        """Resolve a previously triggered incident"""
        payload = {
            "routing_key":  self.routing_key,
            "event_action": "resolve",
            "dedup_key":    dedup_key,
        }
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.post(EVENTS_API_URL, json=payload) as resp:
                return await resp.json()

    async def acknowledge_incident(self, dedup_key: str) -> dict:
        """Acknowledge a triggered incident (stop escalation)"""
        payload = {
            "routing_key":  self.routing_key,
            "event_action": "acknowledge",
            "dedup_key":    dedup_key,
        }
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.post(EVENTS_API_URL, json=payload) as resp:
                return await resp.json()

    async def get_on_call(self, escalation_policy_id: str | None = None) -> list[dict]:
        """Get current on-call responders via REST API"""
        if not self.api_token:
            return []
        headers = {
            "Authorization": f"Token token={self.api_token}",
            "Accept":        "application/vnd.pagerduty+json;version=2",
        }
        params = {}
        if escalation_policy_id:
            params["escalation_policy_ids[]"] = escalation_policy_id

        async with aiohttp.ClientSession(
            headers=headers, timeout=self.timeout
        ) as session:
            async with session.get(f"{REST_API_URL}/oncalls", params=params) as resp:
                data = await resp.json()
                return data.get("oncalls", [])
