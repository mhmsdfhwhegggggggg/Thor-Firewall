"""
ServiceNow Integration — Create/update incidents and security cases via Table API
"""
from __future__ import annotations
import asyncio, base64, json, logging, os
import aiohttp

logger = logging.getLogger("thor.integrations.servicenow")

class ServiceNowConnector:
    """
    ServiceNow Table API connector.
    Env vars: SNOW_INSTANCE, SNOW_USER, SNOW_PASSWORD
    """

    def __init__(self):
        instance         = os.getenv("SNOW_INSTANCE", "yourinstance")
        self.base_url    = f"https://{instance}.service-now.com/api/now"
        self.user        = os.getenv("SNOW_USER", "")
        self.password    = os.getenv("SNOW_PASSWORD", "")
        self.timeout     = aiohttp.ClientTimeout(total=15)

    def _auth_headers(self) -> dict:
        creds = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    async def create_incident(
        self,
        short_description: str,
        description:       str,
        urgency:           str = "2",
        impact:            str = "2",
        category:          str = "Security",
        assignment_group:  str = "Security Operations",
    ) -> dict:
        payload = {
            "short_description": short_description,
            "description":       description,
            "urgency":           urgency,
            "impact":            impact,
            "category":          category,
            "assignment_group":  assignment_group,
            "state":             "1",  # New
        }
        url = f"{self.base_url}/table/incident"
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.post(url, json=payload) as resp:
                data = await resp.json()
                result = data.get("result", {})
                logger.info("ServiceNow incident: %s", result.get("number"))
                return result

    async def create_case(
        self,
        short_description: str,
        description:       str,
        urgency:           str = "1",
        impact:            str = "1",
        category:          str = "Security Incident",
    ) -> dict:
        """Create a security case (sn_si_incident table)"""
        payload = {
            "short_description": short_description,
            "description":       description,
            "urgency":           urgency,
            "impact":            impact,
            "category":          category,
        }
        url = f"{self.base_url}/table/sn_si_incident"
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.post(url, json=payload) as resp:
                data = await resp.json()
                return data.get("result", {})

    async def update_record(self, table: str, sys_id: str, fields: dict) -> dict:
        url = f"{self.base_url}/table/{table}/{sys_id}"
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.patch(url, json=fields) as resp:
                data = await resp.json()
                return data.get("result", {})

    async def get_incident(self, number: str) -> dict:
        url = f"{self.base_url}/table/incident"
        params = {"sysparm_query": f"number={number}", "sysparm_limit": 1}
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.get(url, params=params) as resp:
                data = await resp.json()
                results = data.get("result", [])
                return results[0] if results else {}
