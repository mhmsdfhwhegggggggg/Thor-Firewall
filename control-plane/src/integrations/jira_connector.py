"""
Jira Integration — Create/update security incidents, link to SOAR executions
Supports Jira Cloud (REST API v3) and Jira Server (REST API v2)
"""
from __future__ import annotations
import asyncio, base64, json, logging, os, time
from typing import Any
import aiohttp

logger = logging.getLogger("thor.integrations.jira")

class JiraConnector:
    """
    Jira Cloud/Server connector.
    Env vars: JIRA_URL, JIRA_USER, JIRA_API_TOKEN, JIRA_PROJECT_KEY
    """

    def __init__(self):
        self.base_url    = os.getenv("JIRA_URL", "https://yourorg.atlassian.net")
        self.user        = os.getenv("JIRA_USER", "")
        self.api_token   = os.getenv("JIRA_API_TOKEN", "")
        self.project_key = os.getenv("JIRA_PROJECT_KEY", "SEC")
        self.timeout     = aiohttp.ClientTimeout(total=15)

    def _auth_headers(self) -> dict:
        creds = base64.b64encode(f"{self.user}:{self.api_token}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    async def create_incident(
        self,
        summary:     str,
        description: str,
        priority:    str = "High",
        labels:      list[str] | None = None,
        issue_type:  str = "Bug",
        assignee:    str | None = None,
        components:  list[str] | None = None,
    ) -> dict:
        """Create Jira issue and return the created issue data"""
        payload: dict[str, Any] = {
            "fields": {
                "project":     {"key": self.project_key},
                "summary":     summary,
                "description": {
                    "type":    "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description}]
                    }]
                },
                "issuetype":   {"name": issue_type},
                "priority":    {"name": priority},
                "labels":      labels or [],
            }
        }
        if assignee:
            payload["fields"]["assignee"] = {"accountId": assignee}
        if components:
            payload["fields"]["components"] = [{"name": c} for c in components]

        url = f"{self.base_url}/rest/api/3/issue"
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.post(url, json=payload) as resp:
                body = await resp.json()
                if resp.status not in (200, 201):
                    logger.error("Jira create failed %d: %s", resp.status, body)
                    return {"error": body, "status": resp.status}
                logger.info("Jira ticket created: %s", body.get("key"))
                return body

    async def update_issue(self, issue_key: str, fields: dict) -> bool:
        url = f"{self.base_url}/rest/api/3/issue/{issue_key}"
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.put(url, json={"fields": fields}) as resp:
                return resp.status == 204

    async def add_comment(self, issue_key: str, comment: str) -> dict:
        url = f"{self.base_url}/rest/api/3/issue/{issue_key}/comment"
        payload = {
            "body": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph",
                              "content": [{"type": "text", "text": comment}]}]
            }
        }
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.post(url, json=payload) as resp:
                return await resp.json()

    async def transition_issue(self, issue_key: str, transition_name: str) -> bool:
        """Move issue to new status (e.g. 'In Progress', 'Resolved')"""
        # First get available transitions
        url = f"{self.base_url}/rest/api/3/issue/{issue_key}/transitions"
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.get(url) as resp:
                data = await resp.json()
            transitions = {t["name"]: t["id"] for t in data.get("transitions", [])}
            tid = transitions.get(transition_name)
            if not tid:
                logger.warning("Transition '%s' not found for %s", transition_name, issue_key)
                return False
            payload = {"transition": {"id": tid}}
            async with session.post(url, json=payload) as resp:
                return resp.status == 204

    async def search_issues(self, jql: str, fields: list[str] | None = None) -> list[dict]:
        url = f"{self.base_url}/rest/api/3/search"
        params = {"jql": jql, "maxResults": 50}
        if fields:
            params["fields"] = ",".join(fields)
        async with aiohttp.ClientSession(
            headers=self._auth_headers(), timeout=self.timeout
        ) as session:
            async with session.get(url, params=params) as resp:
                data = await resp.json()
                return data.get("issues", [])
