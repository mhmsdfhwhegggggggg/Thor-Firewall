"""
Azure Security Collector — Sentinel + AAD SignIn + Defender for Cloud + Activity Logs
Uses Azure SDK (azure-mgmt-monitor, azure-identity, microsoft-graph-core)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator

logger = logging.getLogger("thor.cloud.azure")

# MITRE mappings for Azure AAD events
_AAD_MITRE = {
    "UserLoginFailed":                ["T1110"],       # Brute Force
    "Add member to role.":            ["T1098.003"],   # Account Manipulation
    "Add service principal.":         ["T1136.003"],   # Create Cloud Account
    "Update user.":                   ["T1098"],
    "Reset user password.":           ["T1098"],
    "Add application.":               ["T1550.001"],
    "Consent to application.":        ["T1528"],       # Steal Application Access Token
    "Add owner to application.":      ["T1098"],
    "Delete application.":            ["T1562"],
}

class AzureCollector:
    """
    Azure multi-service security collector.
    Supports: AAD SignIn logs, AAD Audit logs, Azure Activity logs, Defender alerts.
    Uses managed identity or service principal authentication.
    """

    GRAPH_API   = "https://graph.microsoft.com/v1.0"
    MONITOR_API = "https://management.azure.com"

    def __init__(
        self,
        tenant_id:       str = "",
        client_id:       str = "",
        client_secret:   str = "",
        subscription_id: str = "",
        workspace_id:    str = "",   # Log Analytics Workspace
        lookback_hours:  int = 1,
    ):
        self.tenant_id       = tenant_id
        self.client_id       = client_id
        self.client_secret   = client_secret
        self.subscription_id = subscription_id
        self.workspace_id    = workspace_id
        self.lookback_hours  = lookback_hours
        self._token_cache: dict[str, tuple[str, float]] = {}

    async def _get_token(self, scope: str) -> str:
        """Get OAuth2 token via client credentials flow"""
        cached = self._token_cache.get(scope)
        if cached and time.time() < cached[1] - 60:
            return cached[0]

        import aiohttp
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         scope,
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data) as resp:
                resp.raise_for_status()
                result = await resp.json()

        token      = result["access_token"]
        expires_in = result.get("expires_in", 3600)
        self._token_cache[scope] = (token, time.time() + expires_in)
        return token

    # ─────────────────────────── AAD SignIn Logs ───────────────────────

    async def collect_signin_logs(self) -> AsyncGenerator[dict, None]:
        """
        Collect AAD sign-in logs via Microsoft Graph API.
        Requires: AuditLog.Read.All, Directory.Read.All permissions.
        """
        token = await self._get_token("https://graph.microsoft.com/.default")
        end   = datetime.now(timezone.utc)
        start = end - timedelta(hours=self.lookback_hours)

        filter_str = (
            f"createdDateTime ge {start.strftime('%Y-%m-%dT%H:%M:%SZ')} and "
            f"createdDateTime le {end.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        url = f"{self.GRAPH_API}/auditLogs/signIns?$filter={filter_str}&$top=999"

        import aiohttp
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        async with aiohttp.ClientSession(headers=headers) as session:
            while url:
                try:
                    async with session.get(url) as resp:
                        if resp.status == 429:
                            retry_after = int(resp.headers.get("Retry-After", "10"))
                            logger.warning("AAD rate limited, sleeping %ds", retry_after)
                            await asyncio.sleep(retry_after)
                            continue
                        resp.raise_for_status()
                        data = await resp.json()

                    for event in data.get("value", []):
                        yield self._normalize_signin(event)

                    url = data.get("@odata.nextLink")
                except Exception as e:
                    logger.error("AAD sign-in collection error: %s", e)
                    break

    def _normalize_signin(self, ev: dict) -> dict:
        status      = ev.get("status", {})
        error_code  = status.get("errorCode", 0)
        location    = ev.get("location", {})
        device      = ev.get("deviceDetail", {})
        app         = ev.get("appliedConditionalAccessPolicies", [])

        outcome     = "failure" if error_code != 0 else "success"
        risk_level  = ev.get("riskLevelDuringSignIn", "none")
        risk_score  = {"none":0.0,"low":0.2,"medium":0.5,"high":0.8}.get(risk_level, 0.0)

        mitre = []
        if error_code != 0:
            mitre.append("T1110")  # Brute Force on failed logins
        if ev.get("isInteractive") is False and outcome == "success":
            mitre.append("T1078.004")  # Valid Cloud Accounts - non-interactive

        ts_ms = 0
        created = ev.get("createdDateTime", "")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                ts_ms = int(dt.timestamp() * 1000)
            except Exception:
                ts_ms = int(time.time() * 1000)

        return {
            "id":               ev.get("id", ""),
            "timestamp_ms":     ts_ms,
            "source_format":    "aad_signin",
            "source_host":      "azure:aad",
            "source_ip":        ev.get("ipAddress", ""),
            "category":         "auth",
            "action":           "SignIn",
            "outcome":          outcome,
            "actor_user":       ev.get("userPrincipalName", ev.get("userId", "")),
            "target_resource":  ev.get("resourceDisplayName", ""),
            "risk_score":       risk_score,
            "mitre_techniques": mitre,
            "raw":              json.dumps(ev),
            "labels": {
                "cloud_provider":  "azure",
                "tenant_id":       ev.get("tenantId", self.tenant_id),
                "app_id":          ev.get("appId", ""),
                "app_display":     ev.get("appDisplayName", ""),
                "client_app":      ev.get("clientAppUsed", ""),
                "error_code":      str(error_code),
                "failure_reason":  status.get("failureReason", ""),
                "risk_level":      risk_level,
                "risk_state":      ev.get("riskState", "none"),
                "os":              device.get("operatingSystem", ""),
                "browser":         device.get("browser", ""),
                "mfa_detail":      ev.get("authenticationMethodsUsed", [""])[0] if ev.get("authenticationMethodsUsed") else "",
                "country":         location.get("countryOrRegion", ""),
                "city":            location.get("city", ""),
                "conditional_access": str(len(app)) + " policies applied",
            },
        }

    # ─────────────────────────── AAD Audit Logs ────────────────────────

    async def collect_audit_logs(self) -> AsyncGenerator[dict, None]:
        """Collect AAD audit logs (user/group/app changes)"""
        token = await self._get_token("https://graph.microsoft.com/.default")
        end   = datetime.now(timezone.utc)
        start = end - timedelta(hours=self.lookback_hours)

        filter_str = (
            f"activityDateTime ge {start.strftime('%Y-%m-%dT%H:%M:%SZ')} and "
            f"activityDateTime le {end.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        url = f"{self.GRAPH_API}/auditLogs/directoryAudits?$filter={filter_str}&$top=999"

        import aiohttp
        headers = {"Authorization": f"Bearer {token}"}

        async with aiohttp.ClientSession(headers=headers) as session:
            while url:
                try:
                    async with session.get(url) as resp:
                        resp.raise_for_status()
                        data = await resp.json()

                    for event in data.get("value", []):
                        yield self._normalize_audit(event)

                    url = data.get("@odata.nextLink")
                except Exception as e:
                    logger.error("AAD audit log error: %s", e)
                    break

    def _normalize_audit(self, ev: dict) -> dict:
        activity    = ev.get("activityDisplayName", "")
        result      = ev.get("result", "success")
        initiator   = ev.get("initiatedBy", {})
        actor_user  = (
            initiator.get("user", {}).get("userPrincipalName") or
            initiator.get("app", {}).get("displayName") or ""
        )
        mitre = _AAD_MITRE.get(activity, [])

        ts_ms = 0
        ts_str = ev.get("activityDateTime", "")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts_ms = int(dt.timestamp() * 1000)
            except Exception:
                ts_ms = int(time.time() * 1000)

        risk_score = 0.5 if mitre else 0.1

        return {
            "id":               ev.get("id", ""),
            "timestamp_ms":     ts_ms,
            "source_format":    "aad_audit",
            "source_host":      "azure:aad_audit",
            "category":         "identity",
            "action":           activity,
            "outcome":          result,
            "actor_user":       actor_user,
            "risk_score":       risk_score,
            "mitre_techniques": mitre,
            "raw":              json.dumps(ev),
            "labels": {
                "cloud_provider": "azure",
                "category":       ev.get("category", ""),
                "correlation_id": ev.get("correlationId", ""),
                "service":        ev.get("loggedByService", ""),
                "result_reason":  ev.get("resultReason", ""),
            },
        }

    # ─────────────────────── Azure Activity Logs ───────────────────────

    async def collect_activity_logs(self) -> AsyncGenerator[dict, None]:
        """Collect Azure subscription activity logs (control plane operations)"""
        if not self.subscription_id:
            logger.warning("No subscription_id configured for activity logs")
            return

        token = await self._get_token("https://management.azure.com/.default")
        end   = datetime.now(timezone.utc)
        start = end - timedelta(hours=self.lookback_hours)

        filter_str = (
            f"eventTimestamp ge '{start.isoformat()}' and "
            f"eventTimestamp le '{end.isoformat()}'"
        )
        url = (
            f"{self.MONITOR_API}/subscriptions/{self.subscription_id}"
            f"/providers/microsoft.insights/eventtypes/management/values"
            f"?api-version=2015-04-01&$filter={filter_str}"
        )

        import aiohttp
        headers = {"Authorization": f"Bearer {token}"}

        async with aiohttp.ClientSession(headers=headers) as session:
            while url:
                try:
                    async with session.get(url) as resp:
                        resp.raise_for_status()
                        data = await resp.json()

                    for event in data.get("value", []):
                        yield self._normalize_activity(event)

                    url = data.get("nextLink")
                except Exception as e:
                    logger.error("Azure activity log error: %s", e)
                    break

    def _normalize_activity(self, ev: dict) -> dict:
        caller    = ev.get("caller", "")
        operation = ev.get("operationName", {}).get("value", "") or ev.get("operationName", "")
        status    = ev.get("status", {}).get("value", "").lower()
        level     = ev.get("level", "Informational")

        # Score dangerous operations
        risk_score = 0.1
        if any(x in operation.lower() for x in ["delete", "write", "action"]):
            risk_score = 0.3
        if any(x in operation.lower() for x in ["microsoft.authorization", "microsoft.keyvault",
                                                   "microsoft.security", "diagnosticsettings"]):
            risk_score = 0.6

        ts_ms = 0
        ts_str = ev.get("eventTimestamp", "")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts_ms = int(dt.timestamp() * 1000)
            except Exception:
                ts_ms = int(time.time() * 1000)

        return {
            "id":            ev.get("eventDataId", ""),
            "timestamp_ms":  ts_ms,
            "source_format": "azure_activity",
            "source_host":   "azure:activity",
            "source_ip":     ev.get("httpRequest", {}).get("clientIpAddress", ""),
            "category":      "cloud",
            "action":        operation,
            "outcome":       status,
            "actor_user":    caller,
            "risk_score":    risk_score,
            "raw":           json.dumps(ev),
            "labels": {
                "cloud_provider":  "azure",
                "subscription_id": self.subscription_id,
                "resource_group":  ev.get("resourceGroupName", ""),
                "resource_id":     ev.get("resourceId", ""),
                "level":           level,
                "correlation_id":  ev.get("correlationId", ""),
            },
        }
