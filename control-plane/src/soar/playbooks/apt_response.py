"""
APT Lateral Movement Response Playbook
Triggered on: XDR chains with lateral movement + credential access TTPs
Actions: Isolate host → Block IP → Reset credentials → Create ticket → Notify team
"""
from __future__ import annotations
import asyncio, logging, json, time
from ..orchestrator import PlaybookExecution, SOAROrchestrator

logger = logging.getLogger("thor.soar.apt")

class AptResponsePlaybook:
    """
    Automated APT response — mirrors CrowdStrike RTR containment capabilities.
    Stages:
    1. Immediate containment (network isolation via iptables/AWS Security Group)
    2. Evidence preservation (memory dump trigger, log collection)
    3. Credential revocation (AD/AAD forced password reset)
    4. Threat intelligence enrichment (VirusTotal, MISP lookup)
    5. Notification + ticketing (PagerDuty P1, Jira Critical ticket)
    6. Forensic collection scheduling
    """

    PLAYBOOK_NAME = "apt_lateral_movement"

    def __init__(self, orchestrator: SOAROrchestrator):
        self.orch = orchestrator

    async def run(self, alert: dict, execution: PlaybookExecution):
        logger.warning("APT PLAYBOOK TRIGGERED: alert_id=%s", alert.get("id"))

        # Extract context
        affected_host  = alert.get("source_host", alert.get("hostname", "unknown"))
        actor_user     = alert.get("actor_user", "")
        source_ip      = alert.get("source_ip", "")
        techniques     = alert.get("mitre_techniques", [])
        risk_score     = alert.get("risk_score", 0.0)

        execution.context.update({
            "affected_host": affected_host,
            "actor_user":    actor_user,
            "source_ip":     source_ip,
            "techniques":    techniques,
        })

        # ── Stage 1: Immediate notification ──────────────────────────────
        await self.orch.record_action(
            execution, "notify_security_team",
            self._notify_slack(alert, affected_host, techniques),
        )

        # ── Stage 2: Parallel containment ────────────────────────────────
        containment_tasks = []
        if affected_host and affected_host != "unknown":
            containment_tasks.append(
                self.orch.record_action(
                    execution, f"isolate_host:{affected_host}",
                    self._isolate_host(affected_host),
                )
            )
        if source_ip:
            containment_tasks.append(
                self.orch.record_action(
                    execution, f"block_ip:{source_ip}",
                    self._block_ip(source_ip),
                )
            )
        if containment_tasks:
            await asyncio.gather(*containment_tasks, return_exceptions=True)

        # ── Stage 3: Credential revocation ───────────────────────────────
        if actor_user and "T1078" in str(techniques):
            await self.orch.record_action(
                execution, f"force_logout:{actor_user}",
                self._revoke_sessions(actor_user),
            )

        # ── Stage 4: Threat Intel enrichment ─────────────────────────────
        intel_tasks = []
        if source_ip:
            intel_tasks.append(
                self.orch.record_action(
                    execution, f"ti_enrich_ip:{source_ip}",
                    self._enrich_ip(source_ip),
                )
            )
        if intel_tasks:
            intel_results = await asyncio.gather(*intel_tasks, return_exceptions=True)
            ioc_data = [r.output for r in intel_results if hasattr(r, "output") and r.output]
            execution.context["ioc_data"] = ioc_data

        # ── Stage 5: Create JIRA/PagerDuty ticket ────────────────────────
        await self.orch.record_action(
            execution, "create_incident_ticket",
            self._create_ticket(alert, execution),
        )

        # ── Stage 6: Schedule forensic collection ────────────────────────
        await self.orch.record_action(
            execution, "schedule_forensics",
            self._schedule_forensics(affected_host, alert),
        )

        logger.info("APT playbook complete for host=%s", affected_host)

    async def _notify_slack(self, alert: dict, host: str, techniques: list) -> dict:
        """Post rich Slack message to #security-incidents"""
        from ...integrations.slack_bot import SlackNotifier
        try:
            notifier = SlackNotifier()
            msg = {
                "channel": "#security-incidents",
                "text": f":rotating_light: *APT ALERT* — Lateral Movement Detected",
                "attachments": [{
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Host",        "value": host,                   "short": True},
                        {"title": "Risk Score",  "value": str(alert.get("risk_score", 0.0)), "short": True},
                        {"title": "MITRE TTPs",  "value": ", ".join(techniques),  "short": False},
                        {"title": "Alert ID",    "value": alert.get("id", ""),    "short": True},
                        {"title": "Timestamp",   "value": str(int(time.time())),  "short": True},
                    ],
                    "footer": "Thor Firewall SOAR",
                    "ts": int(time.time()),
                }],
            }
            result = await notifier.post_message(msg)
            return {"slack_ts": result.get("ts", "")}
        except Exception as e:
            logger.error("Slack notify failed: %s", e)
            return {"error": str(e)}

    async def _isolate_host(self, hostname: str) -> dict:
        """
        Network isolation via:
        1. EDR agent containment command (thor-agent isolate)
        2. AWS Security Group rule addition (fallback)
        3. Firewall ACL push (fallback)
        """
        logger.warning("ISOLATING HOST: %s", hostname)
        # In production: send command via agent gRPC channel
        # agent_client.send_command(hostname, "isolate_network", {})
        return {
            "hostname": hostname,
            "action":   "isolated",
            "method":   "edr_containment",
            "timestamp": int(time.time()),
        }

    async def _block_ip(self, ip: str) -> dict:
        """Block IP across all enforcement points"""
        logger.warning("BLOCKING IP: %s", ip)
        # In production: push to pf/iptables/AWS NACL/Palo Alto via API
        return {
            "ip":       ip,
            "action":   "blocked",
            "points":   ["iptables", "aws_nacl"],
            "timestamp": int(time.time()),
        }

    async def _revoke_sessions(self, user: str) -> dict:
        """Force revoke all active sessions for a user (AAD/LDAP)"""
        logger.warning("REVOKING SESSIONS for user: %s", user)
        # In production: call MS Graph revokeSignInSessions or LDAP password reset
        return {"user": user, "action": "sessions_revoked", "timestamp": int(time.time())}

    async def _enrich_ip(self, ip: str) -> dict:
        """Query VirusTotal + AbuseIPDB for IP reputation"""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                # AbuseIPDB (free tier)
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": "REPLACE_WITH_ABUSEIPDB_KEY", "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    return {
                        "ip":            ip,
                        "abuse_score":   data.get("abuseConfidenceScore", 0),
                        "country":       data.get("countryCode", ""),
                        "total_reports": data.get("totalReports", 0),
                        "domain":        data.get("domain", ""),
                        "is_tor":        data.get("isTor", False),
                    }
        except Exception as e:
            logger.debug("IP enrichment error for %s: %s", ip, e)
        return {"ip": ip, "enrichment": "unavailable"}

    async def _create_ticket(self, alert: dict, execution: PlaybookExecution) -> dict:
        """Create P1 incident in Jira + PagerDuty"""
        from ...integrations.jira_connector   import JiraConnector
        from ...integrations.pagerduty        import PagerDutyConnector

        results = {}

        # Jira ticket
        try:
            jira = JiraConnector()
            ticket = await jira.create_incident(
                summary     = f"[CRITICAL] APT Lateral Movement — {execution.context.get('affected_host')}",
                description = self._build_ticket_body(alert, execution),
                priority    = "Highest",
                labels      = ["APT", "SOAR", "AutoCreated"] + alert.get("mitre_techniques", []),
            )
            results["jira_key"] = ticket.get("key", "")
            execution.context["jira_ticket"] = ticket.get("key", "")
        except Exception as e:
            logger.error("Jira ticket creation failed: %s", e)
            results["jira_error"] = str(e)

        # PagerDuty incident
        try:
            pd = PagerDutyConnector()
            incident = await pd.trigger_incident(
                title       = f"APT Alert: Lateral Movement on {execution.context.get('affected_host')}",
                severity    = "critical",
                details     = alert,
                dedup_key   = f"apt_{execution.trigger_id}",
            )
            results["pd_incident_key"] = incident.get("dedup_key", "")
        except Exception as e:
            logger.error("PagerDuty incident failed: %s", e)
            results["pd_error"] = str(e)

        return results

    def _build_ticket_body(self, alert: dict, execution: PlaybookExecution) -> str:
        ctx = execution.context
        return f"""
*AUTOMATED SOAR RESPONSE — APT LATERAL MOVEMENT*

*Alert ID:* {alert.get('id', 'N/A')}
*Risk Score:* {alert.get('risk_score', 0.0):.2f}
*Affected Host:* {ctx.get('affected_host', 'unknown')}
*Actor User:* {ctx.get('actor_user', 'unknown')}
*Source IP:* {ctx.get('source_ip', 'N/A')}
*MITRE Techniques:* {', '.join(ctx.get('techniques', []))}

*Automated Actions Taken:*
{chr(10).join(f'  - {a.action_name}: {a.status}' for a in execution.actions)}

*IOC Data:*
{json.dumps(ctx.get('ioc_data', []), indent=2)}

_Created automatically by Thor Firewall SOAR Engine_
_Execution ID: {execution.id}_
"""

    async def _schedule_forensics(self, hostname: str, alert: dict) -> dict:
        """Schedule full forensic collection: memory dump, disk image, log pack"""
        logger.info("Scheduling forensic collection for %s", hostname)
        return {
            "hostname":    hostname,
            "tasks":       ["memory_dump", "process_tree", "network_connections", "log_pack"],
            "scheduled_at": int(time.time()),
            "priority":    "high",
        }
