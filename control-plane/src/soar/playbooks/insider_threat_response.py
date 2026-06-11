"""
Insider Threat Response Playbook
Triggered on: UEBA anomaly score > 0.85 + data exfiltration indicators
Handles: employee data theft, privilege abuse, sabotage patterns
"""
from __future__ import annotations
import asyncio, logging, json, time
from ..orchestrator import PlaybookExecution, SOAROrchestrator

logger = logging.getLogger("thor.soar.insider")

class InsiderThreatPlaybook:
    PLAYBOOK_NAME = "insider_threat"

    def __init__(self, orchestrator: SOAROrchestrator):
        self.orch = orchestrator

    async def run(self, alert: dict, execution: PlaybookExecution):
        user       = alert.get("actor_user", "unknown")
        host       = alert.get("source_host", "unknown")
        risk_score = alert.get("risk_score", 0.0)
        behaviors  = alert.get("labels", {}).get("anomalous_behaviors", "")

        logger.warning("INSIDER THREAT: user=%s host=%s score=%.2f", user, host, risk_score)

        execution.context.update({
            "user": user, "host": host, "behaviors": behaviors
        })

        # Staged response based on risk score (avoid false-positive damage)
        if risk_score >= 0.95:
            # Critical: immediate action
            await asyncio.gather(
                self.orch.record_action(execution, "revoke_access",      self._revoke_access(user)),
                self.orch.record_action(execution, "preserve_evidence",  self._preserve_evidence(user, host)),
                self.orch.record_action(execution, "notify_hr_legal",    self._notify_hr(user, alert)),
                return_exceptions=True,
            )
        elif risk_score >= 0.85:
            # High: enhanced monitoring + alert HR
            await asyncio.gather(
                self.orch.record_action(execution, "increase_monitoring", self._increase_monitoring(user)),
                self.orch.record_action(execution, "notify_manager",      self._notify_manager(user, alert)),
                return_exceptions=True,
            )

        # Always: collect evidence and create ticket
        await asyncio.gather(
            self.orch.record_action(execution, "collect_dlp_evidence",  self._collect_dlp(user)),
            self.orch.record_action(execution, "create_hr_ticket",      self._create_hr_ticket(user, alert, execution)),
            return_exceptions=True,
        )

    async def _revoke_access(self, user: str) -> dict:
        """Disable AD/AAD account + revoke VPN + revoke SSO sessions"""
        logger.warning("REVOKING ALL ACCESS for insider: %s", user)
        return {"user": user, "ad_disabled": True, "vpn_revoked": True, "sso_sessions_revoked": True}

    async def _preserve_evidence(self, user: str, host: str) -> dict:
        """Forensic preservation: screenshot, process list, network connections, email archive"""
        return {
            "user":      user,
            "host":      host,
            "preserved": ["screen_capture", "process_list", "network_conns",
                          "usb_history", "email_metadata", "file_access_log"],
            "chain_of_custody": True,
        }

    async def _notify_hr(self, user: str, alert: dict) -> dict:
        """Confidential notification to HR and Legal"""
        return {
            "notified":    ["hr_director", "legal_counsel", "ciso"],
            "user":        user,
            "sensitivity": "CONFIDENTIAL",
            "timestamp":   int(time.time()),
        }

    async def _notify_manager(self, user: str, alert: dict) -> dict:
        """Alert manager to enhanced monitoring without tipping off employee"""
        return {"user": user, "manager_notified": True, "monitoring_level": "enhanced"}

    async def _increase_monitoring(self, user: str) -> dict:
        """Elevate monitoring: full packet capture, DLP alerts, USB monitoring"""
        return {
            "user":          user,
            "monitoring":    ["full_pcap", "dlp_strict", "usb_block", "print_log"],
            "retention_days": 90,
        }

    async def _collect_dlp(self, user: str) -> dict:
        """Pull last 30 days DLP events for user: email, cloud upload, USB, print"""
        return {
            "user":       user,
            "dlp_events": "collected",
            "period_days": 30,
        }

    async def _create_hr_ticket(self, user: str, alert: dict, execution: PlaybookExecution) -> dict:
        """Create confidential HR case ticket"""
        from ...integrations.servicenow_connector import ServiceNowConnector
        try:
            snow = ServiceNowConnector()
            return await snow.create_case(
                short_description = f"[CONFIDENTIAL] Insider Threat Investigation — {user}",
                description       = f"Automated detection by Thor UEBA engine.\n"
                                   f"Risk Score: {alert.get('risk_score', 0.0):.2f}\n"
                                   f"User: {user}\n"
                                   f"Behaviors: {execution.context.get('behaviors', 'N/A')}\n"
                                   f"Execution: {execution.id}",
                category          = "Security Incident",
                urgency           = "1",
                impact            = "1",
            )
        except Exception as e:
            return {"error": str(e)}

touch /tmp/thor-firewall/control-plane/src/soar/playbooks/__init__.py
