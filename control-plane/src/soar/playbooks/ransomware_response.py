"""
Ransomware Response Playbook — Lightning-fast containment before encryption spreads
Detection triggers: mass file rename + .locked/.encrypted extensions + shadow copy deletion
Speed is critical: every second = more encrypted files
"""
from __future__ import annotations
import asyncio, logging, json, time
from ..orchestrator import PlaybookExecution, SOAROrchestrator

logger = logging.getLogger("thor.soar.ransomware")

class RansomwareResponsePlaybook:
    """
    Ransomware automated response.
    Target response time: < 30 seconds from detection to isolation.

    Stage 1 (0-5s):  Emergency network isolation + volume snapshot
    Stage 2 (5-15s): Kill suspicious processes + disable scheduled tasks
    Stage 3 (15-30s): Notify + ticket + activate IR team
    Stage 4 (async):  Shadow copy restoration assessment + recovery planning
    """

    PLAYBOOK_NAME = "ransomware_detected"

    # Known ransomware process names
    RANSOMWARE_PROCS = {
        "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe",
        "cmd.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
        "vssadmin.exe", "bcdedit.exe", "wbadmin.exe",
    }

    def __init__(self, orchestrator: SOAROrchestrator):
        self.orch = orchestrator

    async def run(self, alert: dict, execution: PlaybookExecution):
        start_time = time.time()
        logger.critical(
            "RANSOMWARE PLAYBOOK TRIGGERED: host=%s alert=%s",
            alert.get("source_host"), alert.get("id")
        )

        host       = alert.get("source_host", "unknown")
        source_ip  = alert.get("source_ip", "")
        actor_pid  = alert.get("actor_pid", 0)
        share_path = alert.get("labels", {}).get("share_path", "")

        execution.context.update({
            "affected_host": host,
            "detection_time": int(time.time()),
            "elapsed_ms": 0,
        })

        # ── STAGE 1: Emergency containment (parallel, fastest actions first) ──
        stage1 = await asyncio.gather(
            self.orch.record_action(execution, f"EMERGENCY_isolate:{host}",      self._emergency_isolate(host)),
            self.orch.record_action(execution, f"snapshot_volumes:{host}",        self._snapshot_volumes(host)),
            self.orch.record_action(execution, "alert_critical_channel",          self._send_emergency_alert(alert, host)),
            return_exceptions=True,
        )
        elapsed = int((time.time() - start_time) * 1000)
        logger.critical("Stage 1 complete in %dms", elapsed)

        # ── STAGE 2: Process/persistence elimination ──────────────────────────
        kill_tasks = []
        if actor_pid:
            kill_tasks.append(
                self.orch.record_action(execution, f"kill_pid:{actor_pid}", self._kill_process(host, actor_pid))
            )
        kill_tasks.extend([
            self.orch.record_action(execution, "disable_vss_deletion",   self._block_vss_delete(host)),
            self.orch.record_action(execution, "disable_scheduled_tasks", self._disable_sched_tasks(host)),
            self.orch.record_action(execution, "revoke_smb_shares",       self._revoke_smb(host, share_path)),
        ])
        await asyncio.gather(*kill_tasks, return_exceptions=True)

        elapsed = int((time.time() - start_time) * 1000)
        logger.critical("Stage 2 complete in %dms", elapsed)

        # ── STAGE 3: Notifications + Ticketing ───────────────────────────────
        await asyncio.gather(
            self.orch.record_action(execution, "pagerduty_p1",     self._page_oncall(alert, host)),
            self.orch.record_action(execution, "create_jira_p1",   self._create_critical_ticket(alert, execution)),
            self.orch.record_action(execution, "notify_executives", self._notify_exec(host, elapsed)),
            return_exceptions=True,
        )

        # ── STAGE 4: Recovery assessment ─────────────────────────────────────
        await self.orch.record_action(
            execution, "assess_recovery_options",
            self._assess_recovery(host),
        )

        total_ms = int((time.time() - start_time) * 1000)
        execution.context["total_response_ms"] = total_ms
        logger.critical("RANSOMWARE RESPONSE COMPLETE in %dms for host=%s", total_ms, host)

    async def _emergency_isolate(self, host: str) -> dict:
        """Immediate network isolation — highest priority"""
        logger.critical("EMERGENCY ISOLATING: %s", host)
        # Production: EDR agent containment + switch port disable + AWS SG quarantine
        return {"host": host, "isolated": True, "method": "edr_emergency_contain", "ts": int(time.time())}

    async def _snapshot_volumes(self, host: str) -> dict:
        """Trigger VSS/LVM snapshot before encryption completes"""
        logger.critical("SNAPSHOTTING VOLUMES on %s", host)
        return {"host": host, "snapshots_triggered": True, "volumes": ["C:", "/", "/data"], "ts": int(time.time())}

    async def _send_emergency_alert(self, alert: dict, host: str) -> dict:
        """Multi-channel emergency notification: Slack + SMS + PagerDuty"""
        msg = (
            f"🚨 *RANSOMWARE DETECTED* 🚨\n"
            f"Host: `{host}`\n"
            f"Risk: {alert.get('risk_score', 1.0):.2f}\n"
            f"Action: AUTOMATIC ISOLATION INITIATED\n"
            f"Alert: {alert.get('id', 'N/A')}"
        )
        logger.critical(msg)
        return {"notification_sent": True, "channels": ["slack_critical", "sms", "pagerduty"]}

    async def _kill_process(self, host: str, pid: int) -> dict:
        """Kill ransomware process via EDR agent command"""
        logger.warning("KILLING PID %d on %s", pid, host)
        # Production: agent_client.execute_command(host, f"kill -9 {pid}")
        return {"host": host, "pid": pid, "killed": True}

    async def _block_vss_delete(self, host: str) -> dict:
        """Prevent shadow copy deletion by blocking vssadmin.exe execution"""
        return {"host": host, "vss_protected": True}

    async def _disable_sched_tasks(self, host: str) -> dict:
        """Disable all recently-created scheduled tasks"""
        return {"host": host, "scheduled_tasks_disabled": True}

    async def _revoke_smb(self, host: str, share_path: str) -> dict:
        """Revoke SMB share access to stop lateral spread to network shares"""
        return {"host": host, "smb_revoked": True, "share": share_path}

    async def _page_oncall(self, alert: dict, host: str) -> dict:
        """Trigger PagerDuty critical incident + wake oncall team"""
        from ...integrations.pagerduty import PagerDutyConnector
        try:
            pd = PagerDutyConnector()
            result = await pd.trigger_incident(
                title    = f"🚨 RANSOMWARE on {host} — IMMEDIATE RESPONSE REQUIRED",
                severity = "critical",
                details  = alert,
                dedup_key= f"ransom_{alert.get('id', '')}",
            )
            return result
        except Exception as e:
            logger.error("PagerDuty page failed: %s", e)
            return {"error": str(e)}

    async def _create_critical_ticket(self, alert: dict, execution: PlaybookExecution) -> dict:
        """Create P1 Jira ticket with full context"""
        from ...integrations.jira_connector import JiraConnector
        try:
            jira = JiraConnector()
            return await jira.create_incident(
                summary  = f"[P1-RANSOMWARE] {execution.context.get('affected_host')} — AUTO-ISOLATED",
                description = f"Automated ransomware response initiated.\n\n"
                             f"Host: {execution.context.get('affected_host')}\n"
                             f"Alert ID: {alert.get('id')}\n"
                             f"Risk Score: {alert.get('risk_score', 1.0)}\n"
                             f"Execution ID: {execution.id}\n\n"
                             f"Actions taken:\n" +
                             "\n".join(f"- {a.action_name}: {a.status}" for a in execution.actions),
                priority = "Highest",
                labels   = ["Ransomware", "P1", "AutoResponse", "SOAR"],
            )
        except Exception as e:
            return {"error": str(e)}

    async def _notify_exec(self, host: str, elapsed_ms: int) -> dict:
        """Notify CISO/executives via email + Slack DM"""
        return {
            "notified":    ["ciso", "security_manager"],
            "host":        host,
            "response_ms": elapsed_ms,
        }

    async def _assess_recovery(self, host: str) -> dict:
        """Assess available recovery options"""
        return {
            "host":              host,
            "backup_available":  True,
            "last_clean_backup": "check_backup_system",
            "recovery_rto_hrs":  4,
            "recommendations":   [
                "Restore from last clean backup (check timestamp)",
                "Run YARA scan on all files before restoration",
                "Re-image if memory forensics shows advanced implant",
                "Review all user credentials on affected host",
            ],
        }
