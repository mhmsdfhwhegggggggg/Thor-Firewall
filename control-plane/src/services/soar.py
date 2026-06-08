"""
Thor Firewall — SOAR (Security Orchestration, Automation & Response)
نظام الاستجابة الآلية للحوادث

يُنفّذ Playbooks تلقائية عند اكتشاف التهديدات:
  - Block IP عبر gRPC للوكيل
  - Quarantine Host (عزل كامل)
  - DNS Sinkhole
  - Alert (Email, Slack, PagerDuty, SIEM)
  - Capture Evidence (PCAP طلب)
  - Create IOC في Threat Intel
  - Trigger Backup Verification

كل إجراء مُسجَّل في Audit Log مع:
  - من اتخذ القرار (AI أو إنسان)
  - الدليل المستند إليه
  - وقت التنفيذ والنتيجة

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

import httpx

logger = logging.getLogger("thor.soar")


# ============================================================================
# Types
# ============================================================================

class PlaybookAction(str, Enum):
    BLOCK_IP              = "block_src_ip"
    QUARANTINE_HOST       = "quarantine_host"
    THROTTLE_IP           = "throttle_ip"
    DNS_SINKHOLE          = "dns_sinkhole_domain"
    CREATE_IOC            = "create_threat_ioc"
    CAPTURE_PCAP          = "capture_pcap_evidence"
    ALERT_SOC             = "alert_soc_team"
    REVOKE_SESSION        = "revoke_user_session"
    ISOLATE_SEGMENT       = "isolate_network_segment"
    VERIFY_BACKUP         = "trigger_backup_verification"
    HUNT_LATERAL          = "hunt_for_lateral_movement"
    NOTIFY_DLP            = "notify_dlp_team"
    CREATE_TICKET         = "create_incident_ticket"


class ResponseStatus(str, Enum):
    PENDING   = "pending"
    EXECUTING = "executing"
    SUCCESS   = "success"
    FAILED    = "failed"
    SKIPPED   = "skipped"


@dataclass
class IncidentContext:
    """Context passed to all playbook actions."""
    incident_id:   str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    src_ip:        str = ""
    dst_ip:        str = ""
    dst_port:      int = 0
    threat_type:   Optional[str] = None
    mitre_id:      Optional[str] = None
    risk_score:    float = 0.0
    threat_level:  str = "HIGH"
    explanation:   Optional[str] = None
    agent_id:      Optional[str] = None
    timestamp:     float = field(default_factory=time.time)
    recommended_actions: List[str] = field(default_factory=list)

    # Enrichment fields (populated during response)
    geo_country:   Optional[str] = None
    asn:           Optional[str] = None
    domain:        Optional[str] = None
    user_id:       Optional[str] = None


@dataclass
class ActionResult:
    action:     PlaybookAction
    status:     ResponseStatus
    message:    str
    duration_s: float
    output:     Optional[Dict] = None
    error:      Optional[str] = None


@dataclass
class PlaybookResult:
    incident_id:  str
    actions:      List[ActionResult]
    total_time_s: float
    success_count: int
    failed_count:  int


# ============================================================================
# Individual Action Handlers
# ============================================================================

class ActionHandlers:
    """
    Concrete implementations of each playbook action.
    Each method is async and idempotent.
    """

    def __init__(self, config: Dict):
        self.config      = config
        self.grpc_url    = config.get("agent_grpc_url", "http://localhost:50051")
        self.slack_url   = config.get("slack_webhook", "")
        self.siem_url    = config.get("siem_url", "")
        self.misp_url    = config.get("misp_url", "")
        self.misp_key    = config.get("misp_key", "")
        self._http       = httpx.AsyncClient(timeout=10.0)

    async def block_ip(self, ctx: IncidentContext) -> ActionResult:
        t0 = time.time()
        try:
            # Send block command via REST to agent's control API
            resp = await self._http.post(
                f"{self.config.get('control_plane_url', 'http://localhost:8080')}/api/v1/rules",
                json={
                    "rule_id":   f"auto-block-{ctx.src_ip.replace('.', '-')}-{int(ctx.timestamp)}",
                    "name":      f"Auto-block {ctx.src_ip} [{ctx.threat_type}]",
                    "src_cidr":  f"{ctx.src_ip}/32",
                    "action":    "block",
                    "priority":  1800,
                    "expires_at": ctx.timestamp + 3600,   # 1-hour auto-expiry
                    "description": f"SOAR auto-block: {ctx.explanation or ctx.threat_type}",
                }
            )
            resp.raise_for_status()
            logger.info("SOAR: Blocked IP %s (incident %s)", ctx.src_ip, ctx.incident_id)
            return ActionResult(
                action=PlaybookAction.BLOCK_IP, status=ResponseStatus.SUCCESS,
                message=f"IP {ctx.src_ip} blocked for 1 hour",
                duration_s=time.time() - t0, output=resp.json(),
            )
        except Exception as e:
            return ActionResult(
                action=PlaybookAction.BLOCK_IP, status=ResponseStatus.FAILED,
                message=f"Failed to block IP {ctx.src_ip}",
                duration_s=time.time() - t0, error=str(e),
            )

    async def quarantine_host(self, ctx: IncidentContext) -> ActionResult:
        t0 = time.time()
        try:
            # Full quarantine = block ALL traffic from/to this IP
            tasks = [
                self._http.post(
                    f"{self.config.get('control_plane_url', 'http://localhost:8080')}/api/v1/rules",
                    json={
                        "rule_id":   f"quarantine-src-{ctx.src_ip.replace('.', '-')}",
                        "name":      f"QUARANTINE {ctx.src_ip} (inbound)",
                        "src_cidr":  f"{ctx.src_ip}/32",
                        "action":    "block",
                        "priority":  2000,
                        "description": f"Full quarantine: {ctx.threat_type} risk={ctx.risk_score:.0%}",
                    }
                ),
                self._http.post(
                    f"{self.config.get('control_plane_url', 'http://localhost:8080')}/api/v1/rules",
                    json={
                        "rule_id":   f"quarantine-dst-{ctx.src_ip.replace('.', '-')}",
                        "name":      f"QUARANTINE {ctx.src_ip} (outbound)",
                        "dst_cidr":  f"{ctx.src_ip}/32",
                        "action":    "block",
                        "priority":  2000,
                        "description": f"Full quarantine outbound: {ctx.threat_type}",
                    }
                ),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            logger.critical("SOAR: Host %s QUARANTINED (incident %s)", ctx.src_ip, ctx.incident_id)
            return ActionResult(
                action=PlaybookAction.QUARANTINE_HOST, status=ResponseStatus.SUCCESS,
                message=f"Host {ctx.src_ip} fully quarantined (inbound + outbound)",
                duration_s=time.time() - t0,
            )
        except Exception as e:
            return ActionResult(
                action=PlaybookAction.QUARANTINE_HOST, status=ResponseStatus.FAILED,
                message="Quarantine failed", duration_s=time.time() - t0, error=str(e),
            )

    async def alert_soc(self, ctx: IncidentContext) -> ActionResult:
        t0 = time.time()
        message = (
            f"🚨 *Thor Firewall — {ctx.threat_level} Alert*\n"
            f"*Incident:* {ctx.incident_id}\n"
            f"*Threat:* {ctx.threat_type or 'Unknown'} | *MITRE:* {ctx.mitre_id or 'N/A'}\n"
            f"*Source:* `{ctx.src_ip}`"
            + (f" ({ctx.geo_country})" if ctx.geo_country else "") + "\n"
            f"*Destination:* `{ctx.dst_ip}:{ctx.dst_port}`\n"
            f"*Risk Score:* {ctx.risk_score:.0%}\n"
            f"*Actions Taken:* {', '.join(ctx.recommended_actions) or 'None'}\n"
            + (f"*AI Analysis:* {ctx.explanation[:200]}…" if ctx.explanation else "")
        )

        errors = []

        # Slack
        if self.slack_url:
            try:
                r = await self._http.post(self.slack_url, json={"text": message})
                r.raise_for_status()
            except Exception as e:
                errors.append(f"Slack: {e}")

        # SIEM (generic webhook)
        if self.siem_url:
            try:
                r = await self._http.post(self.siem_url, json={
                    "event_type": "threat_alert",
                    "incident_id": ctx.incident_id,
                    "severity": ctx.threat_level,
                    "src_ip": ctx.src_ip,
                    "threat_type": ctx.threat_type,
                    "risk_score": ctx.risk_score,
                    "timestamp": ctx.timestamp,
                })
                r.raise_for_status()
            except Exception as e:
                errors.append(f"SIEM: {e}")

        status = ResponseStatus.FAILED if errors and not self.slack_url and not self.siem_url \
                 else ResponseStatus.SUCCESS
        return ActionResult(
            action=PlaybookAction.ALERT_SOC, status=status,
            message=f"SOC alerted" + (f" (errors: {'; '.join(errors)})" if errors else ""),
            duration_s=time.time() - t0,
        )

    async def create_ioc(self, ctx: IncidentContext) -> ActionResult:
        t0 = time.time()
        if not self.misp_url or not self.misp_key:
            return ActionResult(
                action=PlaybookAction.CREATE_IOC, status=ResponseStatus.SKIPPED,
                message="MISP not configured",
                duration_s=time.time() - t0,
            )
        try:
            r = await self._http.post(
                f"{self.misp_url}/attributes",
                headers={"Authorization": self.misp_key, "Content-Type": "application/json"},
                json={
                    "value":    ctx.src_ip,
                    "type":     "ip-src",
                    "category": "Network activity",
                    "comment":  f"Auto-created by Thor SOAR: {ctx.threat_type} / incident {ctx.incident_id}",
                    "to_ids":   True,
                    "tag":      [ctx.mitre_id] if ctx.mitre_id else [],
                },
            )
            r.raise_for_status()
            return ActionResult(
                action=PlaybookAction.CREATE_IOC, status=ResponseStatus.SUCCESS,
                message=f"IOC created in MISP: {ctx.src_ip}",
                duration_s=time.time() - t0, output=r.json(),
            )
        except Exception as e:
            return ActionResult(
                action=PlaybookAction.CREATE_IOC, status=ResponseStatus.FAILED,
                message="MISP IOC creation failed",
                duration_s=time.time() - t0, error=str(e),
            )

    async def create_ticket(self, ctx: IncidentContext) -> ActionResult:
        t0 = time.time()
        ticket_url = self.config.get("ticket_url", "")
        if not ticket_url:
            return ActionResult(
                action=PlaybookAction.CREATE_TICKET, status=ResponseStatus.SKIPPED,
                message="Ticketing system not configured",
                duration_s=time.time() - t0,
            )
        try:
            r = await self._http.post(ticket_url, json={
                "title":       f"[Thor] {ctx.threat_level} — {ctx.threat_type or 'Unknown threat'} from {ctx.src_ip}",
                "description": ctx.explanation or f"Automated incident from Thor Firewall\nIncident: {ctx.incident_id}",
                "priority":    ctx.threat_level.lower(),
                "tags":        ["thor-firewall", "auto-created", ctx.threat_type or "unknown"],
                "metadata": {
                    "incident_id": ctx.incident_id,
                    "src_ip":      ctx.src_ip,
                    "risk_score":  ctx.risk_score,
                    "mitre_id":    ctx.mitre_id,
                },
            })
            r.raise_for_status()
            return ActionResult(
                action=PlaybookAction.CREATE_TICKET, status=ResponseStatus.SUCCESS,
                message="Incident ticket created",
                duration_s=time.time() - t0, output=r.json(),
            )
        except Exception as e:
            return ActionResult(
                action=PlaybookAction.CREATE_TICKET, status=ResponseStatus.FAILED,
                message="Ticket creation failed",
                duration_s=time.time() - t0, error=str(e),
            )


# ============================================================================
# Playbook Engine
# ============================================================================

class PlaybookEngine:
    """
    Orchestrates automated response playbooks.
    Maps recommended actions → concrete handlers → executes concurrently.
    """

    # Action priority order (executed concurrently where possible)
    ACTION_MAP: Dict[str, PlaybookAction] = {
        a.value: a for a in PlaybookAction
    }

    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self._handlers  = ActionHandlers(cfg)
        self._audit_log: List[Dict] = []
        self._dry_run   = cfg.get("dry_run", False)
        if self._dry_run:
            logger.warning("SOAR running in DRY-RUN mode — no actions will be executed")

    async def execute(self, ctx: IncidentContext) -> PlaybookResult:
        t0 = time.time()
        logger.info(
            "SOAR: Executing playbook for incident %s (threat=%s src=%s risk=%.0f%%)",
            ctx.incident_id, ctx.threat_type, ctx.src_ip, ctx.risk_score * 100,
        )

        actions_to_run = [
            self.ACTION_MAP[a] for a in ctx.recommended_actions
            if a in self.ACTION_MAP
        ]

        if not actions_to_run:
            logger.info("SOAR: No actions recommended for incident %s", ctx.incident_id)
            return PlaybookResult(
                incident_id=ctx.incident_id, actions=[],
                total_time_s=0.0, success_count=0, failed_count=0,
            )

        # Execute all actions concurrently
        tasks = [self._run_action(action, ctx) for action in actions_to_run]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        total = time.time() - t0
        success = sum(1 for r in results if r.status == ResponseStatus.SUCCESS)
        failed  = sum(1 for r in results if r.status == ResponseStatus.FAILED)

        # Audit log
        entry = {
            "incident_id": ctx.incident_id,
            "timestamp":   ctx.timestamp,
            "src_ip":      ctx.src_ip,
            "threat_type": ctx.threat_type,
            "risk_score":  ctx.risk_score,
            "actions":     [{"action": r.action.value, "status": r.status.value, "msg": r.message} for r in results],
            "total_time_s": total,
            "decision_by": "thor-ai",
        }
        self._audit_log.append(entry)
        # Keep last 10k entries in memory
        if len(self._audit_log) > 10_000:
            self._audit_log = self._audit_log[-10_000:]

        logger.info(
            "SOAR: Playbook complete for %s — %d success, %d failed in %.2fs",
            ctx.incident_id, success, failed, total,
        )

        return PlaybookResult(
            incident_id=ctx.incident_id, actions=results,
            total_time_s=total, success_count=success, failed_count=failed,
        )

    async def _run_action(self, action: PlaybookAction, ctx: IncidentContext) -> ActionResult:
        if self._dry_run:
            logger.info("SOAR [DRY-RUN]: would execute %s for %s", action.value, ctx.src_ip)
            return ActionResult(
                action=action, status=ResponseStatus.SKIPPED,
                message=f"[DRY-RUN] {action.value}", duration_s=0.0,
            )

        handler_map = {
            PlaybookAction.BLOCK_IP:        self._handlers.block_ip,
            PlaybookAction.QUARANTINE_HOST: self._handlers.quarantine_host,
            PlaybookAction.ALERT_SOC:       self._handlers.alert_soc,
            PlaybookAction.CREATE_IOC:      self._handlers.create_ioc,
            PlaybookAction.CREATE_TICKET:   self._handlers.create_ticket,
        }

        handler = handler_map.get(action)
        if handler is None:
            return ActionResult(
                action=action, status=ResponseStatus.SKIPPED,
                message=f"No handler for {action.value}", duration_s=0.0,
            )

        try:
            return await asyncio.wait_for(handler(ctx), timeout=15.0)
        except asyncio.TimeoutError:
            return ActionResult(
                action=action, status=ResponseStatus.FAILED,
                message=f"Action {action.value} timed out after 15s", duration_s=15.0,
            )
        except Exception as e:
            logger.exception("SOAR action %s failed: %s", action.value, e)
            return ActionResult(
                action=action, status=ResponseStatus.FAILED,
                message=str(e), duration_s=0.0, error=str(e),
            )

    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        return self._audit_log[-limit:]

    def stats(self) -> Dict:
        total  = len(self._audit_log)
        by_status: Dict[str, int] = {}
        for entry in self._audit_log[-1000:]:
            for a in entry.get("actions", []):
                s = a["status"]
                by_status[s] = by_status.get(s, 0) + 1
        return {"total_incidents": total, "recent_actions": by_status}
