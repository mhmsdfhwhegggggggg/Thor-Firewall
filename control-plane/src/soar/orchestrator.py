"""
SOAR Orchestrator — Automated Security Orchestration, Automation and Response
Executes playbooks based on alert triggers, manages action queues and audit trails
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine

logger = logging.getLogger("thor.soar")

class PlaybookStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    SUCCESS   = "success"
    FAILED    = "failed"
    PARTIAL   = "partial"
    CANCELLED = "cancelled"

class ActionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED  = "failed"
    SKIPPED = "skipped"

@dataclass
class ActionResult:
    action_name: str
    status:      ActionStatus
    output:      Any  = None
    error:       str  = ""
    duration_ms: int  = 0
    timestamp:   int  = field(default_factory=lambda: int(time.time() * 1000))

@dataclass
class PlaybookExecution:
    id:          str = field(default_factory=lambda: str(uuid.uuid4()))
    playbook:    str = ""
    trigger_id:  str = ""
    status:      PlaybookStatus = PlaybookStatus.PENDING
    actions:     list[ActionResult] = field(default_factory=list)
    started_at:  int = 0
    finished_at: int = 0
    context:     dict = field(default_factory=dict)
    approved_by: str = ""

    @property
    def duration_ms(self) -> int:
        if self.finished_at and self.started_at:
            return self.finished_at - self.started_at
        return 0

class SOAROrchestrator:
    """
    Central SOAR engine.
    - Registers playbooks by trigger type
    - Executes action chains with error handling and rollback
    - Integrates with ticketing, messaging, and enforcement systems
    - Maintains full audit trail in ClickHouse
    """

    def __init__(self, ch_client=None, redis_client=None, require_approval: bool = False):
        self.ch              = ch_client
        self.redis           = redis_client
        self.require_approval= require_approval
        self._playbooks:  dict[str, Callable] = {}
        self._executions: dict[str, PlaybookExecution] = {}
        self._pending_approvals: dict[str, asyncio.Event] = {}
        self._register_builtin_playbooks()

    def _register_builtin_playbooks(self):
        from .playbooks.apt_response        import AptResponsePlaybook
        from .playbooks.ransomware_response import RansomwareResponsePlaybook
        from .playbooks.insider_threat_response import InsiderThreatPlaybook

        self.register("apt_lateral_movement",  AptResponsePlaybook(self).run)
        self.register("ransomware_detected",    RansomwareResponsePlaybook(self).run)
        self.register("insider_threat",         InsiderThreatPlaybook(self).run)

    def register(self, trigger: str, handler: Callable):
        self._playbooks[trigger] = handler
        logger.info("Registered playbook: %s", trigger)

    async def trigger(
        self,
        trigger_type: str,
        alert: dict,
        context: dict | None = None,
    ) -> PlaybookExecution:
        """
        Trigger a playbook for a given alert.
        Returns PlaybookExecution tracking object immediately (async execution).
        """
        handler = self._playbooks.get(trigger_type)
        if not handler:
            # Try to find partial match
            for key in self._playbooks:
                if key in trigger_type or trigger_type in key:
                    handler = self._playbooks[key]
                    break

        execution = PlaybookExecution(
            playbook   = trigger_type,
            trigger_id = alert.get("id", ""),
            status     = PlaybookStatus.PENDING,
            context    = {**(context or {}), "alert": alert},
        )
        self._executions[execution.id] = execution

        if handler:
            asyncio.create_task(self._execute(execution, handler, alert))
        else:
            logger.warning("No playbook for trigger: %s", trigger_type)
            execution.status = PlaybookStatus.FAILED
            execution.actions.append(ActionResult(
                action_name="lookup_playbook",
                status=ActionStatus.FAILED,
                error=f"No playbook registered for trigger: {trigger_type}",
            ))

        return execution

    async def _execute(
        self,
        execution: PlaybookExecution,
        handler: Callable,
        alert: dict,
    ):
        execution.status     = PlaybookStatus.RUNNING
        execution.started_at = int(time.time() * 1000)

        logger.info(
            "SOAR executing playbook=%s execution_id=%s alert_id=%s",
            execution.playbook, execution.id, execution.trigger_id
        )

        try:
            await handler(alert, execution)
            failed = [a for a in execution.actions if a.status == ActionStatus.FAILED]
            execution.status = PlaybookStatus.PARTIAL if failed else PlaybookStatus.SUCCESS
        except Exception as e:
            logger.error("Playbook %s failed: %s", execution.playbook, e, exc_info=True)
            execution.status = PlaybookStatus.FAILED
            execution.actions.append(ActionResult(
                action_name="playbook_runner",
                status=ActionStatus.FAILED,
                error=str(e),
            ))
        finally:
            execution.finished_at = int(time.time() * 1000)

        logger.info(
            "SOAR completed playbook=%s status=%s duration=%dms actions=%d",
            execution.playbook, execution.status,
            execution.duration_ms, len(execution.actions),
        )

        await self._persist(execution)

        if self.redis:
            await self.redis.publish(
                "thor:soar:executions",
                json.dumps({
                    "id":       execution.id,
                    "playbook": execution.playbook,
                    "status":   execution.status,
                    "alert_id": execution.trigger_id,
                })
            )

    async def record_action(
        self,
        execution: PlaybookExecution,
        name: str,
        coro: Coroutine,
        critical: bool = False,
    ) -> ActionResult:
        """Execute a single action and record the result"""
        start = time.time()
        result = ActionResult(action_name=name, status=ActionStatus.RUNNING)
        execution.actions.append(result)

        try:
            output       = await coro
            result.status = ActionStatus.SUCCESS
            result.output = output
            logger.debug("Action %s: SUCCESS", name)
        except Exception as e:
            result.status = ActionStatus.FAILED
            result.error  = str(e)
            logger.error("Action %s FAILED: %s", name, e)
            if critical:
                raise

        result.duration_ms = int((time.time() - start) * 1000)
        return result

    async def _persist(self, execution: PlaybookExecution):
        if not self.ch:
            return
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.ch.insert(
                    "thor.soar_executions",
                    [[
                        execution.id,
                        execution.trigger_id,
                        execution.playbook,
                        execution.status,
                        execution.started_at,
                        execution.finished_at,
                        execution.duration_ms,
                        len(execution.actions),
                        sum(1 for a in execution.actions if a.status == ActionStatus.SUCCESS),
                        sum(1 for a in execution.actions if a.status == ActionStatus.FAILED),
                        json.dumps([{
                            "name": a.action_name,
                            "status": a.status,
                            "duration_ms": a.duration_ms,
                            "error": a.error,
                        } for a in execution.actions]),
                        execution.approved_by,
                    ]],
                    column_names=[
                        "id","trigger_id","playbook","status",
                        "started_at","finished_at","duration_ms",
                        "total_actions","success_actions","failed_actions",
                        "action_log","approved_by",
                    ],
                )
            )
        except Exception as e:
            logger.error("Failed to persist SOAR execution: %s", e)

    def get_execution(self, exec_id: str) -> PlaybookExecution | None:
        return self._executions.get(exec_id)

    def list_executions(self, limit: int = 100) -> list[PlaybookExecution]:
        return list(self._executions.values())[-limit:]
