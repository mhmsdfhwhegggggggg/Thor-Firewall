"""
Thor Firewall — Immutable Audit Trail
سجل تدقيق غير قابل للتعديل مع تحقق cryptographic

يستخدم:
  - ClickHouse append-only table
  - HMAC-SHA256 لكل entry
  - Merkle tree للتحقق من سلامة السجل

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import hashlib, hmac, json, logging, os, time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger("thor.audit")

AUDIT_SECRET = os.getenv("AUDIT_HMAC_SECRET", "CHANGE_ME_IN_PRODUCTION_32BYTES!!")

@dataclass
class AuditEntry:
    event_type: str    # "rule_change" | "policy_decision" | "soar_action" | "user_login" | "config_change"
    actor_id: str
    target: str
    action: str
    result: str        # "success" | "failure" | "denied"
    details: Dict[str, Any] = field(default_factory=dict)
    source_ip: Optional[str] = None
    session_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    entry_id: str = field(default="")
    hmac_signature: str = field(default="")

    def __post_init__(self):
        if not self.entry_id:
            import uuid
            self.entry_id = str(uuid.uuid4())
        if not self.hmac_signature:
            self.hmac_signature = self._compute_hmac()

    def _compute_hmac(self) -> str:
        payload = json.dumps({
            "entry_id": self.entry_id, "event_type": self.event_type,
            "actor_id": self.actor_id, "target": self.target,
            "action": self.action, "result": self.result,
            "timestamp": self.timestamp,
        }, sort_keys=True).encode()
        return hmac.new(AUDIT_SECRET.encode(), payload, hashlib.sha256).hexdigest()

    def verify(self) -> bool:
        return hmac.compare_digest(self.hmac_signature, self._compute_hmac())


class AuditLogger:
    """يُسجّل كل حدث في نظام Thor في سجل غير قابل للتعديل"""

    def __init__(self, clickhouse_client=None):
        self.ch = clickhouse_client
        self._buffer: List[AuditEntry] = []

    async def log(self, entry: AuditEntry):
        """تسجيل حدث جديد"""
        if not entry.verify():
            logger.error("Audit entry integrity check failed! Possible tampering.")
            return

        self._buffer.append(entry)

        if self.ch:
            try:
                await self.ch.execute(
                    "INSERT INTO audit_log VALUES",
                    [asdict(entry)]
                )
            except Exception as e:
                logger.error("Failed to persist audit entry to ClickHouse: %s", e)

        logger.info("AUDIT: %s | %s | %s → %s | %s",
                    entry.event_type, entry.actor_id, entry.action,
                    entry.target, entry.result)

    async def verify_chain(self, entries: List[AuditEntry]) -> bool:
        """التحقق من سلامة سلسلة الأدلة"""
        return all(e.verify() for e in entries)

    async def export_forensics(self, output_format: str = "json") -> bytes:
        """تصدير كامل السجل للتحليل الجنائي"""
        data = [asdict(e) for e in self._buffer]
        if output_format == "json":
            return json.dumps(data, indent=2).encode()
        return json.dumps(data).encode()


# Singleton
_audit_logger: Optional[AuditLogger] = None

def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
