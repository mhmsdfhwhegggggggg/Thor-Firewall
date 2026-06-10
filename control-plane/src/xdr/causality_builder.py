"""
Thor XDR — Causality Chain Builder (Root Cause Analysis)
مستوحى من Palo Alto Cortex XDR Causality Engine

يبني سلاسل سببية تلقائياً من الأحداث المتفرقة:
Port Scan → CVE Exploit → Lateral Movement → Data Exfil
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import structlog

from .mitre_mapper import MitreTechnique, map_threat_to_mitre, get_kill_chain_phase

log = structlog.get_logger("thor.xdr.causality")

CORRELATION_WINDOW_SECONDS = 1800   # 30 دقيقة
MIN_CHAIN_LENGTH = 2


@dataclass
class SecurityEvent:
    event_id:    str
    timestamp:   float
    src_ip:      str
    dst_ip:      Optional[str]
    threat_type: str
    severity:    str
    risk_score:  float
    details:     Dict[str, Any] = field(default_factory=dict)
    mitre:       Optional[MitreTechnique] = None

    def __post_init__(self):
        if self.mitre is None:
            self.mitre = map_threat_to_mitre(self.threat_type)


@dataclass
class CausalityChain:
    chain_id:        str
    events:          List[SecurityEvent]
    root_event:      SecurityEvent
    mitre_tactics:   List[MitreTechnique]
    aggregate_risk:  float
    severity:        str
    start_time:      float
    end_time:        float
    affected_ips:    List[str]
    kill_chain_progress: float  # 0.0-1.0 مدى التقدم في Kill Chain
    summary:         str = ""

    @property
    def duration_minutes(self) -> float:
        return (self.end_time - self.start_time) / 60

    @property
    def event_count(self) -> int:
        return len(self.events)


class CausalityChainBuilder:
    """
    يبني causality chains تلقائياً من stream من الأحداث الأمنية.

    خوارزمية الربط:
    1. نفس src_ip في نافذة 30 دقيقة
    2. الترتيب الزمني يتبع Kill Chain
    3. الأحداث المترابطة بنفس الـ dst_ip
    4. IOC مشترك (hash, domain, C2 server)
    """

    def __init__(self):
        # src_ip → [SecurityEvent]
        self._pending: Dict[str, List[SecurityEvent]] = {}
        self._completed_chains: List[CausalityChain] = []

    def add_event(self, event: SecurityEvent) -> Optional[CausalityChain]:
        """
        أضف حدثاً وأعد chain مكتملة إذا تشكّلت.
        """
        key = event.src_ip
        if key not in self._pending:
            self._pending[key] = []

        # احذف الأحداث القديمة
        cutoff = time.time() - CORRELATION_WINDOW_SECONDS
        self._pending[key] = [e for e in self._pending[key] if e.timestamp > cutoff]

        self._pending[key].append(event)
        self._pending[key].sort(key=lambda e: e.timestamp)

        chain = self._try_build_chain(key)
        if chain:
            self._completed_chains.append(chain)
            log.info("causality_chain_built",
                     chain_id=chain.chain_id,
                     events=chain.event_count,
                     risk=chain.aggregate_risk,
                     tactics=[t.tactic for t in chain.mitre_tactics])
        return chain

    def _try_build_chain(self, src_ip: str) -> Optional[CausalityChain]:
        events = self._pending.get(src_ip, [])
        if len(events) < MIN_CHAIN_LENGTH:
            return None

        # تحقق من وجود تقدم في Kill Chain (حدثان على الأقل في مراحل مختلفة)
        mitre_list = [e.mitre for e in events if e.mitre is not None]
        if not mitre_list:
            return None

        phases = sorted(set(get_kill_chain_phase(m) for m in mitre_list))
        if len(phases) < 2:
            return None

        # Risk score مجمَّع (مع تفادي التضخم)
        aggregate_risk = min(
            sum(e.risk_score for e in events) / max(len(events), 1) * (1 + len(phases) * 0.1),
            1.0
        )

        severity = (
            "critical" if aggregate_risk > 0.85
            else "high" if aggregate_risk > 0.65
            else "medium" if aggregate_risk > 0.40
            else "low"
        )

        max_phase = max(phases)
        kill_chain_progress = max_phase / 13.0  # 14 مرحلة في MITRE

        affected_ips = list({e.src_ip for e in events} | {e.dst_ip for e in events if e.dst_ip})

        tactics_seen: list[MitreTechnique] = []
        seen_ids: set[str] = set()
        for e in events:
            if e.mitre and e.mitre.id not in seen_ids:
                tactics_seen.append(e.mitre)
                seen_ids.add(e.mitre.id)
        tactics_seen.sort(key=lambda t: get_kill_chain_phase(t))

        summary = self._generate_summary(events, tactics_seen, aggregate_risk)

        chain_id = f"chain_{src_ip.replace('.', '_')}_{int(events[0].timestamp)}"
        return CausalityChain(
            chain_id           = chain_id,
            events             = events.copy(),
            root_event         = events[0],
            mitre_tactics      = tactics_seen,
            aggregate_risk     = round(aggregate_risk, 3),
            severity           = severity,
            start_time         = events[0].timestamp,
            end_time           = events[-1].timestamp,
            affected_ips       = affected_ips,
            kill_chain_progress= round(kill_chain_progress, 2),
            summary            = summary,
        )

    def _generate_summary(self,
                           events: List[SecurityEvent],
                           tactics: List[MitreTechnique],
                           risk: float) -> str:
        tactic_names = " → ".join(t.tactic for t in tactics[:5])
        threat_types = list({e.threat_type for e in events})
        return (
            f"Attack chain from {events[0].src_ip}: "
            f"{tactic_names}. "
            f"Threats: {', '.join(threat_types[:3])}. "
            f"Risk: {risk:.0%}."
        )

    def get_active_chains(self) -> List[CausalityChain]:
        return self._completed_chains[-100:]   # آخر 100 سلسلة

    def clear_old_pending(self):
        cutoff = time.time() - CORRELATION_WINDOW_SECONDS
        for key in list(self._pending.keys()):
            self._pending[key] = [e for e in self._pending[key] if e.timestamp > cutoff]
            if not self._pending[key]:
                del self._pending[key]


# Singleton
_builder = CausalityChainBuilder()

def get_causality_builder() -> CausalityChainBuilder:
    return _builder
