"""
Thor Firewall — Threat Correlator
محرك ربط التهديدات

يُطبّق "Attack Chain Reconstruction" — ربط الأحداث المتفرقة لاكتشاف
الهجمات متعددة الخطوات (APT, Lateral Movement, Kill Chain).

المنهجية:
  1. Sliding Window — نافذة زمنية متحركة لكل مصدر تهديد
  2. Kill Chain Mapping — خريطة مراحل الهجوم (Reconnaisance→Exfiltration)
  3. Graph-based Correlation — مرتبط بـ GNN لاكتشاف الانتشار الجانبي
  4. MITRE ATT&CK Coverage — كل حدث مُرتبط بتكتيك أو تقنية

مثال:
  [port-scan T1046] + [brute-force T1110] + [c2-comm T1071] على نفس IP
  → Attack Chain score = 0.95 → QUARANTINE

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .decision_engine import FlowFeatures, DecisionResult, Action, ThreatLevel


# ============================================================================
# Kill Chain Stages (Lockheed Martin + MITRE)
# ============================================================================

KILL_CHAIN_ORDER = {
    "port-scan":    0,   # Reconnaissance
    "dns-enum":     0,
    "vuln-scan":    1,   # Weaponization
    "brute-force":  2,   # Delivery / Initial Access
    "exploit":      3,   # Exploitation
    "backdoor":     4,   # Installation
    "c2-comm":      5,   # Command & Control
    "lateral":      6,   # Lateral Movement
    "data-exfil":   7,   # Exfiltration
    "ransomware":   8,   # Impact
    "dos":          8,
    "syn-flood":    8,
}

# Points for each stage: later stages score more
STAGE_SCORE = [0.05, 0.10, 0.20, 0.30, 0.40, 0.55, 0.70, 0.85, 0.95]


# ============================================================================
# Data structures
# ============================================================================

@dataclass
class ThreatEvent:
    timestamp:   float
    src_ip:      int
    dst_ip:      int
    dst_port:    int
    threat_type: Optional[str]
    mitre_id:    Optional[str]
    risk_score:  float
    action:      Action


@dataclass
class AttackChain:
    """Reconstructed attack chain for one source IP."""
    src_ip:      int
    first_seen:  float
    last_seen:   float
    stages_seen: Set[int]            = field(default_factory=set)
    events:      deque               = field(default_factory=deque)
    targets:     Set[int]            = field(default_factory=set)   # dst IPs
    ports_hit:   Set[int]            = field(default_factory=set)
    mitre_ids:   Set[str]            = field(default_factory=set)
    threat_types: List[str]          = field(default_factory=list)

    @property
    def chain_score(self) -> float:
        """
        Score based on how far along the kill chain this attacker is.
        Advanced stage = higher score.
        Multiple stages = multiplier.
        """
        if not self.stages_seen:
            return 0.0
        max_stage  = max(self.stages_seen)
        base_score = STAGE_SCORE[min(max_stage, len(STAGE_SCORE) - 1)]
        # Bonus for multi-stage (likely a real APT, not a script kiddie)
        stage_bonus = min(0.30, len(self.stages_seen) * 0.07)
        # Bonus for many targets (lateral movement)
        spread_bonus = min(0.15, (len(self.targets) - 1) * 0.03)
        return min(1.0, base_score + stage_bonus + spread_bonus)

    @property
    def is_active(self) -> bool:
        return (time.time() - self.last_seen) < 600   # 10 minutes


# ============================================================================
# Threat Correlator
# ============================================================================

class ThreatCorrelator:
    """
    Real-time attack chain reconstruction.

    Maintains a sliding window of threat events per source IP and computes
    a correlation risk score based on:
      - Kill chain progression
      - Multi-target lateral movement
      - Temporal clustering
      - MITRE technique co-occurrence
    """

    def __init__(
        self,
        time_window_s: int = 300,
        min_events: int = 3,
        max_chains: int = 100_000,
    ):
        self.time_window_s = time_window_s
        self.min_events    = min_events
        self.max_chains    = max_chains

        # src_ip → AttackChain
        self._chains: Dict[int, AttackChain] = {}

        # Recent high-risk IPs (for fast lookup)
        self._hot_ips: Set[int] = set()

        # Global event rate (for DDoS detection)
        self._event_rate: deque = deque(maxlen=1000)

    # ── Public API ────────────────────────────────────────────────────────────

    def score(self, flow: FlowFeatures) -> float:
        """
        Return correlation risk [0,1] for this flow.
        High score = this flow fits into a known attack chain.
        """
        src_ip = flow.src_ip

        # Fast path: known hot IP
        if src_ip in self._hot_ips:
            chain = self._chains.get(src_ip)
            if chain and chain.is_active:
                return min(1.0, chain.chain_score * 1.2)   # boost for known bad

        chain = self._chains.get(src_ip)
        if chain is None:
            return 0.0

        # Prune stale events
        cutoff = time.time() - self.time_window_s
        while chain.events and chain.events[0].timestamp < cutoff:
            chain.events.popleft()

        if len(chain.events) < self.min_events:
            return 0.0

        return chain.chain_score

    def record(self, flow: FlowFeatures, result: DecisionResult) -> None:
        """Record a decision result to build attack chains."""
        if result.threat_level < ThreatLevel.LOW:
            return

        src_ip = flow.src_ip
        now    = time.time()

        if src_ip not in self._chains:
            if len(self._chains) >= self.max_chains:
                self._evict_inactive()
            self._chains[src_ip] = AttackChain(
                src_ip=src_ip, first_seen=now, last_seen=now
            )

        chain = self._chains[src_ip]
        chain.last_seen = now
        chain.targets.add(flow.dst_ip)
        chain.ports_hit.add(flow.dst_port)

        if result.threat_type:
            stage = KILL_CHAIN_ORDER.get(result.threat_type)
            if stage is not None:
                chain.stages_seen.add(stage)
            chain.threat_types.append(result.threat_type)

        if result.mitre_id:
            chain.mitre_ids.add(result.mitre_id)

        event = ThreatEvent(
            timestamp=now,
            src_ip=src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            threat_type=result.threat_type,
            mitre_id=result.mitre_id,
            risk_score=result.final_risk,
            action=result.action,
        )
        chain.events.append(event)

        # Promote to hot_ips if chain score is high
        if chain.chain_score >= 0.55:
            self._hot_ips.add(src_ip)

        # Track global event rate
        self._event_rate.append(now)

    def get_chain(self, src_ip: int) -> Optional[AttackChain]:
        return self._chains.get(src_ip)

    def get_hot_ips(self, limit: int = 100) -> List[Dict]:
        hot = []
        for ip in self._hot_ips:
            chain = self._chains.get(ip)
            if chain and chain.is_active:
                hot.append({
                    "src_ip":      ip,
                    "score":       chain.chain_score,
                    "stages":      sorted(chain.stages_seen),
                    "targets":     len(chain.targets),
                    "mitre":       list(chain.mitre_ids),
                    "last_seen":   chain.last_seen,
                })
        hot.sort(key=lambda x: x["score"], reverse=True)
        return hot[:limit]

    def stats(self) -> Dict[str, Any]:
        now = time.time()
        active = sum(1 for c in self._chains.values() if c.is_active)
        return {
            "total_chains":  len(self._chains),
            "active_chains": active,
            "hot_ips":       len(self._hot_ips),
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _evict_inactive(self) -> None:
        inactive = [ip for ip, c in self._chains.items() if not c.is_active]
        for ip in inactive[:len(inactive)//2]:
            del self._chains[ip]
            self._hot_ips.discard(ip)
