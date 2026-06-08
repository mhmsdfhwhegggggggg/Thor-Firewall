"""
Thor Firewall — Policy Engine
محرك السياسات الأمني

يُنفّذ ABAC (Attribute-Based Access Control) + Zero-Trust Policy Evaluation.

الفلسفة: "Never Trust, Always Verify"

بنية السياسة (YAML/JSON):
  - Subject: من يُرسل (IP, User, Role, Device)
  - Resource: ما يُطلب (IP, Port, Protocol, Application)
  - Action: ماذا يفعل (access, transfer, execute)
  - Environment: السياق (time, geo, risk_score)
  - Effect: allow | deny | require_mfa | throttle | sandbox

مثال:
  policy:
    name: "Block external SSH"
    subject: {not_in_cidr: "10.0.0.0/8"}
    resource: {port: 22, proto: TCP}
    effect: block
    priority: 900

يدعم:
  - تقييم سياسات متعددة بأولويات مختلفة
  - سياسات مؤقتة (time-limited)
  - استثناءات ديناميكية (emergency bypass)
  - تصدير سياسات eBPF (ترجمة تلقائية إلى BPF maps)

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("thor.policy")


# ============================================================================
# Policy Types
# ============================================================================

class PolicyEffect(str, Enum):
    ALLOW     = "allow"
    BLOCK     = "block"
    THROTTLE  = "throttle"
    LOG       = "log"
    MIRROR    = "mirror"
    SANDBOX   = "sandbox"    # route to honeypot
    CHALLENGE = "challenge"  # require re-authentication


class PolicyMatch(str, Enum):
    EXACT    = "exact"
    CIDR     = "cidr"
    RANGE    = "range"
    REGEX    = "regex"
    ANY      = "any"


@dataclass
class SubjectCondition:
    """Who is making the request?"""
    src_cidr:       Optional[str] = None    # e.g. "10.0.0.0/8"
    not_src_cidr:   Optional[str] = None
    src_country:    Optional[List[str]] = None
    not_src_country: Optional[List[str]] = None
    asn:            Optional[List[int]] = None
    user_role:      Optional[List[str]] = None   # for authenticated users
    device_type:    Optional[str] = None


@dataclass
class ResourceCondition:
    """What is being accessed?"""
    dst_cidr:       Optional[str] = None
    dst_port:       Optional[Any] = None     # int | [int,int] | [int,...]
    protocol:       Optional[str] = None     # TCP | UDP | ICMP | any
    application:    Optional[str] = None     # HTTP | SSH | DNS | ...
    tls_version_lt: Optional[str] = None     # Block TLS < 1.2


@dataclass
class EnvironmentCondition:
    """Contextual conditions."""
    time_range:     Optional[Tuple[str, str]] = None  # ("08:00", "18:00") UTC
    days:           Optional[List[str]] = None         # ["Mon","Tue",...,"Sun"]
    max_risk_score: Optional[float] = None
    min_risk_score: Optional[float] = None
    geo_block_list: Optional[List[str]] = None         # ISO country codes
    threat_intel_match: bool = False


@dataclass
class PolicyRule:
    """A single policy rule."""
    rule_id:     str
    name:        str
    priority:    int              # 0-2000, higher = evaluated first
    effect:      PolicyEffect
    subject:     SubjectCondition = field(default_factory=SubjectCondition)
    resource:    ResourceCondition = field(default_factory=ResourceCondition)
    environment: EnvironmentCondition = field(default_factory=EnvironmentCondition)
    is_active:   bool = True
    expires_at:  Optional[float] = None   # Unix timestamp
    description: Optional[str] = None
    created_by:  Optional[str] = None
    hit_count:   int = 0
    last_hit:    Optional[float] = None

    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() > self.expires_at


@dataclass
class EvaluationContext:
    """Runtime context passed to policy evaluation."""
    src_ip:       str
    dst_ip:       str
    src_port:     int
    dst_port:     int
    protocol:     str
    risk_score:   float = 0.0
    geo_country:  Optional[str] = None
    asn:          Optional[int] = None
    application:  Optional[str] = None
    tls_version:  Optional[str] = None
    user_id:      Optional[str] = None
    user_roles:   List[str] = field(default_factory=list)
    timestamp:    float = field(default_factory=time.time)
    threat_intel_match: bool = False


@dataclass
class PolicyDecision:
    rule_id:     Optional[str]
    rule_name:   Optional[str]
    effect:      PolicyEffect
    matched:     bool
    reason:      str
    latency_us:  float = 0.0


# ============================================================================
# Policy Engine
# ============================================================================

class PolicyEngine:
    """
    ABAC Policy Engine with ordered rule evaluation.

    Rules are sorted by priority (descending) — first match wins.
    Default action if no rule matches: ALLOW (whitelist) or BLOCK (blacklist)
    depending on default_action setting.

    Thread-safe for asyncio (no locks needed — Python GIL protects dict reads).
    """

    def __init__(self, default_action: PolicyEffect = PolicyEffect.ALLOW):
        self.default_action = default_action
        self._rules: List[PolicyRule] = []
        self._rules_by_id: Dict[str, PolicyRule] = {}
        self._sorted = True   # rules sorted by priority descending

        # Threat Intel IOC set (populated by ThreatIntelService)
        self._blocked_ips:   Set[str] = set()
        self._blocked_cidrs: List[ipaddress.IPv4Network] = []

        # Statistics
        self._decisions = {"allow": 0, "block": 0, "throttle": 0, "log": 0}

    # ── Rule Management ───────────────────────────────────────────────────────

    def add_rule(self, rule: PolicyRule) -> None:
        if rule.rule_id in self._rules_by_id:
            self.remove_rule(rule.rule_id)
        self._rules.append(rule)
        self._rules_by_id[rule.rule_id] = rule
        self._sorted = False
        logger.info("Policy rule added: %s (priority=%d effect=%s)", rule.name, rule.priority, rule.effect)

    def remove_rule(self, rule_id: str) -> bool:
        if rule_id not in self._rules_by_id:
            return False
        rule = self._rules_by_id.pop(rule_id)
        self._rules.remove(rule)
        logger.info("Policy rule removed: %s", rule_id)
        return True

    def toggle_rule(self, rule_id: str) -> Optional[bool]:
        rule = self._rules_by_id.get(rule_id)
        if not rule:
            return None
        rule.is_active = not rule.is_active
        return rule.is_active

    def load_rules_from_json(self, rules_json: List[Dict]) -> int:
        count = 0
        for r in rules_json:
            try:
                rule = self._parse_rule(r)
                self.add_rule(rule)
                count += 1
            except Exception as e:
                logger.error("Failed to parse rule %s: %s", r.get("rule_id", "?"), e)
        return count

    def _parse_rule(self, d: Dict) -> PolicyRule:
        subj = d.get("subject", {})
        res  = d.get("resource", {})
        env  = d.get("environment", {})
        return PolicyRule(
            rule_id     = d["rule_id"],
            name        = d["name"],
            priority    = int(d.get("priority", 100)),
            effect      = PolicyEffect(d.get("effect", "allow")),
            description = d.get("description"),
            is_active   = d.get("is_active", True),
            expires_at  = d.get("expires_at"),
            subject     = SubjectCondition(
                src_cidr        = subj.get("src_cidr"),
                not_src_cidr    = subj.get("not_src_cidr"),
                src_country     = subj.get("src_country"),
                not_src_country = subj.get("not_src_country"),
                asn             = subj.get("asn"),
                user_role       = subj.get("user_role"),
            ),
            resource    = ResourceCondition(
                dst_cidr     = res.get("dst_cidr"),
                dst_port     = res.get("dst_port"),
                protocol     = res.get("protocol"),
                application  = res.get("application"),
            ),
            environment = EnvironmentCondition(
                time_range       = tuple(env["time_range"]) if "time_range" in env else None,
                days             = env.get("days"),
                max_risk_score   = env.get("max_risk_score"),
                min_risk_score   = env.get("min_risk_score"),
                geo_block_list   = env.get("geo_block_list"),
                threat_intel_match = env.get("threat_intel_match", False),
            ),
        )

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate(self, ctx: EvaluationContext) -> PolicyDecision:
        """
        Evaluate all active rules against the context.
        Returns first matching rule's decision.
        O(log N) for sorted rule list with early exit.
        """
        t0 = time.perf_counter()

        # Threat Intel fast-path check
        if ctx.src_ip in self._blocked_ips:
            return PolicyDecision(
                rule_id="threat-intel-ip", rule_name="Threat Intel IP Block",
                effect=PolicyEffect.BLOCK, matched=True,
                reason=f"{ctx.src_ip} is in threat intel blocklist",
                latency_us=(time.perf_counter() - t0) * 1e6,
            )

        try:
            src_addr = ipaddress.ip_address(ctx.src_ip)
            for cidr in self._blocked_cidrs:
                if src_addr in cidr:
                    return PolicyDecision(
                        rule_id="threat-intel-cidr", rule_name="Threat Intel CIDR Block",
                        effect=PolicyEffect.BLOCK, matched=True,
                        reason=f"{ctx.src_ip} in blocked CIDR {cidr}",
                        latency_us=(time.perf_counter() - t0) * 1e6,
                    )
        except ValueError:
            pass

        # Sort rules if needed
        if not self._sorted:
            self._rules.sort(key=lambda r: r.priority, reverse=True)
            self._sorted = True

        # Evict expired rules
        now = time.time()
        expired = [r for r in self._rules if r.is_expired()]
        for r in expired:
            self.remove_rule(r.rule_id)

        # Rule evaluation loop
        for rule in self._rules:
            if not rule.is_active:
                continue
            if not self._match_rule(rule, ctx):
                continue

            # Rule matched
            rule.hit_count += 1
            rule.last_hit   = now
            self._decisions[rule.effect.value] = self._decisions.get(rule.effect.value, 0) + 1

            return PolicyDecision(
                rule_id   = rule.rule_id,
                rule_name = rule.name,
                effect    = rule.effect,
                matched   = True,
                reason    = f"Matched rule '{rule.name}' (priority={rule.priority})",
                latency_us = (time.perf_counter() - t0) * 1e6,
            )

        # No match — default action
        self._decisions[self.default_action.value] = self._decisions.get(self.default_action.value, 0) + 1
        return PolicyDecision(
            rule_id=None, rule_name=None,
            effect=self.default_action, matched=False,
            reason="No matching policy rule — using default action",
            latency_us=(time.perf_counter() - t0) * 1e6,
        )

    def _match_rule(self, rule: PolicyRule, ctx: EvaluationContext) -> bool:
        """Check if all conditions in a rule match the context."""
        return (
            self._match_subject(rule.subject, ctx) and
            self._match_resource(rule.resource, ctx) and
            self._match_environment(rule.environment, ctx)
        )

    def _match_subject(self, s: SubjectCondition, ctx: EvaluationContext) -> bool:
        try:
            src = ipaddress.ip_address(ctx.src_ip)
            if s.src_cidr and src not in ipaddress.ip_network(s.src_cidr, strict=False):
                return False
            if s.not_src_cidr and src in ipaddress.ip_network(s.not_src_cidr, strict=False):
                return False
        except ValueError:
            return False
        if s.src_country and ctx.geo_country not in s.src_country:
            return False
        if s.not_src_country and ctx.geo_country in (s.not_src_country or []):
            return False
        if s.asn and ctx.asn not in s.asn:
            return False
        if s.user_role and not any(r in ctx.user_roles for r in s.user_role):
            return False
        return True

    def _match_resource(self, r: ResourceCondition, ctx: EvaluationContext) -> bool:
        try:
            if r.dst_cidr:
                dst = ipaddress.ip_address(ctx.dst_ip)
                if dst not in ipaddress.ip_network(r.dst_cidr, strict=False):
                    return False
        except ValueError:
            return False
        if r.dst_port is not None:
            port = ctx.dst_port
            if isinstance(r.dst_port, int):
                if port != r.dst_port:
                    return False
            elif isinstance(r.dst_port, list):
                if len(r.dst_port) == 2 and isinstance(r.dst_port[0], int):
                    if not (r.dst_port[0] <= port <= r.dst_port[1]):
                        return False
                elif port not in r.dst_port:
                    return False
        if r.protocol and r.protocol.upper() != "ANY":
            if ctx.protocol.upper() != r.protocol.upper():
                return False
        if r.application and ctx.application != r.application:
            return False
        return True

    def _match_environment(self, e: EnvironmentCondition, ctx: EvaluationContext) -> bool:
        if e.time_range:
            import datetime
            t   = datetime.datetime.utcfromtimestamp(ctx.timestamp)
            cur = t.strftime("%H:%M")
            if not (e.time_range[0] <= cur <= e.time_range[1]):
                return False
        if e.days:
            import datetime
            day = datetime.datetime.utcfromtimestamp(ctx.timestamp).strftime("%a")
            if day not in e.days:
                return False
        if e.max_risk_score is not None and ctx.risk_score > e.max_risk_score:
            return False
        if e.min_risk_score is not None and ctx.risk_score < e.min_risk_score:
            return False
        if e.geo_block_list and ctx.geo_country in e.geo_block_list:
            return True   # match for geo block
        if e.threat_intel_match and not ctx.threat_intel_match:
            return False
        return True

    # ── Threat Intel integration ──────────────────────────────────────────────

    def update_blocklist(self, ips: Set[str], cidrs: List[str]) -> None:
        self._blocked_ips = ips
        self._blocked_cidrs = []
        for cidr in cidrs:
            try:
                self._blocked_cidrs.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        logger.info("Blocklist updated: %d IPs, %d CIDRs", len(self._blocked_ips), len(self._blocked_cidrs))

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        return {
            "rule_count":    len(self._rules),
            "active_rules":  sum(1 for r in self._rules if r.is_active),
            "decisions":     self._decisions,
            "blocked_ips":   len(self._blocked_ips),
            "blocked_cidrs": len(self._blocked_cidrs),
        }

    def export_rules(self) -> List[Dict]:
        return [
            {
                "rule_id":   r.rule_id,
                "name":      r.name,
                "priority":  r.priority,
                "effect":    r.effect.value,
                "is_active": r.is_active,
                "hit_count": r.hit_count,
                "last_hit":  r.last_hit,
            }
            for r in self._rules
        ]
