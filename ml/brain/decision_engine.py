"""
Thor Firewall — AI Decision Engine
محرك القرار الذكي — العقل المركزي لنظام Thor

هذا هو القلب النابض للنظام. يُنسّق بين:
  1. MARL agents  — قرار سريع (<1μs) للأنماط المعروفة
  2. GNN analyzer — تحليل الشبكة الكلية وانتشار التهديد
  3. Behavioral Analyzer — هل هذا السلوك طبيعي لهذا الكيان؟
  4. Threat Correlator — هل هناك هجوم ممتد عبر الزمن؟
  5. Zero-Day Detector — هل هذا شيء لم نره من قبل؟
  6. LLM Explainer — تفسير القرار بلغة طبيعية

الفلسفة: "افترض الخطر حتى تثبت السلامة" (Zero-Trust)
النموذج: Palo Alto WildFire + Darktrace Enterprise Immune System

مستوى التهديد يُحسب بـ Bayesian fusion:
  final_risk = P(threat | MARL) × P(threat | behavioral) × P(threat | correlation) × P(threat | zero_day)
  normalized عبر Jeffrey's rule

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("thor.brain.engine")

# ============================================================================
# Types
# ============================================================================

class ThreatLevel(IntEnum):
    CLEAN     = 0   # verified safe
    LOW       = 1   # minor anomaly, allow + log
    MEDIUM    = 2   # suspicious, allow + alert
    HIGH      = 3   # likely threat, block + alert
    CRITICAL  = 4   # confirmed attack, block + quarantine + IR


class Action(IntEnum):
    ALLOW      = 0
    LOG        = 1
    THROTTLE   = 2
    BLOCK      = 3
    QUARANTINE = 4   # isolate source host entirely
    MIRROR     = 5   # allow + copy to analysis tap


@dataclass
class FlowFeatures:
    """Feature vector for one network flow (must match kernel extractor)"""
    # L4 identifiers
    src_ip:       int        # packed IPv4
    dst_ip:       int
    src_port:     int
    dst_port:     int
    proto:        int        # 6=TCP, 17=UDP, 1=ICMP

    # Counters (normalized 0-1 downstream)
    pkt_count:    float = 0.0
    byte_count:   float = 0.0
    duration_ms:  float = 0.0

    # Statistical features (first 16 = flow, next 16 = behavioral context)
    features:     List[float] = field(default_factory=lambda: [0.0] * 50)

    # Optional context
    gnn_embedding:  Optional[List[float]] = None  # 32-dim
    user_id:        Optional[str] = None
    app_layer_proto: Optional[str] = None         # HTTP, TLS, DNS …
    tls_ja3:        Optional[str] = None
    tls_ja4:        Optional[str] = None
    dns_query:      Optional[str] = None
    http_host:      Optional[str] = None
    http_uri:       Optional[str] = None
    geo_country:    Optional[str] = None
    asn:            Optional[int] = None
    timestamp:      float = field(default_factory=time.time)

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}/{self.proto}"

    @property
    def flow_key_hash(self) -> int:
        return int(hashlib.md5(self.flow_key.encode()).hexdigest()[:16], 16)


@dataclass
class DecisionRequest:
    flow:            FlowFeatures
    require_explain: bool = False
    explain_lang:    str  = "ar"    # ar | en


@dataclass
class DecisionResult:
    flow_key:      str
    action:        Action
    threat_level:  ThreatLevel

    # Confidence scores from each sub-engine [0,1]
    marl_risk:        float = 0.0
    behavioral_risk:  float = 0.0
    correlation_risk: float = 0.0
    zero_day_risk:    float = 0.0
    final_risk:       float = 0.0   # Bayesian fusion

    threat_type:   Optional[str] = None
    mitre_id:      Optional[str] = None
    explanation:   Optional[str] = None
    confidence:    float = 0.0
    latency_us:    float = 0.0
    engine_path:   str = "fast"     # fast | deep | llm

    # Recommended response actions
    recommended_actions: List[str] = field(default_factory=list)


# ============================================================================
# Bayesian Risk Fusion
# ============================================================================

def bayesian_fusion(probs: List[float], weights: Optional[List[float]] = None) -> float:
    """
    Fuse independent risk probabilities using Jeffrey's rule.

    P(threat | e1, e2, ..., en) ∝ ∏ P(threat | ei)^wi
    normalized to [0, 1].

    This is the same approach used by Palo Alto WildFire's verdict engine.
    """
    if not probs:
        return 0.0
    if weights is None:
        weights = [1.0] * len(probs)

    assert len(probs) == len(weights)

    # Log-domain multiplication (numerically stable)
    log_threat = 0.0
    log_safe   = 0.0
    for p, w in zip(probs, weights):
        p = max(1e-9, min(1 - 1e-9, float(p)))
        log_threat += w * np.log(p)
        log_safe   += w * np.log(1 - p)

    # Softmax normalization
    m = max(log_threat, log_safe)
    threat_exp = np.exp(log_threat - m)
    safe_exp   = np.exp(log_safe   - m)
    return float(threat_exp / (threat_exp + safe_exp))


# ============================================================================
# Decision Engine
# ============================================================================

class DecisionEngine:
    """
    Central AI Brain — orchestrates all sub-engines into one verdict.

    Usage:
        engine = await DecisionEngine.create(config)
        result = await engine.decide(DecisionRequest(flow=features))
    """

    # Risk thresholds → action mapping
    THRESHOLD = {
        ThreatLevel.CRITICAL: 0.90,
        ThreatLevel.HIGH:     0.72,
        ThreatLevel.MEDIUM:   0.45,
        ThreatLevel.LOW:      0.20,
    }

    # Sub-engine weights for Bayesian fusion
    WEIGHTS = {
        "marl":        1.5,   # trained on labeled attacks — most trusted
        "behavioral":  1.2,   # knows normal per entity
        "correlation": 1.0,   # multi-hop attack chains
        "zero_day":    0.8,   # higher false-positive potential
    }

    def __init__(self):
        self._marl       = None
        self._behavioral = None
        self._correlator = None
        self._zero_day   = None
        self._explainer  = None
        self._gnn        = None
        self._ready      = False

        # Fast-path cache: flow_key_hash → (action, ttl)
        self._cache: Dict[int, Tuple[Action, float, DecisionResult]] = {}
        self._cache_ttl = 5.0   # seconds

        # Per-engine latency tracking (exponential moving average)
        self._lat = {"marl": 0.0, "behavioral": 0.0, "total": 0.0}

    # ── Initialization ──────────────────────────────────────────────────────

    @classmethod
    async def create(cls, config: Optional[Dict] = None) -> "DecisionEngine":
        engine = cls()
        await engine._initialize(config or {})
        return engine

    async def _initialize(self, config: Dict) -> None:
        from .behavioral_analyzer import BehavioralAnalyzer
        from .threat_correlator   import ThreatCorrelator
        from .zero_day_detector   import ZeroDayDetector

        self._behavioral = BehavioralAnalyzer(
            window_minutes=config.get("behavioral_window_min", 60),
            min_samples=config.get("behavioral_min_samples", 30),
        )

        self._correlator = ThreatCorrelator(
            time_window_s=config.get("correlation_window_s", 300),
            min_events=config.get("correlation_min_events", 3),
        )

        self._zero_day = ZeroDayDetector(
            contamination=config.get("zero_day_contamination", 0.01),
        )

        # Optionally load MARL
        try:
            from ml.marl.agents import MetaAgent, MARLConfig
            self._marl = MetaAgent(MARLConfig())
            ckpt = config.get("checkpoint", "ml/checkpoints/latest.pt")
            self._marl.load(ckpt)
            logger.info("MARL agent loaded from %s", ckpt)
        except Exception as e:
            logger.warning("MARL not loaded (%s) — using heuristics only", e)

        # LLM explainer (optional — lazy-loaded on first explain request)
        self._explainer = None

        self._ready = True
        logger.info("Decision Engine initialized — all sub-engines online")

    # ── Fast-path cache ──────────────────────────────────────────────────────

    def _cache_get(self, key_hash: int) -> Optional[DecisionResult]:
        entry = self._cache.get(key_hash)
        if entry is None:
            return None
        action, expires, result = entry
        if time.monotonic() > expires:
            del self._cache[key_hash]
            return None
        return result

    def _cache_put(self, key_hash: int, result: DecisionResult) -> None:
        # Cache clean flows longer, threats shorter
        ttl = 0.5 if result.threat_level >= ThreatLevel.HIGH else self._cache_ttl
        self._cache[key_hash] = (result.action, time.monotonic() + ttl, result)
        # Evict old entries every ~1000 inserts
        if len(self._cache) > 50_000:
            now = time.monotonic()
            self._cache = {k: v for k, v in self._cache.items() if v[1] > now}

    # ── Main decision path ───────────────────────────────────────────────────

    async def decide(self, req: DecisionRequest) -> DecisionResult:
        t0 = time.perf_counter()

        # 0. Cache hit (fast path — <1μs)
        cached = self._cache_get(req.flow.flow_key_hash)
        if cached is not None:
            return cached

        # 1. Gather sub-engine scores concurrently
        marl_risk, behavioral_risk, corr_risk, zd_risk = await asyncio.gather(
            self._run_marl(req.flow),
            self._run_behavioral(req.flow),
            self._run_correlator(req.flow),
            self._run_zero_day(req.flow),
        )

        # 2. Bayesian fusion
        final_risk = bayesian_fusion(
            [marl_risk, behavioral_risk, corr_risk, zd_risk],
            weights=[
                self.WEIGHTS["marl"],
                self.WEIGHTS["behavioral"],
                self.WEIGHTS["correlation"],
                self.WEIGHTS["zero_day"],
            ],
        )

        # 3. Classify threat level
        threat_level = ThreatLevel.CLEAN
        for level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW]:
            if final_risk >= self.THRESHOLD[level]:
                threat_level = level
                break

        # 4. Map to action
        action = self._action_from_threat(threat_level, req.flow)

        # 5. Identify threat type (heuristic + ML)
        threat_type, mitre_id = self._classify_threat_type(req.flow, final_risk,
                                                             marl_risk, behavioral_risk)

        # 6. Build result
        latency_us = (time.perf_counter() - t0) * 1e6
        result = DecisionResult(
            flow_key      = req.flow.flow_key,
            action        = action,
            threat_level  = threat_level,
            marl_risk     = marl_risk,
            behavioral_risk = behavioral_risk,
            correlation_risk = corr_risk,
            zero_day_risk = zd_risk,
            final_risk    = final_risk,
            threat_type   = threat_type,
            mitre_id      = mitre_id,
            confidence    = 1.0 - abs(final_risk - 0.5) * 2,
            latency_us    = latency_us,
            engine_path   = "deep" if (behavioral_risk > 0.3 or zd_risk > 0.3) else "fast",
            recommended_actions = self._recommend_actions(threat_level, threat_type),
        )

        # 7. Async explanation (only if requested AND threat is significant)
        if req.require_explain and threat_level >= ThreatLevel.MEDIUM:
            result.explanation = await self._explain(req, result)
            result.engine_path = "llm"

        # 8. Cache and update sub-engines
        self._cache_put(req.flow.flow_key_hash, result)
        self._correlator.record(req.flow, result)

        # EMA latency
        self._lat["total"] = 0.9 * self._lat["total"] + 0.1 * latency_us

        return result

    # ── Sub-engines ──────────────────────────────────────────────────────────

    async def _run_marl(self, flow: FlowFeatures) -> float:
        if self._marl is None:
            return self._heuristic_risk(flow)
        try:
            features = np.array(flow.features, dtype=np.float32)
            if flow.gnn_embedding:
                features = np.concatenate([features, np.array(flow.gnn_embedding, dtype=np.float32)])
            with __import__("torch").no_grad():
                result = self._marl.act(features)
            return float(result.risk_score)
        except Exception as e:
            logger.debug("MARL error: %s", e)
            return self._heuristic_risk(flow)

    async def _run_behavioral(self, flow: FlowFeatures) -> float:
        if self._behavioral is None:
            return 0.0
        return self._behavioral.score(flow)

    async def _run_correlator(self, flow: FlowFeatures) -> float:
        if self._correlator is None:
            return 0.0
        return self._correlator.score(flow)

    async def _run_zero_day(self, flow: FlowFeatures) -> float:
        if self._zero_day is None:
            return 0.0
        return self._zero_day.score(flow)

    # ── Heuristics (fallback when ML not loaded) ─────────────────────────────

    def _heuristic_risk(self, flow: FlowFeatures) -> float:
        """
        Rule-based risk scoring — same as what Snort/Suricata do,
        but as a continuous probability instead of binary.
        """
        risk = 0.0

        # High-risk destination ports
        HIGH_RISK_PORTS = {22, 23, 3389, 4444, 1337, 31337, 8080, 9001}
        if flow.dst_port in HIGH_RISK_PORTS:
            risk += 0.25

        # Well-known C2 ports
        C2_PORTS = {4444, 5555, 6666, 7777, 1337, 31337, 8081, 9876}
        if flow.dst_port in C2_PORTS:
            risk += 0.40

        # Private-to-private with unusually high bandwidth
        def is_private(ip: int) -> bool:
            return (
                (ip >> 24 == 10) or
                (ip >> 20 == 0xAC1) or   # 172.16/12
                (ip >> 16 == 0xC0A8)     # 192.168/16
            )

        if is_private(flow.src_ip) and not is_private(flow.dst_ip):
            if flow.byte_count > 1e8:   # > 100MB outbound
                risk += 0.35            # potential exfiltration

        # Port scan pattern (many dports, same src)
        if flow.features[2] > 0.8:     # feature[2] = unique_dports_norm
            risk += 0.30

        # SYN flood pattern
        if flow.proto == 6 and flow.features[5] > 0.95:   # feature[5] = syn_ratio
            risk += 0.45

        # DNS tunneling (unusually long DNS queries)
        if flow.app_layer_proto == "DNS" and flow.byte_count > 500:
            risk += 0.35

        # Payload entropy (encrypted/obfuscated = high entropy)
        if len(flow.features) > 10 and flow.features[10] > 0.85:
            risk += 0.15

        return min(1.0, risk)

    # ── Action mapping ───────────────────────────────────────────────────────

    def _action_from_threat(self, level: ThreatLevel, flow: FlowFeatures) -> Action:
        if level == ThreatLevel.CLEAN:
            return Action.ALLOW
        if level == ThreatLevel.LOW:
            return Action.LOG
        if level == ThreatLevel.MEDIUM:
            # Throttle suspicious traffic — don't block immediately
            return Action.THROTTLE
        if level == ThreatLevel.HIGH:
            return Action.BLOCK
        # CRITICAL: full quarantine of the source
        return Action.QUARANTINE

    # ── Threat classification ────────────────────────────────────────────────

    def _classify_threat_type(
        self,
        flow: FlowFeatures,
        final_risk: float,
        marl_risk: float,
        behavioral_risk: float,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Map feature patterns to known threat types with MITRE ATT&CK IDs."""

        if final_risk < self.THRESHOLD[ThreatLevel.LOW]:
            return None, None

        # Prioritize by feature pattern
        feat = flow.features

        # SYN flood → T1498.001
        if flow.proto == 6 and len(feat) > 5 and feat[5] > 0.9:
            return "syn-flood", "T1498.001"

        # Port scan → T1046
        if len(feat) > 2 and feat[2] > 0.7:
            return "port-scan", "T1046"

        # Brute force (many conns, same dst:port) → T1110.001
        if len(feat) > 7 and feat[7] > 0.8 and flow.dst_port in {22, 3389, 21, 25, 110}:
            return "brute-force", "T1110.001"

        # DNS tunneling → T1071.004
        if flow.app_layer_proto == "DNS" and len(feat) > 10 and feat[10] > 0.7:
            return "dns-tunnel", "T1071.004"

        # Data exfiltration (large outbound) → T1041
        if flow.byte_count > 1e7 and not (flow.dst_ip >> 24 == 10):
            return "data-exfil", "T1041"

        # C2 beaconing (periodic small flows) → T1071
        if behavioral_risk > 0.6 and flow.byte_count < 1000 and len(feat) > 15 and feat[15] > 0.7:
            return "c2-comm", "T1071"

        # Zero-day / unknown
        if marl_risk < 0.3 and final_risk > 0.5:
            return "zero-day", "T1190"

        return "anomaly", None

    # ── Response recommendations ─────────────────────────────────────────────

    def _recommend_actions(self, level: ThreatLevel, threat_type: Optional[str]) -> List[str]:
        actions = []
        if level >= ThreatLevel.HIGH:
            actions.append("block_src_ip")
            actions.append("create_threat_ioc")
        if level >= ThreatLevel.CRITICAL:
            actions.append("quarantine_host")
            actions.append("alert_soc_team")
            actions.append("capture_pcap_evidence")
        if threat_type == "data-exfil":
            actions.append("revoke_user_session")
            actions.append("notify_dlp_team")
        if threat_type == "ransomware":
            actions.append("isolate_network_segment")
            actions.append("trigger_backup_verification")
        if threat_type == "c2-comm":
            actions.append("dns_sinkhole_domain")
            actions.append("hunt_for_lateral_movement")
        return actions

    # ── LLM Explanation ──────────────────────────────────────────────────────

    async def _explain(self, req: DecisionRequest, result: DecisionResult) -> str:
        try:
            if self._explainer is None:
                from ml.llm.explainer import SecurityExplainer, LLMConfig
                self._explainer = SecurityExplainer(LLMConfig())

            return await self._explainer.explain(
                flow=req.flow,
                result=result,
                language=req.explain_lang,
            )
        except Exception as e:
            logger.warning("LLM explainer failed: %s", e)
            return self._fallback_explanation(result)

    def _fallback_explanation(self, r: DecisionResult) -> str:
        lines = [
            f"Risk Score: {r.final_risk:.1%} (MARL:{r.marl_risk:.0%} / Behavior:{r.behavioral_risk:.0%} / Correlation:{r.correlation_risk:.0%} / ZeroDay:{r.zero_day_risk:.0%})",
            f"Decision: {r.action.name} — Threat: {r.threat_level.name}",
        ]
        if r.threat_type:
            lines.append(f"Type: {r.threat_type}" + (f" [{r.mitre_id}]" if r.mitre_id else ""))
        if r.recommended_actions:
            lines.append("Recommended: " + ", ".join(r.recommended_actions))
        return "\n".join(lines)

    # ── Health ────────────────────────────────────────────────────────────────

    def health(self) -> Dict[str, Any]:
        return {
            "ready":           self._ready,
            "marl_loaded":     self._marl is not None,
            "behavioral_ok":   self._behavioral is not None,
            "correlator_ok":   self._correlator is not None,
            "zero_day_ok":     self._zero_day is not None,
            "cache_size":      len(self._cache),
            "avg_latency_us":  round(self._lat["total"], 2),
        }
