"""
Thor Firewall — MARL Training Environment
بيئة التدريب لنظام التعلم المعزز متعدد الوكلاء

تُحاكي شبكة مؤسسية واقعية بـ:
  - حركة مرور طبيعية (مُولَّدة من نماذج إحصائية)
  - هجمات معروفة (SYN flood, Port scan, Brute force, C2, Exfil)
  - أحداث عشوائية (spikes, maintenance windows)

واجهة OpenAI Gym:
  - observation_space: R^82 (50 flow + 32 GNN context)
  - action_space: Discrete(5) [allow, block, throttle, mirror, redirect]
  - reward: accuracy × speed_factor - false_positive_penalty

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    import gymnasium as gym
    from gymnasium import spaces
    GYM_AVAILABLE = True
except ImportError:
    GYM_AVAILABLE = False


# ============================================================================
# Attack Scenarios
# ============================================================================

@dataclass
class AttackScenario:
    name:        str
    threat_type: str
    mitre_id:    str
    probability: float     # base probability per step
    features:    np.ndarray  # feature vector when attack is present
    label:       int       # 1 = attack, 0 = benign


ATTACK_SCENARIOS: List[AttackScenario] = [
    AttackScenario(
        name="SYN Flood",
        threat_type="syn-flood",
        mitre_id="T1498.001",
        probability=0.05,
        features=np.array([0.1, 0.95, 0.05, 0.98, 0.0, 0.99, 0.02, 0.0,  0.0,  0.97,
                           0.0, 0.0,  0.0,  0.0,  0.0, 0.0,  1.0,  0.0,  0.0,  0.0,
                           0.0, 0.0,  0.0,  0.0,  0.0, 0.0,  0.0,  0.0,  0.0,  0.0,
                           0.0, 0.0,  0.0,  0.0,  0.0, 0.0,  0.0,  0.0,  0.0,  0.0,
                           0.0, 0.0,  0.0,  0.0,  0.0, 0.0,  0.0,  0.0,  0.0,  0.0], dtype=np.float32),
        label=1,
    ),
    AttackScenario(
        name="Port Scan",
        threat_type="port-scan",
        mitre_id="T1046",
        probability=0.08,
        features=np.array([0.5, 0.1, 0.9, 0.02, 0.0, 0.05, 0.95, 0.1, 0.0, 0.0,
                           0.3, 0.0, 0.0, 0.0,  0.0, 0.0,  0.0,  0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0,  0.0, 0.0,  0.0,  0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0,  0.0, 0.0,  0.0,  0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0,  0.0, 0.0,  0.0,  0.0, 0.0, 0.0], dtype=np.float32),
        label=1,
    ),
    AttackScenario(
        name="Brute Force SSH",
        threat_type="brute-force",
        mitre_id="T1110.001",
        probability=0.06,
        features=np.array([0.3, 0.2, 0.1, 0.8, 0.1, 0.3, 0.0, 0.95, 0.7, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  0.0, 0.0], dtype=np.float32),
        label=1,
    ),
    AttackScenario(
        name="DNS Tunneling",
        threat_type="dns-tunnel",
        mitre_id="T1071.004",
        probability=0.03,
        features=np.array([0.2, 0.05, 0.1, 0.1, 0.7, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.9, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32),
        label=1,
    ),
    AttackScenario(
        name="Data Exfiltration",
        threat_type="data-exfil",
        mitre_id="T1041",
        probability=0.02,
        features=np.array([0.4, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.95, 0.8, 0.3, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32),
        label=1,
    ),
    AttackScenario(
        name="C2 Beaconing",
        threat_type="c2-comm",
        mitre_id="T1071",
        probability=0.04,
        features=np.array([0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.7, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.85, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                           0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32),
        label=1,
    ),
]

# Benign traffic baseline
BENIGN_MEAN = np.zeros(50, dtype=np.float32)
BENIGN_STD  = np.ones(50, dtype=np.float32) * 0.15


# ============================================================================
# Reward Function
# ============================================================================

class RewardFunction:
    """
    Shaped reward balancing security vs. availability:
      +10   : Correctly blocked attack
      +1    : Correctly allowed benign
      -5    : False positive (blocked benign)
      -20   : False negative (allowed attack)
      -0.01 : Per-step throttle penalty (encourages not over-throttling)
    """

    TRUE_POSITIVE_REWARD   = +10.0
    TRUE_NEGATIVE_REWARD   = +1.0
    FALSE_POSITIVE_PENALTY = -5.0
    FALSE_NEGATIVE_PENALTY = -20.0
    THROTTLE_PENALTY       = -0.01

    def compute(self, action: int, is_attack: bool) -> float:
        blocked = action in (1, 2)  # block or throttle
        if is_attack and blocked:
            return self.TRUE_POSITIVE_REWARD
        if not is_attack and not blocked:
            return self.TRUE_NEGATIVE_REWARD
        if not is_attack and blocked:
            return self.FALSE_POSITIVE_PENALTY
        if is_attack and not blocked:
            return self.FALSE_NEGATIVE_PENALTY
        return 0.0


# ============================================================================
# Thor Network Environment
# ============================================================================

class ThorNetworkEnv:
    """
    Simulated network environment for MARL training.

    Observation: R^82
      - [0:50]  : flow features
      - [50:82] : GNN context (32-dim)

    Action: Discrete(5)
      0: allow, 1: block, 2: throttle, 3: mirror, 4: redirect

    Episode: 1000 steps
    """

    OBS_DIM    = 82
    ACTION_DIM = 5
    MAX_STEPS  = 1_000

    def __init__(self, attack_rate: float = 0.15, seed: Optional[int] = None):
        self.attack_rate = attack_rate
        self.rng         = np.random.default_rng(seed)
        self.reward_fn   = RewardFunction()

        self._step      = 0
        self._done      = False
        self._info: Dict = {}

        # Episode statistics
        self._tp = self._tn = self._fp = self._fn = 0

        if GYM_AVAILABLE:
            self.observation_space = spaces.Box(
                low=0.0, high=1.0, shape=(self.OBS_DIM,), dtype=np.float32,
            )
            self.action_space = spaces.Discrete(self.ACTION_DIM)

    def reset(self, seed: Optional[int] = None) -> Tuple[np.ndarray, Dict]:
        if seed is not None:
            self.rng = np.random.default_rng(seed)
        self._step = 0
        self._done = False
        self._tp = self._tn = self._fp = self._fn = 0
        obs = self._generate_observation()
        self._info = {"is_attack": False, "scenario": None}
        return obs, {}

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        assert not self._done, "Episode done — call reset()"
        self._step += 1

        # Determine if this flow is an attack
        is_attack = self.rng.random() < self.attack_rate
        scenario  = None
        if is_attack:
            scenario = self.rng.choice(ATTACK_SCENARIOS)

        # Compute reward
        reward = self.reward_fn.compute(action, is_attack)

        # Update stats
        blocked = action in (1, 2)
        if is_attack and blocked:     self._tp += 1
        elif not is_attack and not blocked: self._tn += 1
        elif not is_attack and blocked:     self._fp += 1
        elif is_attack and not blocked:     self._fn += 1

        # Next observation
        obs   = self._generate_observation(scenario if is_attack else None)
        done  = self._step >= self.MAX_STEPS
        self._done = done

        total = self._tp + self._tn + self._fp + self._fn
        acc   = (self._tp + self._tn) / max(total, 1)
        self._info = {
            "is_attack": is_attack,
            "scenario":  scenario.name if scenario else None,
            "accuracy":  acc,
            "tp": self._tp, "tn": self._tn, "fp": self._fp, "fn": self._fn,
            "step": self._step,
        }

        return obs, reward, done, False, self._info

    def _generate_observation(self, scenario: Optional[AttackScenario] = None) -> np.ndarray:
        if scenario is not None:
            # Attack features + noise
            flow_feat = scenario.features.copy()
            flow_feat += self.rng.normal(0, 0.05, size=50).astype(np.float32)
            flow_feat = np.clip(flow_feat, 0.0, 1.0)
        else:
            # Benign traffic
            flow_feat = self.rng.normal(BENIGN_MEAN, BENIGN_STD).astype(np.float32)
            flow_feat = np.clip(flow_feat, 0.0, 1.0)

        # GNN context (random topology embedding for now — replaced by real GNN in training)
        gnn_feat = self.rng.normal(0.5, 0.1, size=32).astype(np.float32)
        gnn_feat = np.clip(gnn_feat, 0.0, 1.0)

        return np.concatenate([flow_feat, gnn_feat])

    @property
    def episode_stats(self) -> Dict:
        total = self._tp + self._tn + self._fp + self._fn
        return {
            "steps":     self._step,
            "total":     total,
            "accuracy":  (self._tp + self._tn) / max(total, 1),
            "precision": self._tp / max(self._tp + self._fp, 1),
            "recall":    self._tp / max(self._tp + self._fn, 1),
            "tp": self._tp, "tn": self._tn, "fp": self._fp, "fn": self._fn,
        }
