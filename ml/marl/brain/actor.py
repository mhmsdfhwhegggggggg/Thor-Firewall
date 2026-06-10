"""
Thor Firewall — Actor Network (Policy)
=======================================
شبكة السياسة لكل Agent في نظام MARL.

المدخلات:  [batch, FEATURE_DIM=82]  — feature vector
المخرجات:  action_logits [batch, N_ACTIONS]
           action_probs  [batch, N_ACTIONS]  (Softmax)
           entropy       scalar  (للتنظيم)
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch.distributions import Categorical


N_ACTIONS   = 8   # BENIGN, DoS, DDoS, PortScan, BruteForce, WebAttack, Bot/C2, Infiltration
FEATURE_DIM = 82


class SwiGLU(nn.Module):
    def __init__(self, in_dim: int, hidden_dim: int | None = None):
        super().__init__()
        hidden_dim = hidden_dim or in_dim * 4
        self.gate = nn.Linear(in_dim, hidden_dim)
        self.proj = nn.Linear(in_dim, hidden_dim)
        self.out  = nn.Linear(hidden_dim, in_dim)

    def forward(self, x: Tensor) -> Tensor:
        return self.out(F.silu(self.gate(x)) * self.proj(x))


class ThorActorBlock(nn.Module):
    def __init__(self, dim: int, dropout: float = 0.1):
        super().__init__()
        self.norm = nn.LayerNorm(dim)
        self.ff   = SwiGLU(dim)
        self.drop = nn.Dropout(dropout)

    def forward(self, x: Tensor) -> Tensor:
        return x + self.drop(self.ff(self.norm(x)))


class ThorActor(nn.Module):
    """
    MARL Actor — maps flow features → action distribution.

    Architecture: Input projection → N residual blocks → action head
    Uses SwiGLU activation + LayerNorm (proven superior for tabular data).
    """

    def __init__(
        self,
        input_dim:   int   = FEATURE_DIM,
        hidden_dim:  int   = 256,
        n_actions:   int   = N_ACTIONS,
        n_blocks:    int   = 4,
        dropout:     float = 0.1,
    ):
        super().__init__()
        self.input_dim  = input_dim
        self.hidden_dim = hidden_dim
        self.n_actions  = n_actions

        # Input projection
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )

        # Residual backbone
        self.blocks = nn.Sequential(*[
            ThorActorBlock(hidden_dim, dropout) for _ in range(n_blocks)
        ])

        # Action head
        self.action_head = nn.Sequential(
            nn.LayerNorm(hidden_dim),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),
            nn.Linear(hidden_dim // 2, n_actions),
        )

        # Threat-type detector (auxiliary task for better representations)
        self.threat_head = nn.Sequential(
            nn.LayerNorm(hidden_dim),
            nn.Linear(hidden_dim, n_actions),
        )

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=0.01)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x: Tensor) -> dict[str, Tensor]:
        """
        Args:
            x: [batch, FEATURE_DIM] float32
        Returns:
            dict with logits, probs, action, log_prob, entropy
        """
        h = self.input_proj(x)
        h = self.blocks(h)

        logits = self.action_head(h)        # [batch, N_ACTIONS]
        probs  = F.softmax(logits, dim=-1)  # [batch, N_ACTIONS]
        dist   = Categorical(probs)

        action   = dist.sample()            # [batch]
        log_prob = dist.log_prob(action)    # [batch]
        entropy  = dist.entropy()           # [batch]

        # Auxiliary threat detection
        threat_logits = self.threat_head(h)

        return {
            "logits":        logits,
            "probs":         probs,
            "action":        action,
            "log_prob":      log_prob,
            "entropy":       entropy,
            "threat_logits": threat_logits,
            "features":      h,             # embeddings for GNN
        }

    def get_action_and_log_prob(self, x: Tensor, action: Tensor) -> tuple[Tensor, Tensor]:
        """Used during PPO update to recompute log_probs for old actions."""
        out = self.forward(x)
        dist = Categorical(out["probs"])
        return dist.log_prob(action), dist.entropy()

    def get_deterministic_action(self, x: Tensor) -> Tensor:
        """Greedy action (argmax) for inference/evaluation."""
        with torch.no_grad():
            out = self.forward(x)
        return out["logits"].argmax(dim=-1)
