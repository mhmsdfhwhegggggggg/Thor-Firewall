"""
Thor Firewall — Centralized Critic (Value Network)
===================================================
في MARL، الـ Critic مركزي: يرى observations جميع الـ Agents
لحساب قيمة الحالة الكلية V(s) بدقة أعلى.

المدخلات:  global_state  [batch, N_AGENTS * FEATURE_DIM]
           أو            [batch, GLOBAL_STATE_DIM]
المخرجات:  value         [batch, 1]
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor


FEATURE_DIM       = 82
N_AGENTS_DEFAULT  = 4     # default: 4 agents per deployment
GLOBAL_STATE_DIM  = FEATURE_DIM * N_AGENTS_DEFAULT  # 328


class ThorCentralizedCritic(nn.Module):
    """
    CTDE (Centralized Training, Decentralized Execution) Critic.
    
    During training: receives global state (all agents concatenated).
    During execution: only the Actor is needed (no Critic inference).
    """

    def __init__(
        self,
        global_state_dim: int   = GLOBAL_STATE_DIM,
        hidden_dim:       int   = 512,
        n_blocks:         int   = 6,
        dropout:          float = 0.1,
    ):
        super().__init__()
        self.global_state_dim = global_state_dim

        # Attention-based global state encoder
        self.state_encoder = nn.Sequential(
            nn.Linear(global_state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )

        # Multi-head self-attention for cross-agent information sharing
        self.attn = nn.MultiheadAttention(
            embed_dim    = hidden_dim,
            num_heads    = 8,
            dropout      = dropout,
            batch_first  = True,
        )
        self.attn_norm = nn.LayerNorm(hidden_dim)

        # Deep value network
        self.value_net = nn.Sequential(
            *[self._make_block(hidden_dim, dropout) for _ in range(n_blocks)],
            nn.LayerNorm(hidden_dim),
        )

        # Value head with dual outputs for variance reduction
        self.value_head = nn.Linear(hidden_dim, 1)
        self.var_head   = nn.Linear(hidden_dim, 1)  # predicted return variance

        self._init_weights()

    def _make_block(self, dim: int, dropout: float) -> nn.Module:
        return nn.Sequential(
            nn.LayerNorm(dim),
            nn.Linear(dim, dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(dim * 2, dim),
            nn.Dropout(dropout),
        )

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=1.0)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
        # Value head: small init for stable value estimates
        nn.init.orthogonal_(self.value_head.weight, gain=0.01)
        nn.init.orthogonal_(self.var_head.weight,   gain=0.01)

    def forward(self, global_state: Tensor) -> dict[str, Tensor]:
        """
        Args:
            global_state: [batch, global_state_dim]
        Returns:
            value:    [batch, 1]
            variance: [batch, 1]  (for distributional RL)
        """
        h = self.state_encoder(global_state)  # [batch, hidden]

        # Self-attention: treat hidden dim as sequence of 1
        h_seq = h.unsqueeze(1)                # [batch, 1, hidden]
        h_attn, _ = self.attn(h_seq, h_seq, h_seq)
        h = self.attn_norm(h + h_attn.squeeze(1))

        h = self.value_net(h) + h  # residual

        value    = self.value_head(h)
        variance = F.softplus(self.var_head(h))  # always positive

        return {"value": value, "variance": variance}


class ThorAgentCritic(nn.Module):
    """
    Per-agent critic variant (for Independent PPO baseline).
    Uses only local observation, simpler than centralized critic.
    """

    def __init__(
        self,
        input_dim:  int   = FEATURE_DIM,
        hidden_dim: int   = 256,
        n_blocks:   int   = 4,
        dropout:    float = 0.1,
    ):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            *[nn.Sequential(
                nn.LayerNorm(hidden_dim),
                nn.Linear(hidden_dim, hidden_dim),
                nn.GELU(),
                nn.Dropout(dropout),
              ) for _ in range(n_blocks)],
        )
        self.value_head = nn.Linear(hidden_dim, 1)
        nn.init.orthogonal_(self.value_head.weight, gain=0.01)

    def forward(self, x: Tensor) -> Tensor:
        return self.value_head(self.net(x))
