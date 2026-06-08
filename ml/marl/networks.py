"""
Thor Firewall — Neural Network Architectures
معماريات الشبكات العصبية لنظام MARL

تتضمن:
  1. AttentionPolicyNet  — شبكة السياسة مع Self-Attention
  2. ValueNet            — شبكة القيمة المركزية (Centralized Critic)
  3. ThreatEncoder       — مشفّر السمات الأمنية
  4. TemporalConvNet     — استخراج الأنماط الزمنية من التدفقات
  5. ProtocolSpecificNet — شبكة مخصصة لكل بروتوكول

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import math
from typing import List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


# ============================================================================
# Building Blocks
# ============================================================================

class SwiGLU(nn.Module):
    """SwiGLU activation (Noam Shazeer 2020) — better than ReLU/GELU."""
    def __init__(self, dim: int, hidden_dim: Optional[int] = None):
        super().__init__()
        hidden_dim = hidden_dim or dim * 4
        self.w1 = nn.Linear(dim, hidden_dim, bias=False)
        self.w2 = nn.Linear(dim, hidden_dim, bias=False)
        self.w3 = nn.Linear(hidden_dim, dim, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.w3(F.silu(self.w1(x)) * self.w2(x))


class RMSNorm(nn.Module):
    """Root Mean Square Normalization (faster than LayerNorm)."""
    def __init__(self, dim: int, eps: float = 1e-8):
        super().__init__()
        self.eps   = eps
        self.scale = nn.Parameter(torch.ones(dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        rms = x.pow(2).mean(-1, keepdim=True).add(self.eps).sqrt()
        return self.scale * (x / rms)


class ResidualBlock(nn.Module):
    """Pre-norm residual block with SwiGLU."""
    def __init__(self, dim: int, dropout: float = 0.1):
        super().__init__()
        self.norm  = RMSNorm(dim)
        self.ff    = SwiGLU(dim)
        self.drop  = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.drop(self.ff(self.norm(x)))


class CausalSelfAttention(nn.Module):
    """Multi-head self-attention over flow sequence (temporal context)."""
    def __init__(self, dim: int, n_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        assert dim % n_heads == 0
        self.n_heads = n_heads
        self.head_dim = dim // n_heads
        self.scale    = self.head_dim ** -0.5

        self.qkv  = nn.Linear(dim, 3 * dim, bias=False)
        self.proj = nn.Linear(dim, dim, bias=False)
        self.norm = RMSNorm(dim)
        self.drop = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        B, T, D = x.shape
        qkv = self.qkv(self.norm(x)).chunk(3, dim=-1)
        Q, K, V = [t.view(B, T, self.n_heads, self.head_dim).transpose(1, 2) for t in qkv]

        # Flash-Attention if available, else manual
        if hasattr(F, "scaled_dot_product_attention"):
            out = F.scaled_dot_product_attention(Q, K, V, dropout_p=self.drop.p if self.training else 0.0)
        else:
            attn = (Q @ K.transpose(-2, -1)) * self.scale
            attn = F.softmax(attn, dim=-1)
            attn = self.drop(attn)
            out  = attn @ V

        out = out.transpose(1, 2).contiguous().view(B, T, D)
        return x + self.proj(out)


# ============================================================================
# Threat Feature Encoder
// ============================================================================

class ThreatEncoder(nn.Module):
    """
    Encodes raw flow features (50-dim) + GNN context (32-dim) into
    a rich threat-aware representation (256-dim).

    Architecture:
      Input  → Linear projection → 4× ResidualBlocks → output
    """
    def __init__(
        self,
        flow_dim:    int = 50,
        gnn_dim:     int = 32,
        output_dim:  int = 256,
        num_blocks:  int = 4,
        dropout:     float = 0.1,
    ):
        super().__init__()
        input_dim = flow_dim + gnn_dim

        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, output_dim),
            RMSNorm(output_dim),
            nn.GELU(),
        )

        self.blocks = nn.ModuleList([
            ResidualBlock(output_dim, dropout) for _ in range(num_blocks)
        ])

        self.output_norm = RMSNorm(output_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (B, flow_dim + gnn_dim)"""
        h = self.input_proj(x)
        for block in self.blocks:
            h = block(h)
        return self.output_norm(h)


# ============================================================================
# Temporal Convolutional Network
// ============================================================================

class TemporalConvNet(nn.Module):
    """
    1D Causal Dilated Convolutions over a sequence of flow embeddings.
    Captures temporal patterns without recurrent state.

    Based on: Bai et al., "An Empirical Evaluation of Generic Convolutional
    and Recurrent Networks for Sequence Modeling" (2018).
    """
    def __init__(self, dim: int = 256, n_levels: int = 4, kernel_size: int = 3):
        super().__init__()
        layers = []
        for i in range(n_levels):
            dilation  = 2 ** i
            padding   = (kernel_size - 1) * dilation
            layers += [
                nn.Conv1d(dim, dim, kernel_size, padding=padding, dilation=dilation),
                nn.GELU(),
                nn.utils.weight_norm(nn.Conv1d(dim, dim, 1)),
            ]
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (B, T, D) → (B, T, D)"""
        return self.net(x.transpose(1, 2)).transpose(1, 2)


# ============================================================================
# Policy Network
// ============================================================================

class AttentionPolicyNet(nn.Module):
    """
    Actor network with temporal self-attention.

    Takes: encoded flow feature + flow history
    Outputs: action logits over 5 possible actions
    """

    def __init__(
        self,
        encoded_dim:  int = 256,
        history_len:  int = 16,
        n_heads:      int = 4,
        n_attn_layers: int = 2,
        action_dim:   int = 5,
        dropout:      float = 0.1,
    ):
        super().__init__()
        self.history_len = history_len

        self.attn_layers = nn.ModuleList([
            CausalSelfAttention(encoded_dim, n_heads, dropout)
            for _ in range(n_attn_layers)
        ])

        self.ff_blocks = nn.ModuleList([
            ResidualBlock(encoded_dim, dropout)
            for _ in range(n_attn_layers)
        ])

        self.head = nn.Sequential(
            RMSNorm(encoded_dim),
            nn.Linear(encoded_dim, action_dim),
        )

    def forward(self, encoded: torch.Tensor, history: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        encoded: (B, D)
        history: (B, T, D) optional
        returns: (B, action_dim) logits
        """
        if history is not None:
            # Append current embedding to history
            x = torch.cat([history, encoded.unsqueeze(1)], dim=1)  # (B, T+1, D)
        else:
            x = encoded.unsqueeze(1)  # (B, 1, D)

        for attn, ff in zip(self.attn_layers, self.ff_blocks):
            x = attn(x)
            x = ff(x)

        # Use last token as representation
        return self.head(x[:, -1])   # (B, action_dim)


# ============================================================================
# Value Network (Centralized Critic)
// ============================================================================

class CentralizedValueNet(nn.Module):
    """
    Centralized critic for MARL — sees ALL agent observations.
    Provides lower-variance value estimates during training.

    Input: concatenated observations from all agents (N_agents × D)
    Output: scalar value estimate V(s)
    """

    def __init__(
        self,
        encoded_dim: int = 256,
        n_agents:    int = 3,       # TCP, UDP, ICMP agents
        hidden_dim:  int = 512,
        n_layers:    int = 3,
        dropout:     float = 0.1,
    ):
        super().__init__()

        input_dim = encoded_dim * n_agents

        layers: List[nn.Module] = [
            nn.Linear(input_dim, hidden_dim),
            RMSNorm(hidden_dim),
            nn.GELU(),
        ]
        for _ in range(n_layers - 1):
            layers += [ResidualBlock(hidden_dim, dropout)]

        layers += [
            RMSNorm(hidden_dim),
            nn.Linear(hidden_dim, 1),
        ]

        self.net = nn.Sequential(*layers)

    def forward(self, all_agent_obs: torch.Tensor) -> torch.Tensor:
        """
        all_agent_obs: (B, N_agents × D)
        returns: (B, 1)
        """
        return self.net(all_agent_obs)


# ============================================================================
# Protocol-Specific Networks
// ============================================================================

class ProtocolNet(nn.Module):
    """
    Lightweight specialist network per protocol (TCP, UDP, ICMP).
    Fused with the main encoder via cross-attention.
    """

    PROTOCOL_FEATURES = {
        "tcp":  [4, 5, 6, 7, 8, 9, 10, 11, 12, 13],  # indices in flow feature vector
        "udp":  [0, 1, 2, 3, 14, 15, 16, 17],
        "icmp": [0, 1, 18, 19, 20, 21],
    }

    def __init__(self, protocol: str, output_dim: int = 64):
        super().__init__()
        self.protocol = protocol
        self.feat_idx = torch.tensor(self.PROTOCOL_FEATURES.get(protocol, list(range(16))))
        input_dim = len(self.feat_idx)

        self.net = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.GELU(),
            nn.Linear(128, output_dim),
            RMSNorm(output_dim),
        )

    def forward(self, flow_features: torch.Tensor) -> torch.Tensor:
        """flow_features: (B, 50)"""
        selected = flow_features[:, self.feat_idx.to(flow_features.device)]
        return self.net(selected)


# ============================================================================
# Full Agent Architecture
// ============================================================================

class ThorAgentNet(nn.Module):
    """
    Complete neural architecture for one MARL agent.

    Inputs:
      - flow_features (B, 50)
      - gnn_embedding (B, 32)
      - flow_history  (B, T, 256)  optional

    Output:
      - action_logits (B, 5)
      - value_estimate (B, 1)   [for shared critic baseline]
    """

    def __init__(
        self,
        protocol:     str = "tcp",
        action_dim:   int = 5,
        encoded_dim:  int = 256,
        history_len:  int = 16,
    ):
        super().__init__()
        self.protocol = protocol

        self.encoder      = ThreatEncoder(output_dim=encoded_dim)
        self.proto_net    = ProtocolNet(protocol, output_dim=64)
        self.fusion       = nn.Sequential(
            nn.Linear(encoded_dim + 64, encoded_dim),
            RMSNorm(encoded_dim),
            nn.GELU(),
        )
        self.policy_net   = AttentionPolicyNet(encoded_dim=encoded_dim, action_dim=action_dim)
        self.value_head   = nn.Sequential(
            RMSNorm(encoded_dim),
            nn.Linear(encoded_dim, 1),
        )

    def forward(
        self,
        flow_features: torch.Tensor,   # (B, 50)
        gnn_embedding: torch.Tensor,   # (B, 32)
        flow_history:  Optional[torch.Tensor] = None,  # (B, T, 256)
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Returns: (action_logits, value, encoded)"""
        x       = torch.cat([flow_features, gnn_embedding], dim=-1)
        encoded = self.encoder(x)
        proto   = self.proto_net(flow_features)
        fused   = self.fusion(torch.cat([encoded, proto], dim=-1))

        logits = self.policy_net(fused, flow_history)
        value  = self.value_head(fused)

        return logits, value, fused

    def act(self, obs: torch.Tensor, deterministic: bool = False) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Sample an action from the policy.
        Returns: (action, log_prob, value)
        """
        with torch.no_grad():
            flow_feat = obs[:, :50]
            gnn_feat  = obs[:, 50:82] if obs.shape[1] >= 82 else torch.zeros(obs.shape[0], 32, device=obs.device)
            logits, value, _ = self.forward(flow_feat, gnn_feat)

            dist     = torch.distributions.Categorical(logits=logits)
            action   = logits.argmax(dim=-1) if deterministic else dist.sample()
            log_prob = dist.log_prob(action)

        return action, log_prob, value.squeeze(-1)
