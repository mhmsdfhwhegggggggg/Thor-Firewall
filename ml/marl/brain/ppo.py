"""
Thor Firewall — PPO Trainer
============================
Proximal Policy Optimization لتدريب شبكة Actor-Critic.

الخوارزمية: MAPPO (Multi-Agent PPO) مع Centralized Critic
المرجع: "The Surprising Effectiveness of PPO in Cooperative Multi-Agent Games"
         https://arxiv.org/abs/2103.01955

المرحلة 1 (pretrain): Supervised Learning على CICIDS لمحاكاة سياسة جيدة
المرحلة 2 (rl_fine):  PPO fine-tuning على Thor environment مع reward shaping
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts

from .actor  import ThorActor, N_ACTIONS, FEATURE_DIM
from .critic import ThorCentralizedCritic

logger = logging.getLogger("thor.ppo")


@dataclass
class PPOConfig:
    # ── Dimensions ──────────────────────────────────────────────────────────
    input_dim:        int   = FEATURE_DIM     # 82
    hidden_dim:       int   = 256
    n_actions:        int   = N_ACTIONS       # 8
    n_agents:         int   = 4

    # ── PPO Hyperparameters ──────────────────────────────────────────────────
    clip_eps:         float = 0.2             # PPO clip ratio ε
    value_coef:       float = 0.5             # c1: value loss coefficient
    entropy_coef:     float = 0.01            # c2: entropy bonus
    aux_threat_coef:  float = 0.3             # auxiliary task weight
    gamma:            float = 0.99            # discount factor
    gae_lambda:       float = 0.95            # GAE λ

    # ── Optimization ─────────────────────────────────────────────────────────
    lr_actor:         float = 3e-4
    lr_critic:        float = 1e-3
    max_grad_norm:    float = 0.5
    weight_decay:     float = 1e-4

    # ── Training loop ─────────────────────────────────────────────────────────
    n_epochs:         int   = 4               # PPO epochs per rollout
    batch_size:       int   = 2048
    minibatch_size:   int   = 256
    rollout_len:      int   = 2048

    # ── Pretrain (Supervised) ─────────────────────────────────────────────────
    pretrain_epochs:  int   = 30
    pretrain_lr:      float = 1e-3
    pretrain_batch:   int   = 512


@dataclass
class RolloutBuffer:
    """Stores transitions for a single PPO update."""
    observations:  List[Tensor] = field(default_factory=list)
    actions:       List[Tensor] = field(default_factory=list)
    log_probs:     List[Tensor] = field(default_factory=list)
    rewards:       List[Tensor] = field(default_factory=list)
    values:        List[Tensor] = field(default_factory=list)
    dones:         List[Tensor] = field(default_factory=list)
    threat_labels: List[Tensor] = field(default_factory=list)

    def clear(self):
        for attr in vars(self):
            setattr(self, attr, [])

    def __len__(self):
        return len(self.observations)


class PPOTrainer:
    """
    MAPPO trainer for Thor Firewall threat classification.

    Two-phase training:
      Phase 1 — Supervised pretraining on CICIDS dataset (cross-entropy)
      Phase 2 — PPO fine-tuning with environment reward signal
    """

    def __init__(self, config: PPOConfig = PPOConfig(), device: str = "auto"):
        self.cfg = config
        self.device = torch.device(
            "cuda" if device == "auto" and torch.cuda.is_available() else
            "mps"  if device == "auto" and torch.backends.mps.is_available() else
            device if device != "auto" else "cpu"
        )
        logger.info("PPO device: %s", self.device)

        # Networks
        self.actor  = ThorActor(
            input_dim  = config.input_dim,
            hidden_dim = config.hidden_dim,
            n_actions  = config.n_actions,
        ).to(self.device)

        self.critic = ThorCentralizedCritic(
            global_state_dim = config.input_dim * config.n_agents,
            hidden_dim       = min(config.hidden_dim * 2, 512),
        ).to(self.device)

        # Optimizers
        self.actor_opt  = AdamW(self.actor.parameters(),
                                 lr=config.lr_actor, weight_decay=config.weight_decay)
        self.critic_opt = AdamW(self.critic.parameters(),
                                 lr=config.lr_critic, weight_decay=config.weight_decay)

        # LR schedulers (cosine warm restarts)
        self.actor_sched  = CosineAnnealingWarmRestarts(self.actor_opt,  T_0=10)
        self.critic_sched = CosineAnnealingWarmRestarts(self.critic_opt, T_0=10)

        self.buffer   = RolloutBuffer()
        self.step     = 0
        self._metrics: deque = deque(maxlen=100)

    # ── Phase 1: Supervised Pretraining ──────────────────────────────────────

    def pretrain_supervised(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val:   np.ndarray,
        y_val:   np.ndarray,
        mlflow_run=None,
    ) -> dict:
        """
        Cross-entropy pretraining on CICIDS labels.
        Gives the actor a good starting policy before RL fine-tuning.
        """
        logger.info("Phase 1: Supervised pretraining for %d epochs", self.cfg.pretrain_epochs)

        X_t = torch.from_numpy(X_train).float().to(self.device)
        y_t = torch.from_numpy(y_train).long().to(self.device)
        X_v = torch.from_numpy(X_val).float().to(self.device)
        y_v = torch.from_numpy(y_val).long().to(self.device)

        # Class weights for imbalanced dataset (BENIGN >> attacks)
        class_counts = np.bincount(y_train, minlength=self.cfg.n_actions).astype(float)
        class_counts = np.where(class_counts == 0, 1, class_counts)
        weights = 1.0 / class_counts
        weights = weights / weights.sum() * self.cfg.n_actions
        weight_tensor = torch.tensor(weights, dtype=torch.float32, device=self.device)
        criterion = nn.CrossEntropyLoss(weight=weight_tensor, label_smoothing=0.05)

        opt = AdamW(self.actor.parameters(), lr=self.cfg.pretrain_lr, weight_decay=1e-4)
        sched = CosineAnnealingWarmRestarts(opt, T_0=10)

        best_val_acc  = 0.0
        best_state    = None
        history       = {"train_loss": [], "val_acc": [], "val_loss": []}

        dataset = torch.utils.data.TensorDataset(X_t, y_t)
        loader  = torch.utils.data.DataLoader(
            dataset, batch_size=self.cfg.pretrain_batch, shuffle=True,
            num_workers=0, pin_memory=False,
        )

        for epoch in range(self.cfg.pretrain_epochs):
            self.actor.train()
            total_loss = 0.0
            correct    = 0
            total      = 0

            for xb, yb in loader:
                opt.zero_grad()
                out   = self.actor(xb)
                loss  = criterion(out["logits"], yb)
                # Auxiliary: threat detection (same labels)
                loss += self.cfg.aux_threat_coef * criterion(out["threat_logits"], yb)
                loss.backward()
                nn.utils.clip_grad_norm_(self.actor.parameters(), self.cfg.max_grad_norm)
                opt.step()

                total_loss += loss.item() * len(xb)
                correct    += (out["logits"].argmax(1) == yb).sum().item()
                total      += len(xb)

            sched.step()
            train_loss = total_loss / total
            train_acc  = correct / total

            # Validation
            self.actor.eval()
            with torch.no_grad():
                val_out  = self.actor(X_v)
                val_loss = criterion(val_out["logits"], y_v).item()
                val_acc  = (val_out["logits"].argmax(1) == y_v).float().mean().item()

            history["train_loss"].append(train_loss)
            history["val_acc"].append(val_acc)
            history["val_loss"].append(val_loss)

            if val_acc > best_val_acc:
                best_val_acc = val_acc
                best_state   = {k: v.cpu().clone() for k, v in self.actor.state_dict().items()}

            if mlflow_run:
                import mlflow
                mlflow.log_metrics({
                    "pretrain/train_loss": train_loss,
                    "pretrain/train_acc":  train_acc,
                    "pretrain/val_loss":   val_loss,
                    "pretrain/val_acc":    val_acc,
                }, step=epoch)

            logger.info(
                "[Pretrain %3d/%d] loss=%.4f  train_acc=%.3f  val_acc=%.3f",
                epoch + 1, self.cfg.pretrain_epochs, train_loss, train_acc, val_acc,
            )

        # Restore best weights
        if best_state:
            self.actor.load_state_dict(best_state)
        logger.info("Pretrain complete. Best val_acc=%.4f", best_val_acc)
        return {**history, "best_val_acc": best_val_acc}

    # ── Phase 2: PPO RL Fine-tuning ───────────────────────────────────────────

    def compute_gae(
        self,
        rewards: Tensor,
        values:  Tensor,
        dones:   Tensor,
        next_value: Tensor,
    ) -> Tuple[Tensor, Tensor]:
        """Generalized Advantage Estimation (GAE-λ)."""
        advantages = torch.zeros_like(rewards)
        gae = 0.0
        for t in reversed(range(len(rewards))):
            next_val = next_value if t == len(rewards) - 1 else values[t + 1]
            delta = rewards[t] + self.cfg.gamma * next_val * (1 - dones[t]) - values[t]
            gae   = delta + self.cfg.gamma * self.cfg.gae_lambda * (1 - dones[t]) * gae
            advantages[t] = gae
        returns = advantages + values
        return advantages, returns

    def ppo_update(self, global_states: Tensor) -> Dict[str, float]:
        """Single PPO update step (called after collecting rollout_len steps)."""
        if len(self.buffer) == 0:
            return {}

        obs      = torch.stack(self.buffer.observations).to(self.device)
        actions  = torch.stack(self.buffer.actions).to(self.device)
        old_lps  = torch.stack(self.buffer.log_probs).detach().to(self.device)
        rewards  = torch.stack(self.buffer.rewards).to(self.device)
        values   = torch.stack(self.buffer.values).detach().squeeze(-1).to(self.device)
        dones    = torch.stack(self.buffer.dones).to(self.device)
        labels   = torch.stack(self.buffer.threat_labels).long().to(self.device)

        # Get next value estimate
        with torch.no_grad():
            last_val = self.critic(
                global_states[-1:].expand(1, self.cfg.n_agents * self.cfg.input_dim)
            )["value"]

        advs, returns = self.compute_gae(rewards, values, dones, last_val.squeeze())
        advs = (advs - advs.mean()) / (advs.std() + 1e-8)

        n = len(obs)
        indices   = torch.randperm(n, device=self.device)
        metrics   = {"actor_loss": 0, "critic_loss": 0, "entropy": 0, "clip_frac": 0}
        n_updates = 0

        for _ in range(self.cfg.n_epochs):
            for start in range(0, n, self.cfg.minibatch_size):
                idx   = indices[start:start + self.cfg.minibatch_size]
                mb_obs    = obs[idx]
                mb_acts   = actions[idx]
                mb_old_lp = old_lps[idx]
                mb_advs   = advs[idx]
                mb_rets   = returns[idx]
                mb_labels = labels[idx]

                # Actor update
                new_lp, entropy = self.actor.get_action_and_log_prob(mb_obs, mb_acts)
                ratio   = (new_lp - mb_old_lp).exp()
                surr1   = ratio * mb_advs
                surr2   = ratio.clamp(1 - self.cfg.clip_eps, 1 + self.cfg.clip_eps) * mb_advs
                pg_loss = -torch.min(surr1, surr2).mean()

                # Auxiliary supervised loss (knowledge distillation from CICIDS labels)
                actor_out = self.actor(mb_obs)
                aux_loss  = F.cross_entropy(actor_out["threat_logits"], mb_labels)

                actor_loss = (pg_loss
                              - self.cfg.entropy_coef * entropy.mean()
                              + self.cfg.aux_threat_coef * aux_loss)

                self.actor_opt.zero_grad()
                actor_loss.backward()
                nn.utils.clip_grad_norm_(self.actor.parameters(), self.cfg.max_grad_norm)
                self.actor_opt.step()

                # Critic update (global state)
                gs = mb_obs.repeat(1, self.cfg.n_agents)  # simplified: same obs for all agents
                val_out  = self.critic(gs)
                val_pred = val_out["value"].squeeze()
                val_loss = F.mse_loss(val_pred, mb_rets)

                self.critic_opt.zero_grad()
                val_loss.backward()
                nn.utils.clip_grad_norm_(self.critic.parameters(), self.cfg.max_grad_norm)
                self.critic_opt.step()

                clip_frac = ((ratio - 1).abs() > self.cfg.clip_eps).float().mean().item()
                metrics["actor_loss"]  += actor_loss.item()
                metrics["critic_loss"] += val_loss.item()
                metrics["entropy"]     += entropy.mean().item()
                metrics["clip_frac"]   += clip_frac
                n_updates += 1

        self.buffer.clear()
        self.actor_sched.step()
        self.critic_sched.step()
        self.step += 1

        if n_updates > 0:
            return {k: v / n_updates for k, v in metrics.items()}
        return metrics

    # ── Serialization ─────────────────────────────────────────────────────────

    def save(self, path: str):
        torch.save({
            "actor":      self.actor.state_dict(),
            "critic":     self.critic.state_dict(),
            "actor_opt":  self.actor_opt.state_dict(),
            "critic_opt": self.critic_opt.state_dict(),
            "step":       self.step,
            "config":     vars(self.cfg),
        }, path)
        logger.info("Checkpoint saved: %s", path)

    def load(self, path: str):
        ckpt = torch.load(path, map_location=self.device)
        self.actor.load_state_dict(ckpt["actor"])
        self.critic.load_state_dict(ckpt["critic"])
        self.actor_opt.load_state_dict(ckpt["actor_opt"])
        self.critic_opt.load_state_dict(ckpt["critic_opt"])
        self.step = ckpt.get("step", 0)
        logger.info("Checkpoint loaded: %s (step %d)", path, self.step)

    def export_onnx(self, path: str):
        """Export actor to ONNX for production inference (no Python dependency)."""
        dummy = torch.randn(1, self.cfg.input_dim, device=self.device)
        torch.onnx.export(
            self.actor, dummy, path,
            input_names=["features"],
            output_names=["logits"],
            dynamic_axes={"features": {0: "batch"}, "logits": {0: "batch"}},
            opset_version=17,
        )
        logger.info("ONNX exported: %s", path)
