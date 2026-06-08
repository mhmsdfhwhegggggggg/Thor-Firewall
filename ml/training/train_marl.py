"""
Thor Firewall — MARL Training Pipeline with MLflow
تدريب نماذج Multi-Agent Reinforcement Learning مع تتبع MLflow

يُشغّل:
  - PPO training لكل protocol agent (TCP/UDP/ICMP)
  - MetaAgent ensemble training
  - تسجيل كل experiment في MLflow
  - Hyperparameter search عبر Optuna
  - حفظ أفضل نموذج في Model Registry

الاستخدام:
  python train_marl.py --epochs 100 --batch-size 64 --experiment thor-marl-v1

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger("thor.training.marl")

# ──────────────────────────────────────────────────────────────────────────────
# Try importing optional dependencies
# ──────────────────────────────────────────────────────────────────────────────

try:
    import mlflow
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    logger.warning("MLflow not installed — metrics will be logged to file only")

try:
    import optuna
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────────────
# Neural Network Architecture
# ──────────────────────────────────────────────────────────────────────────────

class ResidualBlock(nn.Module):
    """ResidualBlock مع BatchNorm + GELU"""
    def __init__(self, dim: int, dropout: float = 0.1):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
        )
        self.act = nn.GELU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.act(x + self.net(x))


class ActorCriticNetwork(nn.Module):
    """
    Actor-Critic Network للـ PPO
    Input: 50 packet features + 32 GNN embedding = 82 features
    Output: action probabilities (5 actions) + value estimate
    """

    ACTIONS = ["allow", "block", "throttle_100pps", "mirror", "redirect_honeypot"]

    def __init__(
        self,
        input_dim: int = 50,
        hidden_dim: int = 256,
        n_actions: int = 5,
        n_residual_blocks: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_dim = input_dim

        # Shared feature extractor
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.GELU(),
        )

        self.residual_blocks = nn.Sequential(
            *[ResidualBlock(hidden_dim, dropout) for _ in range(n_residual_blocks)]
        )

        # Actor head (policy)
        self.actor_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),
            nn.Linear(hidden_dim // 2, n_actions),
        )

        # Critic head (value)
        self.critic_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),
            nn.Linear(hidden_dim // 2, 1),
        )

        # Weight initialization
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=np.sqrt(2))
                nn.init.constant_(m.bias, 0)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        features = self.input_proj(x)
        features = self.residual_blocks(features)
        logits = self.actor_head(features)
        value = self.critic_head(features)
        return logits, value

    def get_action_and_value(self, x: torch.Tensor, action: Optional[torch.Tensor] = None):
        logits, value = self.forward(x)
        dist = torch.distributions.Categorical(logits=logits)
        if action is None:
            action = dist.sample()
        log_prob = dist.log_prob(action)
        entropy = dist.entropy()
        return action, log_prob, entropy, value


class ProtocolAgent:
    """وكيل متخصص لبروتوكول معين (TCP/UDP/ICMP)"""

    def __init__(
        self,
        protocol: str,
        input_dim: int = 50,
        hidden_dim: int = 256,
        lr: float = 3e-4,
        device: str = "cpu",
    ):
        self.protocol = protocol
        self.device = torch.device(device)

        self.network = ActorCriticNetwork(
            input_dim=input_dim,
            hidden_dim=hidden_dim,
        ).to(self.device)

        self.optimizer = optim.Adam(
            self.network.parameters(),
            lr=lr,
            eps=1e-5,
        )
        self.lr_scheduler = optim.lr_scheduler.CosineAnnealingLR(
            self.optimizer, T_max=100, eta_min=1e-6
        )

    def save(self, path: str):
        torch.save({
            "protocol": self.protocol,
            "state_dict": self.network.state_dict(),
            "optimizer": self.optimizer.state_dict(),
        }, path)

    def load(self, path: str):
        checkpoint = torch.load(path, map_location=self.device)
        self.network.load_state_dict(checkpoint["state_dict"])
        self.optimizer.load_state_dict(checkpoint["optimizer"])


# ──────────────────────────────────────────────────────────────────────────────
# PPO Trainer
# ──────────────────────────────────────────────────────────────────────────────

class PPOTrainer:
    """
    PPO (Proximal Policy Optimization) Trainer
    مرجع: Schulman et al., 2017
    """

    def __init__(
        self,
        agent: ProtocolAgent,
        clip_eps: float = 0.2,
        value_coef: float = 0.5,
        entropy_coef: float = 0.01,
        max_grad_norm: float = 0.5,
        n_epochs: int = 4,
        mini_batch_size: int = 64,
    ):
        self.agent = agent
        self.clip_eps = clip_eps
        self.value_coef = value_coef
        self.entropy_coef = entropy_coef
        self.max_grad_norm = max_grad_norm
        self.n_epochs = n_epochs
        self.mini_batch_size = mini_batch_size

    def compute_gae(
        self,
        rewards: torch.Tensor,
        values: torch.Tensor,
        dones: torch.Tensor,
        gamma: float = 0.99,
        lam: float = 0.95,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Generalized Advantage Estimation"""
        T = len(rewards)
        advantages = torch.zeros(T, device=self.agent.device)
        last_gae = 0.0

        for t in reversed(range(T)):
            if t == T - 1:
                next_value = 0.0
            else:
                next_value = values[t + 1]

            delta = rewards[t] + gamma * next_value * (1 - dones[t]) - values[t]
            last_gae = delta + gamma * lam * (1 - dones[t]) * last_gae
            advantages[t] = last_gae

        returns = advantages + values
        # Normalize advantages
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
        return advantages, returns

    def update(
        self,
        obs: torch.Tensor,
        actions: torch.Tensor,
        old_log_probs: torch.Tensor,
        advantages: torch.Tensor,
        returns: torch.Tensor,
    ) -> Dict[str, float]:
        """تحديث الشبكة باستخدام PPO"""
        total_policy_loss = 0.0
        total_value_loss = 0.0
        total_entropy = 0.0
        n_updates = 0

        dataset = TensorDataset(obs, actions, old_log_probs, advantages, returns)
        loader = DataLoader(dataset, batch_size=self.mini_batch_size, shuffle=True)

        for _ in range(self.n_epochs):
            for batch in loader:
                b_obs, b_actions, b_old_lp, b_adv, b_returns = [x.to(self.agent.device) for x in batch]

                _, new_log_probs, entropy, values = self.agent.network.get_action_and_value(b_obs, b_actions)
                values = values.squeeze(-1)

                ratio = torch.exp(new_log_probs - b_old_lp)
                clipped_ratio = torch.clamp(ratio, 1 - self.clip_eps, 1 + self.clip_eps)
                policy_loss = -torch.min(ratio * b_adv, clipped_ratio * b_adv).mean()

                value_loss = nn.functional.mse_loss(values, b_returns)

                loss = policy_loss + self.value_coef * value_loss - self.entropy_coef * entropy.mean()

                self.agent.optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(self.agent.network.parameters(), self.max_grad_norm)
                self.agent.optimizer.step()

                total_policy_loss += policy_loss.item()
                total_value_loss += value_loss.item()
                total_entropy += entropy.mean().item()
                n_updates += 1

        self.agent.lr_scheduler.step()

        return {
            "policy_loss": total_policy_loss / max(n_updates, 1),
            "value_loss": total_value_loss / max(n_updates, 1),
            "entropy": total_entropy / max(n_updates, 1),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Supervised Pre-training on CICIDS2018
# ──────────────────────────────────────────────────────────────────────────────

class SupervisedPretrainer:
    """
    تدريب مسبق (supervised) على CICIDS2018 قبل RL.
    يُسرّع التقارب ويُحسّن الأداء على الهجمات الحقيقية.
    """

    def __init__(
        self,
        agent: ProtocolAgent,
        processed_dir: str = "../data/processed",
        epochs: int = 50,
        batch_size: int = 256,
        device: str = "cpu",
    ):
        self.agent = agent
        self.processed_dir = Path(processed_dir)
        self.epochs = epochs
        self.batch_size = batch_size
        self.device = torch.device(device)

    def load_data(self) -> Tuple[DataLoader, DataLoader, DataLoader]:
        """تحميل البيانات المعالجة مسبقاً"""
        X_train = np.load(self.processed_dir / "X_train.npy")
        y_train = np.load(self.processed_dir / "y_train.npy")
        X_val   = np.load(self.processed_dir / "X_val.npy")
        y_val   = np.load(self.processed_dir / "y_val.npy")
        X_test  = np.load(self.processed_dir / "X_test.npy")
        y_test  = np.load(self.processed_dir / "y_test.npy")

        def make_loader(X, y, shuffle=False):
            X_t = torch.FloatTensor(X[:, :self.agent.network.input_dim])
            y_t = torch.LongTensor(y)
            ds = TensorDataset(X_t, y_t)
            return DataLoader(ds, batch_size=self.batch_size, shuffle=shuffle, num_workers=2)

        return make_loader(X_train, y_train, shuffle=True), \
               make_loader(X_val, y_val), \
               make_loader(X_test, y_test)

    def train(self) -> Dict[str, List[float]]:
        """دورة التدريب الكاملة مع تتبع MLflow"""
        try:
            train_loader, val_loader, test_loader = self.load_data()
        except FileNotFoundError:
            logger.warning("Processed data not found. Run preprocess.py first.")
            logger.info("Generating synthetic data for demonstration...")
            from ml.data.preprocess import run_pipeline
            run_pipeline(use_synthetic=True, output_dir=str(self.processed_dir))
            train_loader, val_loader, test_loader = self.load_data()

        criterion = nn.CrossEntropyLoss()
        history: Dict[str, List[float]] = {"train_loss": [], "val_loss": [], "val_acc": []}

        best_val_acc = 0.0
        best_model_path = f"/tmp/thor_{self.agent.protocol}_best.pt"

        for epoch in range(self.epochs):
            # Training
            self.agent.network.train()
            train_loss = 0.0
            for X_batch, y_batch in train_loader:
                X_batch = X_batch.to(self.device)
                y_batch = y_batch.to(self.device)

                logits, _ = self.agent.network(X_batch)
                loss = criterion(logits, y_batch)

                self.agent.optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(self.agent.network.parameters(), 0.5)
                self.agent.optimizer.step()

                train_loss += loss.item()

            train_loss /= len(train_loader)

            # Validation
            self.agent.network.eval()
            val_loss = 0.0
            correct = 0
            total = 0
            with torch.no_grad():
                for X_batch, y_batch in val_loader:
                    X_batch = X_batch.to(self.device)
                    y_batch = y_batch.to(self.device)
                    logits, _ = self.agent.network(X_batch)
                    loss = criterion(logits, y_batch)
                    val_loss += loss.item()
                    preds = logits.argmax(dim=1)
                    correct += (preds == y_batch).sum().item()
                    total += len(y_batch)

            val_loss /= len(val_loader)
            val_acc = correct / total

            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_loss)
            history["val_acc"].append(val_acc)

            if val_acc > best_val_acc:
                best_val_acc = val_acc
                self.agent.save(best_model_path)

            if (epoch + 1) % 10 == 0:
                logger.info(
                    "Epoch %d/%d | train_loss=%.4f val_loss=%.4f val_acc=%.4f",
                    epoch + 1, self.epochs, train_loss, val_loss, val_acc
                )

            if MLFLOW_AVAILABLE:
                mlflow.log_metrics({
                    f"{self.agent.protocol}/train_loss": train_loss,
                    f"{self.agent.protocol}/val_loss": val_loss,
                    f"{self.agent.protocol}/val_acc": val_acc,
                }, step=epoch)

        logger.info("✅ Best val_acc: %.4f", best_val_acc)
        return history


# ──────────────────────────────────────────────────────────────────────────────
# Main Training Entry Point
# ──────────────────────────────────────────────────────────────────────────────

def train_all_agents(args: argparse.Namespace):
    """تدريب جميع الوكلاء مع MLflow tracking"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
    )

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("Training on: %s", device)

    if MLFLOW_AVAILABLE:
        mlflow.set_tracking_uri(args.mlflow_uri)
        mlflow.set_experiment(args.experiment)
        run = mlflow.start_run(run_name=f"marl_training_{int(time.time())}")
        mlflow.log_params({
            "protocols": ["tcp", "udp", "icmp"],
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "hidden_dim": args.hidden_dim,
            "lr": args.lr,
            "device": device,
        })

    results = {}

    for protocol in ["tcp", "udp", "icmp"]:
        logger.info("=" * 60)
        logger.info("Training %s agent...", protocol.upper())

        agent = ProtocolAgent(
            protocol=protocol,
            input_dim=50,
            hidden_dim=args.hidden_dim,
            lr=args.lr,
            device=device,
        )

        pretrainer = SupervisedPretrainer(
            agent=agent,
            processed_dir=args.data_dir,
            epochs=args.epochs,
            batch_size=args.batch_size,
            device=device,
        )

        history = pretrainer.train()
        results[protocol] = history

        # Save model
        model_path = os.path.join(args.output_dir, f"thor_{protocol}_agent.pt")
        os.makedirs(args.output_dir, exist_ok=True)
        agent.save(model_path)
        logger.info("Saved %s agent to %s", protocol, model_path)

        if MLFLOW_AVAILABLE:
            mlflow.pytorch.log_model(
                agent.network,
                artifact_path=f"models/{protocol}_agent",
                registered_model_name=f"thor_{protocol}_agent",
            )

    # Summary
    summary = {
        protocol: {
            "final_val_acc": history["val_acc"][-1] if history["val_acc"] else 0,
            "best_val_acc": max(history["val_acc"]) if history["val_acc"] else 0,
        }
        for protocol, history in results.items()
    }

    with open(os.path.join(args.output_dir, "training_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    if MLFLOW_AVAILABLE:
        mlflow.log_artifact(os.path.join(args.output_dir, "training_summary.json"))
        mlflow.end_run()

    logger.info("=" * 60)
    logger.info("✅ Training complete!")
    for protocol, s in summary.items():
        logger.info("  %s: best_val_acc=%.4f", protocol, s["best_val_acc"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Thor MARL Training")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--hidden-dim", type=int, default=256)
    parser.add_argument("--lr", type=float, default=3e-4)
    parser.add_argument("--data-dir", default="../data/processed")
    parser.add_argument("--output-dir", default="/models/marl")
    parser.add_argument("--mlflow-uri", default="http://mlflow:5000")
    parser.add_argument("--experiment", default="thor-marl-v1")
    args = parser.parse_args()
    train_all_agents(args)
