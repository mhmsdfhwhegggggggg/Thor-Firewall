"""
Thor Firewall — Multi-Agent Reinforcement Learning (MARL) Training
تدريب نموذج PPO ActorCritic للكشف عن التهديدات

البنية:
- ActorCritic مع ResidualBlocks
- PPO (Proximal Policy Optimization)
- MLflow tracking كامل
- دعم GPU تلقائي
- حفظ أفضل نموذج + ONNX export

المدخلات: feature vectors من CICIDS2018 (50 خاصية)
المخرجات: قرار 8 فئات + قيمة الحالة

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import argparse, logging, os, time
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger("thor.training.marl")

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not installed")

try:
    import mlflow
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False


# ── Model Architecture ─────────────────────────────────────────────────────────

class ResidualBlock(nn.Module):
    """Residual connection block للمعالجة العميقة"""
    def __init__(self, dim: int, dropout: float = 0.1):
        super().__init__()
        self.net = nn.Sequential(
            nn.LayerNorm(dim),
            nn.Linear(dim, dim * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(dim * 2, dim),
            nn.Dropout(dropout),
        )

    def forward(self, x):
        return x + self.net(x)


class ThorActorCritic(nn.Module):
    """
    Actor-Critic لـ PPO
    Actor:  يُقرر فئة التهديد (0=BENIGN ... 7=OTHER)
    Critic: يُقدر قيمة الحالة لتحسين الـ advantage
    """
    def __init__(self, input_dim: int = 50, hidden_dim: int = 256, n_actions: int = 8, n_residual: int = 4):
        super().__init__()
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
        )
        self.backbone = nn.Sequential(*[ResidualBlock(hidden_dim) for _ in range(n_residual)])
        self.actor_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),
            nn.Linear(hidden_dim // 2, n_actions),
        )
        self.critic_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.GELU(),
            nn.Linear(hidden_dim // 2, 1),
        )

    def forward(self, x):
        h = self.input_proj(x)
        h = self.backbone(h)
        return self.actor_head(h), self.critic_head(h).squeeze(-1)

    def act(self, x):
        logits, value = self.forward(x)
        dist = torch.distributions.Categorical(logits=logits)
        action = dist.sample()
        return action, dist.log_prob(action), dist.entropy(), value


# ── PPO Loss ──────────────────────────────────────────────────────────────────

def ppo_loss(
    logprobs: "torch.Tensor",
    old_logprobs: "torch.Tensor",
    advantages: "torch.Tensor",
    returns: "torch.Tensor",
    values: "torch.Tensor",
    clip_eps: float = 0.2,
    entropy_coef: float = 0.01,
    value_coef: float = 0.5,
    entropy: Optional["torch.Tensor"] = None,
) -> "torch.Tensor":
    ratio = torch.exp(logprobs - old_logprobs)
    surr1 = ratio * advantages
    surr2 = torch.clamp(ratio, 1 - clip_eps, 1 + clip_eps) * advantages
    policy_loss = -torch.min(surr1, surr2).mean()
    value_loss  = F.mse_loss(values, returns)
    ent_bonus   = entropy.mean() if entropy is not None else torch.tensor(0.0)
    return policy_loss + value_coef * value_loss - entropy_coef * ent_bonus


# ── Training Loop ─────────────────────────────────────────────────────────────

def train(
    data_dir: str = "data/processed",
    output_dir: str = "/models",
    epochs: int = 100,
    batch_size: int = 256,
    hidden_dim: int = 256,
    n_residual: int = 4,
    lr: float = 3e-4,
    clip_eps: float = 0.2,
    mlflow_uri: str = "http://mlflow:5000",
    experiment: str = "thor-marl-v1",
) -> None:
    if not TORCH_AVAILABLE:
        logger.error("PyTorch required. Install with: pip install torch")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Training on: %s", device)

    if MLFLOW_AVAILABLE:
        mlflow.set_tracking_uri(mlflow_uri)
        mlflow.set_experiment(experiment)
        run = mlflow.start_run(run_name=f"marl_ppo_{int(time.time())}")
        mlflow.log_params({
            "epochs": epochs, "batch_size": batch_size, "hidden_dim": hidden_dim,
            "n_residual": n_residual, "lr": lr, "clip_eps": clip_eps,
            "device": str(device),
        })

    # Load data
    data_path = Path(data_dir)
    try:
        X_train = np.load(data_path / "X_train.npy")
        y_train = np.load(data_path / "y_train.npy")
        X_val   = np.load(data_path / "X_val.npy")
        y_val   = np.load(data_path / "y_val.npy")
        logger.info("Loaded CICIDS2018: train=%d, val=%d", len(X_train), len(X_val))
    except FileNotFoundError:
        logger.warning("Processed data not found — using synthetic data. Run preprocess.py first.")
        rng = np.random.default_rng(42)
        n = 50_000
        X_train = rng.standard_normal((n, 50)).astype(np.float32)
        y_train = rng.integers(0, 8, n)
        X_val   = rng.standard_normal((10_000, 50)).astype(np.float32)
        y_val   = rng.integers(0, 8, 10_000)

    input_dim = X_train.shape[1]
    n_classes = int(y_train.max()) + 1

    train_loader = DataLoader(
        TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train)),
        batch_size=batch_size, shuffle=True, pin_memory=(device.type == "cuda"),
    )

    model = ThorActorCritic(input_dim, hidden_dim, n_classes, n_residual).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_val_acc = 0.0
    os.makedirs(output_dir, exist_ok=True)
    best_path = os.path.join(output_dir, "thor_marl_best.pt")

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        correct = 0

        for X_b, y_b in train_loader:
            X_b, y_b = X_b.to(device), y_b.to(device)
            actions, logprobs, entropy, values = model.act(X_b)
            advantages = (y_b == actions).float() - values.detach()
            returns = (y_b == actions).float()
            logits, _ = model(X_b)
            old_lp = torch.distributions.Categorical(logits=logits.detach()).log_prob(actions)
            loss = ppo_loss(logprobs, old_lp, advantages, returns, values, clip_eps, entropy=entropy)
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 0.5)
            optimizer.step()
            total_loss += loss.item()
            correct += (actions == y_b).sum().item()

        scheduler.step()
        train_acc = correct / len(X_train)

        # Validation
        model.eval()
        with torch.no_grad():
            X_v = torch.FloatTensor(X_val).to(device)
            logits, _ = model(X_v)
            preds = logits.argmax(1).cpu().numpy()
            val_acc = (preds == y_val).mean()

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save({
                "epoch": epoch, "model_state": model.state_dict(),
                "val_accuracy": val_acc, "architecture": {
                    "input_dim": input_dim, "hidden_dim": hidden_dim,
                    "n_classes": n_classes, "n_residual": n_residual,
                }
            }, best_path)

        if epoch % 10 == 0 or epoch == 1:
            logger.info("Epoch %d/%d | loss=%.4f | train_acc=%.4f | val_acc=%.4f",
                        epoch, epochs, total_loss, train_acc, val_acc)
            if MLFLOW_AVAILABLE:
                mlflow.log_metrics({
                    "train/loss": total_loss, "train/accuracy": train_acc,
                    "val/accuracy": val_acc,
                }, step=epoch)

    # Export ONNX
    try:
        onnx_path = os.path.join(output_dir, "thor_marl.onnx")
        dummy = torch.zeros(1, input_dim).to(device)
        torch.onnx.export(model, dummy, onnx_path,
                          input_names=["features"], output_names=["logits", "value"],
                          dynamic_axes={"features": {0: "batch"}})
        logger.info("ONNX model exported: %s", onnx_path)
    except Exception as e:
        logger.warning("ONNX export failed: %s", e)

    if MLFLOW_AVAILABLE:
        mlflow.log_metric("best_val_accuracy", best_val_acc)
        mlflow.pytorch.log_model(model, "models/marl", registered_model_name="thor_marl")
        mlflow.end_run()

    logger.info("✅ Training complete. Best val_accuracy=%.4f", best_val_acc)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir",   default="data/processed")
    p.add_argument("--output-dir", default="/models")
    p.add_argument("--epochs",     type=int,   default=100)
    p.add_argument("--batch-size", type=int,   default=256)
    p.add_argument("--hidden-dim", type=int,   default=256)
    p.add_argument("--n-residual", type=int,   default=4)
    p.add_argument("--lr",         type=float, default=3e-4)
    p.add_argument("--mlflow-uri", default="http://mlflow:5000")
    p.add_argument("--experiment", default="thor-marl-v1")
    args = p.parse_args()
    train(
        data_dir=args.data_dir,   output_dir=args.output_dir,
        epochs=args.epochs,       batch_size=args.batch_size,
        hidden_dim=args.hidden_dim, n_residual=args.n_residual,
        lr=args.lr, mlflow_uri=args.mlflow_uri, experiment=args.experiment,
    )
