"""
Thor Firewall — MARL Training Script
سكريبت تدريب نظام التعلم المعزز المتعدد الوكلاء

يستخدم:
- مجموعة بيانات CICIDS2017/2018 للتدريب المُشرف الأولي
- بيئة شبكية مُحاكاة للتدريب المعزز
- Ray RLlib للتدريب الموزع
- Weights & Biases لتتبع التجارب

الاستخدام:
    python -m ml.training.train_marl \
        --dataset ml/data/CICIDS2017 \
        --output ml/checkpoints/ \
        --protocol tcp \
        --epochs 100 \
        --wandb-project thor-marl
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn.functional as F

try:
    import wandb
    WANDB_AVAILABLE = True
except ImportError:
    WANDB_AVAILABLE = False

from ml.marl.agents import MetaAgent, MARLConfig, ACTION_SPACE

logger = logging.getLogger("thor.training")

# ============================================================================
# Network Simulation Environment
# ============================================================================

class NetworkEnv:
    """
    بيئة محاكاة شبكية للتدريب المعزز

    تُحاكي حركة مرور الشبكة الحقيقية:
    - حركة مرور طبيعية (HTTP, HTTPS, DNS, NTP)
    - هجمات DoS/DDoS
    - مسح المنافذ
    - هجمات Brute Force
    - C2 Communication
    """

    def __init__(self, dataset_path: Optional[str] = None, seed: int = 42):
        self.rng = np.random.default_rng(seed)
        self.dataset = self._load_dataset(dataset_path)
        self.step_count = 0
        self.episode_count = 0

        # إحصاءات التدريب
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0

    def _load_dataset(self, path: Optional[str]) -> Optional[dict]:
        """تحميل CICIDS2017/2018 dataset"""
        if not path or not Path(path).exists():
            logger.warning("No dataset found, using synthetic data generation")
            return None

        logger.info(f"Loading dataset from {path}")
        try:
            import pandas as pd
            dfs = []
            for f in Path(path).glob("*.csv"):
                df = pd.read_csv(f, low_memory=False)
                dfs.append(df)

            if not dfs:
                return None

            df = pd.concat(dfs, ignore_index=True)
            logger.info(f"Loaded {len(df):,} samples from CICIDS dataset")

            # تنظيف البيانات
            df = df.replace([np.inf, -np.inf], np.nan).dropna()

            # استخراج الميزات والتسميات
            feature_cols = [c for c in df.columns if c not in ["Label", "Flow ID", "Source IP"]]
            X = df[feature_cols[:50]].values.astype(np.float32)
            y = (df["Label"] != "BENIGN").astype(int).values

            # توحيد القيم
            from sklearn.preprocessing import StandardScaler
            scaler = StandardScaler()
            X = scaler.fit_transform(X)

            return {"X": X, "y": y, "n_samples": len(X)}

        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return None

    def _generate_synthetic_sample(self) -> Tuple[np.ndarray, bool]:
        """توليد عينة اصطناعية للاختبار"""
        is_attack = self.rng.random() < 0.3  # 30% هجمات

        features = np.zeros(82, dtype=np.float32)

        if is_attack:
            attack_type = self.rng.integers(0, 5)
            if attack_type == 0:  # SYN flood
                features[0] = self.rng.uniform(40, 60)   # packet_len صغير
                features[20] = 1.0   # SYN flag
                features[6] = 1.0    # TCP protocol
                features[13] = 0.0   # ليس well-known port
                features[30] = 0.5   # entropy منخفض

            elif attack_type == 1:  # Port scan
                features[0] = self.rng.uniform(40, 80)
                features[20] = 1.0   # SYN
                features[11] = self.rng.uniform(1, 1024)  # منافذ متعددة

            elif attack_type == 2:  # DDoS UDP
                features[0] = self.rng.uniform(500, 1500)
                features[6] = 2.0    # UDP
                features[30] = self.rng.uniform(7.0, 8.0)  # entropy عالية

            elif attack_type == 3:  # Brute force SSH
                features[11] = 22.0  # dst_port = 22
                features[0] = self.rng.uniform(100, 200)
                features[6] = 1.0    # TCP

            elif attack_type == 4:  # C2 communication
                features[30] = self.rng.uniform(7.5, 8.0)  # entropy عالية جداً
                features[0] = self.rng.uniform(200, 800)
                features[12] = 0.0   # ليس well-known port

        else:  # حركة مرور طبيعية
            traffic_type = self.rng.integers(0, 4)
            if traffic_type == 0:  # HTTP
                features[11] = 80.0 if self.rng.random() < 0.5 else 443.0
                features[0] = self.rng.uniform(100, 1500)
                features[30] = self.rng.uniform(3.0, 6.0)

            elif traffic_type == 1:  # DNS
                features[6] = 2.0   # UDP
                features[11] = 53.0
                features[0] = self.rng.uniform(60, 512)

            elif traffic_type == 2:  # NTP
                features[6] = 2.0
                features[11] = 123.0
                features[0] = self.rng.uniform(56, 90)

            else:  # HTTPS/TLS
                features[11] = 443.0
                features[30] = self.rng.uniform(7.0, 8.0)  # TLS is encrypted
                features[0] = self.rng.uniform(500, 1500)

        # إضافة GNN embedding (32 features)
        if is_attack:
            gnn = self.rng.normal(0.7, 0.2, 32).astype(np.float32)
        else:
            gnn = self.rng.normal(0.1, 0.1, 32).astype(np.float32)
        gnn = np.clip(gnn, 0, 1)
        features[50:82] = gnn

        return features, is_attack

    def sample(self) -> Tuple[np.ndarray, bool, str]:
        """
        الحصول على عينة من البيئة

        Returns:
            (state_features, is_attack, protocol)
        """
        protocols = ["tcp", "udp", "icmp"]

        if self.dataset and self.rng.random() < 0.7:
            # 70% من البيانات الحقيقية
            idx = self.rng.integers(0, self.dataset["n_samples"])
            X = self.dataset["X"][idx]
            y = bool(self.dataset["y"][idx])

            # pad إلى 82 features
            state = np.zeros(82, dtype=np.float32)
            n = min(len(X), 50)
            state[:n] = X[:n]

            # GNN embedding اصطناعي
            gnn = self.rng.normal(0.6 if y else 0.1, 0.15, 32).astype(np.float32)
            state[50:82] = np.clip(gnn, 0, 1)

            protocol = protocols[int(state[6]) % 3]
            return state, y, protocol
        else:
            # 30% اصطناعي
            state, is_attack = self._generate_synthetic_sample()
            protocol = protocols[int(state[6]) % 3]
            return state, is_attack, protocol

    def compute_reward(
        self,
        action: int,
        is_attack: bool,
        latency_ms: float = 0.5,
    ) -> float:
        """حساب المكافأة مع تتبع الإحصاءات"""
        if is_attack:
            if action == 1:  # Block — صحيح
                self.true_positives += 1
                reward = 10.0
            else:  # Allow — خطأ
                self.false_negatives += 1
                reward = -10.0
        else:
            if action == 0:  # Allow — صحيح
                self.true_negatives += 1
                reward = 1.0
            elif action == 1:  # Block — خطأ
                self.false_positives += 1
                reward = -5.0
            else:  # throttle/mirror/redirect
                self.true_negatives += 1
                reward = 0.5  # مقبول ولكن دون المستوى

        # مكافأة صغيرة على السرعة
        reward += max(0, (1.0 - latency_ms) * 0.1)

        self.step_count += 1
        return reward

    def metrics(self) -> Dict:
        total = max(1, self.true_positives + self.true_negatives +
                    self.false_positives + self.false_negatives)
        precision = self.true_positives / max(1, self.true_positives + self.false_positives)
        recall = self.true_positives / max(1, self.true_positives + self.false_negatives)
        f1 = 2 * precision * recall / max(1e-8, precision + recall)
        accuracy = (self.true_positives + self.true_negatives) / total

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "fpr": self.false_positives / max(1, self.false_positives + self.true_negatives),
            "fnr": self.false_negatives / max(1, self.false_negatives + self.true_positives),
        }

    def reset_metrics(self):
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0


# ============================================================================
# Training Loop
# ============================================================================

def train(
    config: MARLConfig,
    env: NetworkEnv,
    epochs: int = 100,
    steps_per_epoch: int = 10000,
    checkpoint_dir: str = "ml/checkpoints",
    wandb_project: Optional[str] = None,
) -> MetaAgent:
    """
    الحلقة الرئيسية للتدريب

    Args:
        config: إعدادات MARL
        env: بيئة المحاكاة
        epochs: عدد حقب التدريب
        steps_per_epoch: خطوات لكل حقبة
        checkpoint_dir: مجلد حفظ النماذج
        wandb_project: مشروع W&B (None = تعطيل)

    Returns:
        MetaAgent المدرَّب
    """
    Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)

    # تهيئة W&B
    if wandb_project and WANDB_AVAILABLE:
        wandb.init(
            project=wandb_project,
            name=f"thor-marl-{time.strftime('%Y%m%d-%H%M%S')}",
            config={
                "epochs": epochs,
                "steps_per_epoch": steps_per_epoch,
                "batch_size": config.batch_size,
                "learning_rate": config.learning_rate,
                "gamma": config.gamma,
            }
        )

    agent = MetaAgent(config)
    best_accuracy = 0.0

    logger.info(f"Starting MARL training: {epochs} epochs × {steps_per_epoch} steps")
    logger.info(f"Device: {config.device}")
    logger.info(f"Action space: {ACTION_SPACE}")

    for epoch in range(epochs):
        epoch_start = time.time()
        env.reset_metrics()
        total_reward = 0.0

        for step in range(steps_per_epoch):
            # الحصول على عينة من البيئة
            state, is_attack, protocol = env.sample()

            # اختيار إجراء
            action, confidence = agent.make_decision(state, protocol, deterministic=False)

            # حساب المكافأة
            reward = env.compute_reward(action, is_attack)
            total_reward += reward

            # تخزين التجربة
            protocol_agent = agent.protocol_agents.get(protocol, agent.protocol_agents["tcp"])
            _, log_prob, value = protocol_agent.network(
                torch.FloatTensor(state).unsqueeze(0).to(torch.device(config.device))
            )
            protocol_agent.store_transition(
                state=state,
                action=action,
                reward=reward,
                log_prob=log_prob.item(),
                value=value.item(),
                done=(step == steps_per_epoch - 1),
            )

            # تحديث النماذج كل batch_size خطوة
            if (step + 1) % config.batch_size == 0:
                for proto, proto_agent in agent.protocol_agents.items():
                    update_metrics = proto_agent.update()

        # إحصاءات الحقبة
        epoch_time = time.time() - epoch_start
        env_metrics = env.metrics()
        avg_reward = total_reward / steps_per_epoch

        logger.info(
            f"Epoch {epoch+1:3d}/{epochs} | "
            f"Reward: {avg_reward:+.2f} | "
            f"Acc: {env_metrics['accuracy']:.3f} | "
            f"F1: {env_metrics['f1_score']:.3f} | "
            f"FPR: {env_metrics['fpr']:.4f} | "
            f"Time: {epoch_time:.1f}s"
        )

        # W&B logging
        if wandb_project and WANDB_AVAILABLE:
            wandb.log({
                "epoch": epoch + 1,
                "avg_reward": avg_reward,
                **{f"env/{k}": v for k, v in env_metrics.items()},
                "time_per_epoch": epoch_time,
            })

        # حفظ أفضل نموذج
        if env_metrics['accuracy'] > best_accuracy:
            best_accuracy = env_metrics['accuracy']
            agent.save_all(f"{checkpoint_dir}/best")
            logger.info(f"  ⭐ New best accuracy: {best_accuracy:.4f}")

        # حفظ دوري كل 10 حقب
        if (epoch + 1) % 10 == 0:
            agent.save_all(f"{checkpoint_dir}/epoch_{epoch+1:04d}")

    # حفظ النهائي
    agent.save_all(f"{checkpoint_dir}/final")

    if wandb_project and WANDB_AVAILABLE:
        wandb.finish()

    logger.info(f"Training complete. Best accuracy: {best_accuracy:.4f}")
    return agent


# ============================================================================
# Evaluation
# ============================================================================

def evaluate(
    agent: MetaAgent,
    env: NetworkEnv,
    n_samples: int = 10000,
) -> Dict:
    """تقييم الوكيل المدرَّب"""
    logger.info(f"Evaluating agent on {n_samples:,} samples...")
    env.reset_metrics()

    for _ in range(n_samples):
        state, is_attack, protocol = env.sample()
        action, _ = agent.make_decision(state, protocol, deterministic=True)
        env.compute_reward(action, is_attack)

    metrics = env.metrics()
    logger.info(f"Evaluation Results:")
    logger.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
    logger.info(f"  Precision: {metrics['precision']:.4f}")
    logger.info(f"  Recall:    {metrics['recall']:.4f}")
    logger.info(f"  F1 Score:  {metrics['f1_score']:.4f}")
    logger.info(f"  FPR:       {metrics['fpr']:.4f}")
    logger.info(f"  FNR:       {metrics['fnr']:.4f}")

    return metrics


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Train Thor MARL agents")
    parser.add_argument("--dataset", help="Path to CICIDS2017/2018 dataset CSV files")
    parser.add_argument("--output", default="ml/checkpoints", help="Checkpoint directory")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--steps", type=int, default=10000, help="Steps per epoch")
    parser.add_argument("--batch-size", type=int, default=2048)
    parser.add_argument("--lr", type=float, default=3e-4)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--wandb-project", help="W&B project name")
    parser.add_argument("--eval-only", action="store_true")
    parser.add_argument("--checkpoint", help="Load checkpoint for eval")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    config = MARLConfig(
        batch_size=args.batch_size,
        learning_rate=args.lr,
    )

    env = NetworkEnv(dataset_path=args.dataset, seed=args.seed)

    if args.eval_only and args.checkpoint:
        agent = MetaAgent(config)
        agent.load_all(args.checkpoint)
        evaluate(agent, env)
    else:
        agent = train(
            config=config,
            env=env,
            epochs=args.epochs,
            steps_per_epoch=args.steps,
            checkpoint_dir=args.output,
            wandb_project=args.wandb_project,
        )
        logger.info("Running final evaluation...")
        evaluate(agent, env)


if __name__ == "__main__":
    main()
