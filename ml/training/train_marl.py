"""
Thor Firewall — MARL Training Script — COMPLETE IMPLEMENTATION
سكريبت تدريب شامل لنظام التعلم المعزز المتعدد الوكلاء

يستخدم:
- مجموعة بيانات CICIDS2017/2018 للتدريب المُشرف الأولي
- بيئة شبكية مُحاكاة للتدريب المعزز (PPO)
- Weights & Biases لتتبع التجارب

الاستخدام:
    python -m ml.training.train_marl --epochs 100 --protocol tcp
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import random
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch

try:
    import wandb
    WANDB_AVAILABLE = True
except ImportError:
    WANDB_AVAILABLE = False

from ml.marl.agents import ACTION_SPACE, MARLConfig, MetaAgent

logger = logging.getLogger("thor.training")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

# ============================================================================
# Configuration
# ============================================================================

FEATURE_NAMES = [
    # Flow features (الميزات الأساسية للتدفق)
    "duration_s", "src_bytes", "dst_bytes", "src_packets", "dst_packets",
    "bytes_per_packet", "packets_per_second", "bytes_per_second",
    "avg_packet_size", "payload_entropy",
    # TCP flags
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count",
    "urg_count", "tcp_window_mean", "tcp_window_std", "retrans_count", "ooo_count",
    # Port info
    "src_port_privileged", "dst_port_privileged", "dst_port_well_known",
    "dst_port_80", "dst_port_443", "dst_port_22", "dst_port_53",
    "dst_port_3389", "dst_port_445", "dst_port_8080",
    # Inter-arrival time
    "iat_mean", "iat_std", "iat_min", "iat_max", "iat_cv",
    # Burst
    "burst_count", "burst_duration_mean", "burst_bytes_mean",
    # IP features
    "ttl", "dscp",
    # Time features
    "hour_of_day_sin", "hour_of_day_cos", "day_of_week_sin", "day_of_week_cos",
    # GNN embeddings (32 dim)
    *[f"gnn_emb_{i}" for i in range(32)],
]

assert len(FEATURE_NAMES) == 82, f"Expected 82 features, got {len(FEATURE_NAMES)}"


# ============================================================================
# Synthetic Network Environment
# ============================================================================

class NetworkEnv:
    """
    بيئة محاكاة شبكية للتدريب المعزز
    تولد تدفقات طبيعية وهجمات متنوعة
    """

    ATTACK_TYPES = [
        "normal",
        "syn_flood",
        "udp_flood",
        "port_scan",
        "brute_force",
        "dns_tunnel",
        "c2_beacon",
        "data_exfil",
        "slowloris",
    ]

    ATTACK_WEIGHTS = [0.70, 0.06, 0.04, 0.05, 0.04, 0.03, 0.03, 0.03, 0.02]

    def __init__(self, protocol: str = "tcp", seed: int = 42):
        self.protocol = protocol
        self.rng = np.random.RandomState(seed)

    def generate_flow(self) -> Tuple[np.ndarray, bool, str]:
        """
        توليد تدفق عشوائي

        Returns:
            (feature_vector [82], is_attack, attack_type)
        """
        attack_type = self.rng.choice(self.ATTACK_TYPES, p=self.ATTACK_WEIGHTS)
        is_attack = attack_type != "normal"
        features = self._gen_features(attack_type)
        return features, is_attack, attack_type

    def _gen_features(self, attack_type: str) -> np.ndarray:
        """توليد ميزات التدفق بناءً على نوع الهجوم"""
        f = np.zeros(82, dtype=np.float32)
        r = self.rng

        if attack_type == "normal":
            f[0]  = r.exponential(10.0)         # duration
            f[1]  = r.lognormal(10, 2)           # src_bytes
            f[2]  = r.lognormal(12, 2)           # dst_bytes
            f[3]  = r.randint(10, 10000)         # src_packets
            f[4]  = r.randint(10, 10000)         # dst_packets
            f[5]  = f[1] / max(f[3], 1)          # bytes/pkt
            f[6]  = f[3] / max(f[0], 0.001)     # pps
            f[9]  = r.uniform(3.0, 6.5)          # entropy (normal)
            f[11] = r.randint(0, 3)              # syn count
            f[12] = r.randint(10, 1000)          # ack count

        elif attack_type == "syn_flood":
            f[0]  = r.uniform(0.01, 1.0)
            f[1]  = r.uniform(100, 500)          # small bytes
            f[2]  = 0                            # no response
            f[3]  = r.randint(1000, 100_000)    # many packets
            f[4]  = 0
            f[6]  = f[3] / max(f[0], 0.001)    # very high pps
            f[9]  = r.uniform(2.0, 3.5)          # low entropy (SYN only)
            f[11] = f[3]                          # all SYN, no ACK
            f[12] = 0

        elif attack_type == "port_scan":
            f[0]  = r.uniform(1.0, 60.0)
            f[3]  = r.randint(50, 5000)
            f[4]  = r.randint(0, 100)            # mostly no response
            f[6]  = f[3] / max(f[0], 0.001)
            f[9]  = r.uniform(1.0, 3.0)
            f[11] = f[3]
            f[13] = f[4] * 0.3                   # RST from closed ports

        elif attack_type == "dns_tunnel":
            f[0]  = r.exponential(30.0)
            f[1]  = r.lognormal(8, 1)
            f[9]  = r.uniform(7.5, 8.0)          # HIGH entropy (encoded data)
            f[26] = 1.0                            # dst_port_53
            f[6]  = r.uniform(1.0, 20.0)

        elif attack_type == "c2_beacon":
            f[0]  = r.exponential(300.0)          # long duration
            # Very regular intervals (jitter < 1%)
            base_iat = r.choice([30.0, 60.0, 120.0])
            f[31] = base_iat
            f[32] = base_iat * 0.005              # very low std
            f[9]  = r.uniform(7.0, 8.0)           # encrypted traffic
            f[6]  = r.uniform(0.01, 0.1)           # low pps

        elif attack_type == "brute_force":
            f[0]  = r.exponential(60.0)
            f[3]  = r.randint(500, 5000)
            f[25] = 1.0                            # dst_port_22 (SSH)
            f[11] = f[3]                           # many SYN
            f[12] = f[3] * 0.3
            f[6]  = f[3] / max(f[0], 0.001)

        elif attack_type == "data_exfil":
            f[0]  = r.exponential(120.0)
            f[1]  = r.lognormal(15, 1)            # HUGE src_bytes
            f[2]  = r.lognormal(6, 1)
            f[9]  = r.uniform(6.0, 8.0)
            f[6]  = r.uniform(100, 1000)

        elif attack_type == "slowloris":
            f[0]  = r.uniform(60.0, 3600.0)       # very long connections
            f[3]  = r.randint(5, 50)              # few packets
            f[4]  = r.randint(5, 50)
            f[6]  = 0.01
            f[30] = r.uniform(20.0, 60.0)         # high IAT mean
            f[32] = 5.0                            # IAT min

        elif attack_type == "udp_flood":
            f[0]  = r.uniform(0.01, 5.0)
            f[1]  = r.uniform(1e6, 1e9)
            f[3]  = r.randint(10000, 1_000_000)
            f[6]  = f[3] / max(f[0], 0.001)

        # Normalize + add noise
        f[:50] = np.clip(f[:50] / (np.abs(f[:50]) + 1e-6 + 1000), -1, 1)

        # Add random GNN embeddings (in real training: from GNN model)
        f[50:] = r.randn(32).astype(np.float32) * 0.1

        # Time features
        h = r.randint(0, 24)
        d = r.randint(0, 7)
        f[42] = np.sin(2 * np.pi * h / 24)
        f[43] = np.cos(2 * np.pi * h / 24)
        f[44] = np.sin(2 * np.pi * d / 7)
        f[45] = np.cos(2 * np.pi * d / 7)

        return f

    def compute_reward(
        self,
        action: int,
        is_attack: bool,
        attack_type: str,
        latency_us: float,
    ) -> float:
        """
        حساب المكافأة بناءً على نتيجة القرار
        """
        action_name = ACTION_SPACE.get(action, "allow")
        blocked = action_name == "block"

        if is_attack:
            if blocked:
                r = 10.0
                # مكافأة إضافية للهجمات الخطيرة
                if attack_type in ("syn_flood", "c2_beacon", "data_exfil"):
                    r += 2.0
            else:
                r = -10.0
                if attack_type == "data_exfil":
                    r -= 5.0  # عقوبة مضاعفة لتسريب البيانات
        else:
            if not blocked:
                r = 1.0
            else:
                r = -5.0  # false positive

        # مكافأة الأداء
        if latency_us < 100:
            r += 0.1
        elif latency_us > 1000:
            r -= 0.05

        return r


# ============================================================================
# CICIDS Dataset Loader
# ============================================================================

class CICIDSDataset:
    """
    محمّل مجموعة بيانات CICIDS2017/2018
    تحميل من ملفات CSV
    """

    LABEL_MAP = {
        "BENIGN":            (False, "normal"),
        "DoS Hulk":          (True,  "syn_flood"),
        "PortScan":          (True,  "port_scan"),
        "DDoS":              (True,  "syn_flood"),
        "DoS GoldenEye":     (True,  "slowloris"),
        "FTP-Patator":       (True,  "brute_force"),
        "SSH-Patator":       (True,  "brute_force"),
        "DoS slowloris":     (True,  "slowloris"),
        "DoS Slowhttptest":  (True,  "slowloris"),
        "Bot":               (True,  "c2_beacon"),
        "Web Attack":        (True,  "brute_force"),
        "Infiltration":      (True,  "data_exfil"),
    }

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.samples: List[Tuple[np.ndarray, bool, str]] = []

    def load(self, max_samples: int = 100_000) -> int:
        """تحميل مجموعة البيانات من ملفات CSV"""
        csv_files = list(self.data_dir.glob("*.csv"))
        if not csv_files:
            logger.warning(f"No CSV files found in {self.data_dir}")
            return 0

        count = 0
        for csv_file in csv_files:
            try:
                with open(csv_file, "r", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if count >= max_samples:
                            break

                        label = row.get("Label", row.get(" Label", "BENIGN")).strip()
                        is_attack, attack_type = self.LABEL_MAP.get(
                            label, (False, "normal")
                        )

                        features = self._row_to_features(row)
                        if features is not None:
                            self.samples.append((features, is_attack, attack_type))
                            count += 1

            except Exception as e:
                logger.warning(f"Failed to load {csv_file}: {e}")

        logger.info(f"Loaded {count} samples from CICIDS dataset")
        return count

    def _row_to_features(self, row: Dict) -> Optional[np.ndarray]:
        """تحويل صف CSV إلى متجه ميزات"""
        try:
            f = np.zeros(82, dtype=np.float32)
            get = lambda k, default=0.0: float(row.get(k, row.get(f" {k}", default)) or default)

            f[0]  = get("Flow Duration") / 1e6     # microseconds → seconds
            f[1]  = get("Total Fwd Packets")
            f[2]  = get("Total Backward Packets")
            f[3]  = get("Fwd Packet Length Mean")
            f[4]  = get("Bwd Packet Length Mean")
            f[5]  = get("Flow Bytes/s") / 1e6
            f[6]  = get("Flow Packets/s")
            f[9]  = get("Average Packet Size") / 1000
            f[11] = get("SYN Flag Count")
            f[12] = get("ACK Flag Count")
            f[13] = get("FIN Flag Count")
            f[14] = get("RST Flag Count")
            f[15] = get("PSH Flag Count")
            f[30] = get("Flow IAT Mean") / 1e6
            f[31] = get("Flow IAT Std")  / 1e6
            f[32] = get("Flow IAT Min")  / 1e6
            f[33] = get("Flow IAT Max")  / 1e6

            # Normalize
            f = np.clip(f, -10, 10)
            f = f / (np.abs(f).max() + 1e-8)

            # GNN embedding = zeros (not available in offline dataset)
            f[50:] = 0.0

            if np.isnan(f).any() or np.isinf(f).any():
                return None

            return f
        except Exception:
            return None

    def __len__(self):
        return len(self.samples)

    def __iter__(self):
        return iter(self.samples)


# ============================================================================
# Training Loop
# ============================================================================

def train(
    protocol:     str   = "tcp",
    epochs:       int   = 100,
    steps_per_epoch: int = 10_000,
    output_dir:   str   = "ml/checkpoints",
    dataset_dir:  Optional[str] = None,
    wandb_project: Optional[str] = None,
    seed:         int   = 42,
) -> MetaAgent:
    """
    حلقة التدريب الرئيسية للـ MARL

    Args:
        protocol:   البروتوكول المستهدف (tcp/udp/icmp)
        epochs:     عدد حقب التدريب
        steps_per_epoch: خطوات لكل حقبة
        output_dir: مجلد حفظ النماذج
        dataset_dir: مسار مجموعة بيانات CICIDS (اختياري)
        wandb_project: اسم مشروع WandB (اختياري)
        seed:       بذرة العشوائية
    """
    torch.manual_seed(seed)
    np.random.seed(seed)
    random.seed(seed)

    config = MARLConfig(protocols=[protocol] if protocol != "all" else ["tcp", "udp", "icmp"])
    agent  = MetaAgent(config)
    env    = NetworkEnv(protocol=protocol, seed=seed)
    proto_agent = agent.protocol_agents.get(protocol, list(agent.protocol_agents.values())[0])

    os.makedirs(output_dir, exist_ok=True)

    # تحميل مجموعة البيانات إذا متوفرة
    dataset = None
    if dataset_dir and Path(dataset_dir).exists():
        dataset = CICIDSDataset(dataset_dir)
        n = dataset.load()
        if n > 0:
            logger.info(f"Using CICIDS dataset: {n} samples")

    # إعداد WandB
    if wandb_project and WANDB_AVAILABLE:
        wandb.init(
            project  = wandb_project,
            name     = f"thor-marl-{protocol}-{int(time.time())}",
            config   = {
                "protocol":        protocol,
                "epochs":          epochs,
                "steps_per_epoch": steps_per_epoch,
                "state_dim":       config.state_dim,
                "action_dim":      config.action_dim,
                "hidden_dim":      config.hidden_dim,
                "learning_rate":   config.learning_rate,
                "gamma":           config.gamma,
            },
        )

    best_accuracy = 0.0
    logger.info(f"Starting MARL training: protocol={protocol}, epochs={epochs}")

    for epoch in range(epochs):
        # إحصاءات الحقبة
        epoch_rewards:      List[float] = []
        epoch_correct:      int = 0
        epoch_total:        int = 0
        epoch_fp:           int = 0
        epoch_fn:           int = 0
        epoch_tp:           int = 0

        # استخدام مجموعة البيانات أو المحاكاة
        data_source: List[Tuple[np.ndarray, bool, str]]
        if dataset and len(dataset) > 0:
            # عيّنة عشوائية من مجموعة البيانات
            indices = np.random.choice(len(dataset), size=min(steps_per_epoch, len(dataset)), replace=True)
            data_source = [dataset.samples[i] for i in indices]
        else:
            # توليد مصطنع
            data_source = [env.generate_flow() for _ in range(steps_per_epoch)]

        for state, is_attack, attack_type in data_source:
            start_us = time.perf_counter() * 1e6

            # اختيار الإجراء
            action, log_prob, value = proto_agent.select_action(state)

            latency_us = time.perf_counter() * 1e6 - start_us

            # حساب المكافأة
            reward = env.compute_reward(action, is_attack, attack_type, latency_us)

            # تتبع الدقة
            action_name = ACTION_SPACE.get(action, "allow")
            blocked = action_name == "block"

            if is_attack and blocked:   epoch_tp += 1; epoch_correct += 1
            elif not is_attack and not blocked: epoch_correct += 1
            elif not is_attack and blocked: epoch_fp += 1
            else: epoch_fn += 1
            epoch_total += 1

            # تخزين التجربة
            proto_agent.store_transition(
                state    = state,
                action   = action,
                reward   = reward,
                log_prob = log_prob,
                value    = value,
                done     = False,
            )
            epoch_rewards.append(reward)

        # تحديث الشبكة
        metrics = proto_agent.update()

        # حساب المقاييس
        accuracy    = epoch_correct / max(epoch_total, 1)
        avg_reward  = np.mean(epoch_rewards) if epoch_rewards else 0.0
        fp_rate     = epoch_fp  / max(epoch_total, 1)
        fn_rate     = epoch_fn  / max(epoch_total, 1)

        proto_agent.avg_reward = avg_reward

        logger.info(
            f"Epoch {epoch+1}/{epochs} | "
            f"acc={accuracy:.4f} | reward={avg_reward:.3f} | "
            f"FP={fp_rate:.4f} FN={fn_rate:.4f} | "
            f"steps={proto_agent.total_steps}"
        )

        # حفظ النموذج الأفضل
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            agent.save_all(f"{output_dir}/best")
            logger.info(f"New best model saved (accuracy={accuracy:.4f})")

        # حفظ دوري كل 10 حقب
        if (epoch + 1) % 10 == 0:
            agent.save_all(f"{output_dir}/epoch_{epoch+1}")

        # إرسال إلى WandB
        if wandb_project and WANDB_AVAILABLE:
            log_dict = {
                "epoch":       epoch + 1,
                "accuracy":    accuracy,
                "avg_reward":  avg_reward,
                "fp_rate":     fp_rate,
                "fn_rate":     fn_rate,
                "total_steps": proto_agent.total_steps,
            }
            if metrics:
                log_dict.update({f"loss/{k}": v for k, v in metrics.items()})
            wandb.log(log_dict)

    # حفظ النموذج النهائي
    agent.save_all(f"{output_dir}/final")
    logger.info(f"Training complete. Best accuracy: {best_accuracy:.4f}")

    if wandb_project and WANDB_AVAILABLE:
        wandb.finish()

    return agent


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Train Thor MARL agents")
    parser.add_argument("--protocol",     default="tcp",   help="tcp|udp|icmp|all")
    parser.add_argument("--epochs",       type=int, default=100)
    parser.add_argument("--steps",        type=int, default=10_000, dest="steps_per_epoch")
    parser.add_argument("--output",       default="ml/checkpoints")
    parser.add_argument("--dataset",      default=None,    help="Path to CICIDS dataset dir")
    parser.add_argument("--wandb",        default=None,    help="WandB project name")
    parser.add_argument("--seed",         type=int, default=42)
    args = parser.parse_args()

    train(
        protocol        = args.protocol,
        epochs          = args.epochs,
        steps_per_epoch = args.steps_per_epoch,
        output_dir      = args.output,
        dataset_dir     = args.dataset,
        wandb_project   = args.wandb,
        seed            = args.seed,
    )


if __name__ == "__main__":
    main()
