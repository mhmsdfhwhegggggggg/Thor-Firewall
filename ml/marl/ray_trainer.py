"""
Thor Firewall — Ray RLlib MARL Trainer
======================================
Multi-Agent Reinforcement Learning لتدريب وكلاء الشبكة الموزعة.

مستوحى من: https://github.com/ray-project/ray (Ray RLlib)
مستوحى من: https://github.com/DLR-RM/stable-baselines3 (للمقارنة والbaseline)

المعمارية:
  - 3 وكلاء متخصصة: TCPAgent + UDPAgent + ICMPAgent
  - MetaCoordinator: يُنسق القرارات المتعارضة
  - خوارزمية: MAPPO (Multi-Agent PPO)
  - التدريب: Ray Tune للـ hyperparameter search
  - التتبع: MLflow لكل experiment
"""

from __future__ import annotations

import os
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

import numpy as np
import mlflow
import mlflow.pytorch

# Ray RLlib imports
import ray
from ray import tune
from ray.rllib.algorithms.ppo import PPOConfig
from ray.rllib.env.multi_agent_env import MultiAgentEnv
from ray.rllib.policy.policy import PolicySpec
from ray.tune.registry import register_env
from ray.rllib.utils.typing import MultiAgentDict, PolicyID

# PyTorch
import torch
import torch.nn as nn
from torch import Tensor

logger = logging.getLogger("thor.ml.ray_trainer")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_DIM    = 50    # PacketParser يُنتج 50 feature لكل تدفق
GNN_EMBED_DIM  = 32    # GraphSAGE embedding من network topology
OBS_DIM        = FEATURE_DIM + GNN_EMBED_DIM  # = 82 total
ACTION_SPACE   = 5     # allow / block / throttle / mirror / redirect_honeypot

PROTOCOLS = ["tcp", "udp", "icmp"]

# نظام المكافآت — معايير Thor
REWARD_TRUE_POSITIVE  = +10.0   # صواب: اكتشاف هجوم حقيقي
REWARD_TRUE_NEGATIVE  = +1.0    # صواب: سماح بحركة شرعية
REWARD_FALSE_POSITIVE = -5.0    # خطأ: حجب حركة شرعية
REWARD_FALSE_NEGATIVE = -10.0   # خطأ: إغفال هجوم حقيقي
REWARD_LATENCY_BONUS  = +0.5    # مكافأة السرعة (< 100µs)


# ─────────────────────────────────────────────────────────────────────────────
# Thor Network Environment — MultiAgentEnv
# ─────────────────────────────────────────────────────────────────────────────

class ThorNetworkEnv(MultiAgentEnv):
    """
    بيئة الشبكة متعددة الوكلاء.
    
    كل وكيل يُعالج بروتوكولاً مختلفاً (TCP/UDP/ICMP).
    يتشاركون في المكافأة الإجمالية (cooperative MARL).
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__()
        config = config or {}

        import gymnasium as gym

        self._agent_ids = set(PROTOCOLS)
        self.observation_space = gym.spaces.Box(
            low=-np.inf, high=np.inf, shape=(OBS_DIM,), dtype=np.float32
        )
        self.action_space = gym.spaces.Discrete(ACTION_SPACE)

        # تكوين البيئة
        self.max_steps        = config.get("max_steps", 10_000)
        self.batch_size       = config.get("batch_size", 256)
        self.attack_rate      = config.get("attack_rate", 0.15)  # 15% هجمات
        self.scenario         = config.get("scenario", "mixed")  # mixed/ddos/apt

        self._step_count = 0
        self._metrics: Dict[str, float] = {p: 0.0 for p in PROTOCOLS}

    # ── Gym Interface ─────────────────────────────────────────────────────────

    def reset(self, *, seed=None, options=None):
        self._step_count = 0
        obs = {agent_id: self._generate_obs(agent_id) for agent_id in PROTOCOLS}
        infos = {agent_id: {} for agent_id in PROTOCOLS}
        return obs, infos

    def step(self, action_dict: MultiAgentDict):
        self._step_count += 1
        observations, rewards, terminateds, truncateds, infos = {}, {}, {}, {}, {}

        terminateds["__all__"] = self._step_count >= self.max_steps
        truncateds["__all__"] = False

        for agent_id, action in action_dict.items():
            obs     = self._generate_obs(agent_id)
            reward  = self._compute_reward(agent_id, action)
            done    = self._step_count >= self.max_steps

            observations[agent_id] = obs
            rewards[agent_id]      = reward
            terminateds[agent_id]  = done
            truncateds[agent_id]   = False
            infos[agent_id]        = {
                "action_name": ["allow","block","throttle","mirror","redirect"][action],
                "step": self._step_count,
            }

        return observations, rewards, terminateds, truncateds, infos

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _generate_obs(self, agent_id: str) -> np.ndarray:
        """
        يُنتج observation من 82 feature:
          - 50 من PacketParser (SIMD-accelerated في Rust)
          - 32 من GNN embedding (GraphSAGE topology analysis)
        """
        # في الإنتاج: يأتي من Rust PacketParser عبر shared memory/Redis
        # هنا: محاكاة للتدريب
        features   = np.random.randn(FEATURE_DIM).astype(np.float32)
        gnn_embed  = np.random.randn(GNN_EMBED_DIM).astype(np.float32)
        return np.concatenate([features, gnn_embed])

    def _compute_reward(self, agent_id: str, action: int) -> float:
        """
        حساب المكافأة بناءً على صحة القرار.
        في الإنتاج: يُحسب من feedback loop (SOC analyst corrections).
        """
        is_attack = np.random.random() < self.attack_rate
        blocked   = action == 1  # action=1 → BLOCK

        if is_attack and blocked:     return REWARD_TRUE_POSITIVE
        if not is_attack and blocked: return REWARD_FALSE_POSITIVE
        if is_attack and not blocked: return REWARD_FALSE_NEGATIVE
        return REWARD_TRUE_NEGATIVE


# ─────────────────────────────────────────────────────────────────────────────
# MAPPO Configuration — Ray RLlib
# ─────────────────────────────────────────────────────────────────────────────

def build_mappo_config(
    num_workers: int = 4,
    num_gpus: float = 0,
    mlflow_uri: str = "http://localhost:5000",
) -> PPOConfig:
    """
    إعداد Multi-Agent PPO باستخدام Ray RLlib.
    
    كل بروتوكول له policy مستقلة (parameter sharing اختياري).
    """
    register_env("thor_network", lambda cfg: ThorNetworkEnv(cfg))

    policies: Dict[PolicyID, PolicySpec] = {
        "tcp_policy":  PolicySpec(),
        "udp_policy":  PolicySpec(),
        "icmp_policy": PolicySpec(),
    }

    def policy_mapping_fn(agent_id: str, *args, **kwargs) -> PolicyID:
        return f"{agent_id}_policy"

    config = (
        PPOConfig()
        .environment(
            env="thor_network",
            env_config={
                "max_steps": 10_000,
                "batch_size": 256,
                "attack_rate": 0.15,
                "scenario": "mixed",
            },
        )
        .multi_agent(
            policies=policies,
            policy_mapping_fn=policy_mapping_fn,
            policies_to_train=list(policies.keys()),
        )
        .training(
            gamma=0.99,
            lambda_=0.95,
            lr=3e-4,
            train_batch_size=4096,
            sgd_minibatch_size=512,
            num_sgd_iter=10,
            clip_param=0.2,
            vf_clip_param=10.0,
            entropy_coeff=0.01,
            vf_loss_coeff=0.5,
            grad_clip=0.5,
            model={
                "fcnet_hiddens": [512, 512, 256],
                "fcnet_activation": "relu",
                "use_lstm": False,
                "use_attention": True,
                "attention_num_heads": 4,
                "attention_head_dim": 32,
                "max_seq_len": 50,
                "attention_memory_inference": 50,
                "attention_memory_training": 50,
            },
        )
        .rollouts(
            num_rollout_workers=num_workers,
            rollout_fragment_length=256,
        )
        .resources(num_gpus=num_gpus)
        .debugging(
            log_level="WARN",
            logger_config={
                "type": "ray.tune.logger.MLflowLogger",
                "experiment_name": "thor-marl-mappo",
                "tracking_uri": mlflow_uri,
            },
        )
        .evaluation(
            evaluation_interval=10,
            evaluation_duration=10,
            evaluation_duration_unit="episodes",
        )
    )

    return config


# ─────────────────────────────────────────────────────────────────────────────
# Training Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

def train(
    num_iterations: int = 500,
    checkpoint_dir: str = "/models/ray_checkpoints",
    mlflow_uri: str = "http://mlflow:5000",
    num_workers: int = 4,
    num_gpus: float = 0,
    resume: bool = False,
) -> str:
    """
    يُشغّل تدريب MAPPO الكامل باستخدام Ray + MLflow.
    
    Returns:
        str: مسار best checkpoint
    """
    logger.info("🚀 بدء تدريب Thor MARL (Ray RLlib MAPPO)")

    # تهيئة Ray
    if not ray.is_initialized():
        ray.init(
            ignore_reinit_error=True,
            log_to_driver=False,
            num_cpus=os.cpu_count(),
            num_gpus=num_gpus,
        )

    # MLflow tracking
    mlflow.set_tracking_uri(mlflow_uri)
    mlflow.set_experiment("thor-marl-mappo")

    config = build_mappo_config(
        num_workers=num_workers,
        num_gpus=num_gpus,
        mlflow_uri=mlflow_uri,
    )

    with mlflow.start_run(run_name="mappo-training") as run:
        mlflow.log_params({
            "algorithm": "MAPPO",
            "obs_dim": OBS_DIM,
            "action_space": ACTION_SPACE,
            "num_workers": num_workers,
            "num_iterations": num_iterations,
            "attack_rate": 0.15,
            "reward_true_positive": REWARD_TRUE_POSITIVE,
            "reward_false_positive": REWARD_FALSE_POSITIVE,
            "reward_false_negative": REWARD_FALSE_NEGATIVE,
        })

        algo = config.build()

        best_reward = float("-inf")
        best_checkpoint = None

        for i in range(num_iterations):
            result = algo.train()

            # Log metrics
            reward_mean = result.get("episode_reward_mean", 0.0)
            reward_max  = result.get("episode_reward_max", 0.0)
            len_mean    = result.get("episode_len_mean", 0.0)

            mlflow.log_metrics({
                "episode_reward_mean": reward_mean,
                "episode_reward_max": reward_max,
                "episode_len_mean": len_mean,
                "timesteps_total": result.get("timesteps_total", 0),
            }, step=i)

            if reward_mean > best_reward:
                best_reward = reward_mean
                checkpoint = algo.save(checkpoint_dir)
                best_checkpoint = checkpoint.checkpoint.path
                logger.info(f"📈 تحسين جديد [{i}] reward={reward_mean:.3f} checkpoint={best_checkpoint}")

            if (i + 1) % 50 == 0:
                logger.info(f"✅ Iteration {i+1}/{num_iterations} | reward={reward_mean:.3f}")

        mlflow.log_metric("best_episode_reward", best_reward)
        if best_checkpoint:
            mlflow.log_artifact(best_checkpoint, "best_checkpoint")

        logger.info(f"🎯 التدريب اكتمل. Best checkpoint: {best_checkpoint}")
        return best_checkpoint or ""


# ─────────────────────────────────────────────────────────────────────────────
# Hyperparameter Search — Ray Tune
# ─────────────────────────────────────────────────────────────────────────────

def hyperparameter_search(
    num_samples: int = 20,
    max_concurrent: int = 4,
    mlflow_uri: str = "http://mlflow:5000",
) -> None:
    """
    يُشغّل بحث تلقائي عن أفضل hyperparameters باستخدام Ray Tune + Optuna.
    """
    from ray.tune.search.optuna import OptunaSearch
    from ray.tune.schedulers import ASHAScheduler

    register_env("thor_network", lambda cfg: ThorNetworkEnv(cfg))

    def train_fn(config: Dict):
        algo_config = build_mappo_config(num_workers=2, mlflow_uri=mlflow_uri)
        algo_config.training(
            lr=config["lr"],
            gamma=config["gamma"],
            lambda_=config["lambda"],
            clip_param=config["clip_param"],
            entropy_coeff=config["entropy_coeff"],
        )
        algo = algo_config.build()
        for _ in range(100):
            result = algo.train()
            tune.report(episode_reward_mean=result.get("episode_reward_mean", 0.0))

    search_space = {
        "lr":            tune.loguniform(1e-5, 1e-3),
        "gamma":         tune.uniform(0.95, 0.999),
        "lambda":        tune.uniform(0.9, 0.999),
        "clip_param":    tune.uniform(0.1, 0.3),
        "entropy_coeff": tune.loguniform(1e-4, 0.05),
    }

    tune.run(
        train_fn,
        config=search_space,
        num_samples=num_samples,
        search_alg=OptunaSearch(metric="episode_reward_mean", mode="max"),
        scheduler=ASHAScheduler(
            metric="episode_reward_mean",
            mode="max",
            max_t=100,
            grace_period=10,
        ),
        max_concurrent_trials=max_concurrent,
        name="thor-hparam-search",
        local_dir="/models/tune_results",
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Thor MARL Trainer")
    parser.add_argument("--iterations",   type=int, default=500)
    parser.add_argument("--workers",      type=int, default=4)
    parser.add_argument("--gpus",         type=float, default=0.0)
    parser.add_argument("--mlflow-uri",   default="http://mlflow:5000")
    parser.add_argument("--checkpoint-dir", default="/models/ray_checkpoints")
    parser.add_argument("--hparam-search", action="store_true")
    args = parser.parse_args()

    if args.hparam_search:
        hyperparameter_search(mlflow_uri=args.mlflow_uri)
    else:
        train(
            num_iterations=args.iterations,
            num_workers=args.workers,
            num_gpus=args.gpus,
            mlflow_uri=args.mlflow_uri,
            checkpoint_dir=args.checkpoint_dir,
        )
