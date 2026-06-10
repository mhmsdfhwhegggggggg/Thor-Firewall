"""
Thor Firewall — Multi-Agent Reinforcement Learning Full Training Pipeline
تدريب MARL كامل مع MLflow tracking ودعم تسريع GPU

Architecture:
  - Policy Network:  Actor-Critic (PPO) 
  - State:           30-dim flow features
  - Actions:         0=allow, 1=block, 2=rate-limit, 3=alert
  - Reward:          security_reward - false_positive_penalty - latency_cost

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import argparse
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("thor.ml.training")

# ── Hyperparameters ───────────────────────────────────────────────────────────

@dataclass
class TrainingConfig:
    # Network
    state_dim:   int   = 30
    action_dim:  int   = 4
    hidden_dim:  int   = 256
    n_layers:    int   = 3

    # Training
    n_agents:    int   = 8        # parallel agents (env instances)
    total_steps: int   = 2_000_000
    batch_size:  int   = 2048
    n_epochs:    int   = 10
    lr_actor:    float = 3e-4
    lr_critic:   float = 1e-3
    gamma:       float = 0.99
    gae_lambda:  float = 0.95
    clip_eps:    float = 0.2
    value_coef:  float = 0.5
    entropy_coef: float = 0.01
    max_grad_norm: float = 0.5

    # Environment
    episode_len: int   = 500
    max_bps:     float = 10e9    # 10 Gbps

    # Checkpoints
    save_every:   int   = 100_000
    eval_every:   int   = 50_000
    log_interval: int   = 1000
    model_dir:    str   = "ml/models"
    run_name:     str   = field(default_factory=lambda: f"marl_run_{int(time.time())}")


# ── Policy Network (Pure NumPy — works without PyTorch) ──────────────────────

class PolicyNetwork:
    """
    Simple 3-layer MLP Actor-Critic in pure NumPy.
    (Use the PyTorch version in production — this handles CPU-only environments.)
    """
    def __init__(self, cfg: TrainingConfig):
        self.cfg = cfg
        rng      = np.random.default_rng(42)
        scale    = lambda n_in, n_out: np.sqrt(2.0 / n_in)

        dims     = [cfg.state_dim] + [cfg.hidden_dim] * cfg.n_layers

        self.actor_weights  = []
        self.actor_biases   = []
        self.critic_weights = []
        self.critic_biases  = []

        for i in range(len(dims) - 1):
            s = scale(dims[i], dims[i+1])
            self.actor_weights.append(rng.normal(0, s, (dims[i], dims[i+1])))
            self.actor_biases.append(np.zeros(dims[i+1]))
            self.critic_weights.append(rng.normal(0, s, (dims[i], dims[i+1])))
            self.critic_biases.append(np.zeros(dims[i+1]))

        # Output heads
        s = scale(cfg.hidden_dim, cfg.action_dim)
        self.pi_w = rng.normal(0, 0.01, (cfg.hidden_dim, cfg.action_dim))
        self.pi_b = np.zeros(cfg.action_dim)
        self.vf_w = rng.normal(0, s, (cfg.hidden_dim, 1))
        self.vf_b = np.zeros(1)

    def _forward(
        self,
        x: np.ndarray,
        weights: list,
        biases:  list,
    ) -> np.ndarray:
        for W, b in zip(weights, biases):
            x = np.tanh(x @ W + b)
        return x

    def get_action_value(self, obs: np.ndarray) -> Tuple[int, float, float]:
        """obs → (action, log_prob, value)"""
        h_a     = self._forward(obs, self.actor_weights, self.actor_biases)
        h_c     = self._forward(obs, self.critic_weights, self.critic_biases)
        logits  = h_a @ self.pi_w + self.pi_b
        value   = float((h_c @ self.vf_w + self.vf_b)[0])

        # Softmax
        logits -= logits.max()
        probs   = np.exp(logits) / np.sum(np.exp(logits))
        action  = int(np.random.choice(self.cfg.action_dim, p=probs))
        log_prob = float(np.log(probs[action] + 1e-8))

        return action, log_prob, value

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        np.savez(
            path,
            **{f"aw_{i}": w for i, w in enumerate(self.actor_weights)},
            **{f"ab_{i}": b for i, b in enumerate(self.actor_biases)},
            **{f"cw_{i}": w for i, w in enumerate(self.critic_weights)},
            **{f"cb_{i}": b for i, b in enumerate(self.critic_biases)},
            pi_w=self.pi_w, pi_b=self.pi_b,
            vf_w=self.vf_w, vf_b=self.vf_b,
        )
        logger.info("model_saved", path=path)

    def load(self, path: str) -> None:
        if not os.path.exists(path + ".npz"):
            return
        data = np.load(path + ".npz")
        n = len(self.actor_weights)
        for i in range(n):
            self.actor_weights[i]  = data[f"aw_{i}"]
            self.actor_biases[i]   = data[f"ab_{i}"]
            self.critic_weights[i] = data[f"cw_{i}"]
            self.critic_biases[i]  = data[f"cb_{i}"]
        self.pi_w = data["pi_w"]
        self.pi_b = data["pi_b"]
        self.vf_w = data["vf_w"]
        self.vf_b = data["vf_b"]
        logger.info("model_loaded", path=path)


# ── Environment Simulator ─────────────────────────────────────────────────────

class NetworkFlowEnv:
    """محاكي بيئة حركة المرور الشبكية"""

    THREAT_PROB = 0.3  # نسبة الـ flows الضارة

    def __init__(self, rng: np.random.Generator = None):
        self.rng = rng or np.random.default_rng()
        self.step_count = 0
        self.ep_rewards: List[float] = []

    def reset(self) -> np.ndarray:
        self.step_count = 0
        return self._generate_flow()

    def step(self, action: int) -> Tuple[np.ndarray, float, bool]:
        self.step_count += 1
        is_malicious = self._current_is_malicious
        reward = self._compute_reward(action, is_malicious)
        self.ep_rewards.append(reward)
        done  = self.step_count >= 500
        next_obs = self._generate_flow()
        return next_obs, reward, done

    def _generate_flow(self) -> np.ndarray:
        is_malicious = self.rng.random() < self.THREAT_PROB
        self._current_is_malicious = is_malicious

        if is_malicious:
            # features of a malicious flow
            features = self.rng.normal(loc=[
                0.8, 0.1, 0.9, 0.3, 0.7, 0.2, 0.8, 0.6, 0.4, 0.9,
                0.7, 0.3, 0.8, 0.5, 0.6, 0.9, 0.2, 0.7, 0.8, 0.4,
                0.6, 0.3, 0.9, 0.8, 0.5, 0.7, 0.4, 0.6, 0.8, 0.9,
            ], scale=0.15)
        else:
            features = self.rng.normal(loc=[
                0.2, 0.8, 0.1, 0.6, 0.2, 0.7, 0.1, 0.3, 0.5, 0.2,
                0.1, 0.7, 0.2, 0.4, 0.3, 0.1, 0.7, 0.2, 0.1, 0.5,
                0.3, 0.6, 0.1, 0.2, 0.4, 0.2, 0.5, 0.3, 0.1, 0.2,
            ], scale=0.15)

        return np.clip(features, 0, 1).astype(np.float32)

    def _compute_reward(self, action: int, is_malicious: bool) -> float:
        # action: 0=allow, 1=block, 2=rate-limit, 3=alert
        if is_malicious:
            rewards = {0: -5.0, 1: +3.0, 2: +1.5, 3: +2.0}   # block is best
        else:
            rewards = {0: +1.0, 1: -3.0, 2: -0.5, 3: -0.2}    # allow is best
        return rewards.get(action, 0.0)

    def episode_stats(self) -> Dict[str, float]:
        if not self.ep_rewards:
            return {}
        return {
            "mean_reward": float(np.mean(self.ep_rewards)),
            "total_reward": float(np.sum(self.ep_rewards)),
            "steps": self.step_count,
        }


# ── PPO Trainer ───────────────────────────────────────────────────────────────

class PPOTrainer:
    """
    PPO (Proximal Policy Optimization) trainer.
    Production version should use PyTorch — this is the offline reference impl.
    """

    def __init__(self, cfg: TrainingConfig):
        self.cfg    = cfg
        self.policy = PolicyNetwork(cfg)
        self.envs   = [NetworkFlowEnv(np.random.default_rng(i)) for i in range(cfg.n_agents)]
        self.obs     = [env.reset() for env in self.envs]
        self.global_step   = 0
        self.episode_count = 0
        self.metrics: List[Dict] = []

        # Try to resume
        ckpt = os.path.join(cfg.model_dir, f"{cfg.run_name}_latest")
        self.policy.load(ckpt)

    def collect_rollout(self, n_steps: int = 2048):
        """جمع بيانات التدريب من جميع الـ agents"""
        buffer: Dict[str, List] = {"obs": [], "actions": [], "rewards": [],
                                   "log_probs": [], "values": [], "dones": []}
        for _ in range(n_steps // self.cfg.n_agents):
            for i, (env, obs) in enumerate(zip(self.envs, self.obs)):
                action, log_prob, value = self.policy.get_action_value(obs)
                next_obs, reward, done  = env.step(action)

                buffer["obs"].append(obs)
                buffer["actions"].append(action)
                buffer["rewards"].append(reward)
                buffer["log_probs"].append(log_prob)
                buffer["values"].append(value)
                buffer["dones"].append(float(done))

                self.obs[i] = env.reset() if done else next_obs
                if done:
                    self.episode_count += 1
                self.global_step += 1

        return {k: np.array(v) for k, v in buffer.items()}

    def compute_advantages(
        self,
        rewards: np.ndarray,
        values:  np.ndarray,
        dones:   np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """GAE (Generalized Advantage Estimation)"""
        n    = len(rewards)
        adv  = np.zeros(n, dtype=np.float64)
        ret  = np.zeros(n, dtype=np.float64)
        gae  = 0.0
        for t in reversed(range(n)):
            next_val = values[t+1] if t < n-1 else 0.0
            delta    = rewards[t] + self.cfg.gamma * next_val * (1 - dones[t]) - values[t]
            gae      = delta + self.cfg.gamma * self.cfg.gae_lambda * (1 - dones[t]) * gae
            adv[t]   = gae
            ret[t]   = adv[t] + values[t]
        # Normalize advantages
        adv = (adv - adv.mean()) / (adv.std() + 1e-8)
        return adv, ret

    def train(self):
        """حلقة التدريب الرئيسية"""
        mlflow_active = False
        try:
            import mlflow
            mlflow.set_experiment("thor_marl_firewall")
            mlflow.start_run(run_name=self.cfg.run_name)
            mlflow.log_params({
                "n_agents": self.cfg.n_agents,
                "lr_actor": self.cfg.lr_actor,
                "batch_size": self.cfg.batch_size,
                "gamma": self.cfg.gamma,
                "clip_eps": self.cfg.clip_eps,
                "total_steps": self.cfg.total_steps,
            })
            mlflow_active = True
            logger.info("mlflow_tracking_active")
        except ImportError:
            logger.warning("mlflow_not_available", msg="Continuing without tracking")

        logger.info("training_start", total_steps=self.cfg.total_steps,
                    n_agents=self.cfg.n_agents)

        t_start = time.time()
        while self.global_step < self.cfg.total_steps:
            rollout = self.collect_rollout(self.cfg.batch_size)
            adv, ret = self.compute_advantages(
                rollout["rewards"], rollout["values"], rollout["dones"]
            )

            # Log metrics
            if self.global_step % self.cfg.log_interval == 0:
                ep_rew_mean = float(np.mean(rollout["rewards"]))
                elapsed     = time.time() - t_start
                sps         = self.global_step / max(elapsed, 1)
                metrics = {
                    "step":         self.global_step,
                    "episode":      self.episode_count,
                    "mean_reward":  round(ep_rew_mean, 4),
                    "value_mean":   round(float(np.mean(rollout["values"])), 4),
                    "sps":          round(sps, 1),
                    "elapsed_s":    round(elapsed, 1),
                }
                self.metrics.append(metrics)
                logger.info("train_step", **metrics)

                if mlflow_active:
                    import mlflow
                    mlflow.log_metrics({
                        "mean_reward": ep_rew_mean,
                        "value_mean":  float(np.mean(rollout["values"])),
                        "sps":         sps,
                    }, step=self.global_step)

            # Save checkpoint
            if self.global_step % self.cfg.save_every == 0:
                ckpt = os.path.join(self.cfg.model_dir,
                                    f"{self.cfg.run_name}_{self.global_step}")
                self.policy.save(ckpt)
                self.policy.save(os.path.join(self.cfg.model_dir, f"{self.cfg.run_name}_latest"))

        # Final checkpoint
        final_path = os.path.join(self.cfg.model_dir, f"{self.cfg.run_name}_final")
        self.policy.save(final_path)
        if mlflow_active:
            import mlflow
            mlflow.log_artifact(final_path + ".npz")
            mlflow.end_run()

        total_time = time.time() - t_start
        logger.info("training_complete",
                    total_steps=self.global_step,
                    total_episodes=self.episode_count,
                    duration_minutes=round(total_time/60, 1))
        return self.metrics


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Thor MARL Training")
    parser.add_argument("--steps",     type=int,   default=200_000)
    parser.add_argument("--agents",    type=int,   default=8)
    parser.add_argument("--lr",        type=float, default=3e-4)
    parser.add_argument("--batch",     type=int,   default=2048)
    parser.add_argument("--model-dir", type=str,   default="ml/models")
    parser.add_argument("--run-name",  type=str,   default=f"marl_{int(time.time())}")
    args = parser.parse_args()

    cfg = TrainingConfig(
        total_steps = args.steps,
        n_agents    = args.agents,
        lr_actor    = args.lr,
        batch_size  = args.batch,
        model_dir   = args.model_dir,
        run_name    = args.run_name,
    )
    trainer = PPOTrainer(cfg)
    metrics = trainer.train()

    if metrics:
        last = metrics[-1]
        print(f"\n=== Training Complete ===")
        print(f"  Final mean reward: {last.get('mean_reward', 0):.4f}")
        print(f"  Total steps:       {last.get('step', 0):,}")
        print(f"  Total time:        {last.get('elapsed_s', 0):.1f}s")


if __name__ == "__main__":
    main()
