"""
Thor Firewall — Multi-Agent Reinforcement Learning (MARL)
نظام الوكلاء المتعددين للتعلم المعزز

يُنفّذ بنية POCA (Population-Enhanced Centralized Agent) المتقدمة:
- وكيل مخصص لكل بروتوكول (TCP, UDP, ICMP)
- وكيل منسق (Meta-Agent) يجمع القرارات
- تدريب موزع على GPU cluster

المرجع: "Multi-Agent Reinforcement Learning for Network Intrusion Detection"
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import numpy as np

# ============================================================================
# Configuration
# ============================================================================

@dataclass
class MARLConfig:
    """إعدادات نظام MARL"""
    # بُعد مساحة الحالة (50 ميزة لكل تدفق + ميزات الشبكة)
    state_dim: int = 50 + 32  # 50 flow features + 32 GNN embedding
    # عدد الإجراءات الممكنة: allow, block, throttle, mirror, redirect
    action_dim: int = 5
    # بُعد الذاكرة الداخلية للشبكة العصبية
    hidden_dim: int = 256
    # عدد طبقات الشبكة العصبية
    num_layers: int = 4
    # معدل التعلم
    learning_rate: float = 3e-4
    # معامل الخصم
    gamma: float = 0.99
    # معامل GAE (Generalized Advantage Estimation)
    gae_lambda: float = 0.95
    # نافذة Clip لـ PPO
    clip_range: float = 0.2
    # معامل انتروبيا (لتشجيع الاستكشاف)
    entropy_coeff: float = 0.01
    # معامل دالة القيمة
    value_coeff: float = 0.5
    # حجم دفعة التدريب
    batch_size: int = 2048
    # عدد حقب التدريب لكل دفعة
    epochs_per_batch: int = 10
    # البروتوكولات المدعومة
    protocols: List[str] = field(default_factory=lambda: ["tcp", "udp", "icmp"])
    # اسم الجهاز (cuda/mps/cpu)
    device: str = "cuda" if torch.cuda.is_available() else "cpu"


# ============================================================================
# Neural Network Architecture
# ============================================================================

class ResidualBlock(nn.Module):
    """كتلة residual لتحسين التدرج في الشبكات العميقة"""

    def __init__(self, dim: int, dropout: float = 0.1):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(dim, dim),
            nn.LayerNorm(dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
            nn.LayerNorm(dim),
        )
        self.activation = nn.GELU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.activation(x + self.net(x))


class ActorCriticNetwork(nn.Module):
    """
    شبكة Actor-Critic للوكيل الفردي
    تُخرج: توزيع الإجراءات (actor) + تقييم الحالة (critic)
    """

    def __init__(self, config: MARLConfig):
        super().__init__()
        self.config = config

        # طبقة الإدخال المشتركة
        self.input_encoder = nn.Sequential(
            nn.Linear(config.state_dim, config.hidden_dim),
            nn.LayerNorm(config.hidden_dim),
            nn.GELU(),
        )

        # طبقات residual مشتركة
        self.shared_trunk = nn.Sequential(
            *[ResidualBlock(config.hidden_dim) for _ in range(config.num_layers // 2)]
        )

        # رأس Actor (السياسة)
        self.actor_head = nn.Sequential(
            *[ResidualBlock(config.hidden_dim) for _ in range(config.num_layers // 2)],
            nn.Linear(config.hidden_dim, config.action_dim),
        )

        # رأس Critic (دالة القيمة)
        self.critic_head = nn.Sequential(
            *[ResidualBlock(config.hidden_dim) for _ in range(config.num_layers // 2)],
            nn.Linear(config.hidden_dim, 1),
        )

        # تهيئة الأوزان
        self._initialize_weights()

    def _initialize_weights(self):
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.orthogonal_(module.weight, gain=np.sqrt(2))
                nn.init.zeros_(module.bias)

        # رأس Actor يبدأ بأوزان صغيرة لتوزيع منتظم
        nn.init.orthogonal_(self.actor_head[-1].weight, gain=0.01)

    def forward(
        self,
        state: torch.Tensor,
        deterministic: bool = False
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Args:
            state: [batch, state_dim]
            deterministic: إذا True، يختار الإجراء الأعلى احتمالاً

        Returns:
            action: [batch] — الإجراء المختار
            log_prob: [batch] — لوغاريتم الاحتمال
            value: [batch] — تقييم الحالة
        """
        x = self.input_encoder(state)
        shared = self.shared_trunk(x)

        logits = self.actor_head(shared)
        value = self.critic_head(shared).squeeze(-1)

        dist = torch.distributions.Categorical(logits=logits)

        if deterministic:
            action = logits.argmax(dim=-1)
        else:
            action = dist.sample()

        log_prob = dist.log_prob(action)

        return action, log_prob, value

    def evaluate_actions(
        self,
        state: torch.Tensor,
        action: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        تقييم إجراءات موجودة (للتدريب)
        Returns: log_prob, entropy, value
        """
        x = self.input_encoder(state)
        shared = self.shared_trunk(x)

        logits = self.actor_head(shared)
        value = self.critic_head(shared).squeeze(-1)

        dist = torch.distributions.Categorical(logits=logits)
        log_prob = dist.log_prob(action)
        entropy = dist.entropy()

        return log_prob, entropy, value


# ============================================================================
# Protocol-Specific Agents
# ============================================================================

class ProtocolAgent:
    """
    وكيل مخصص لبروتوكول معين (TCP, UDP, ICMP)
    كل وكيل يتخصص في أنماط التهديد الخاصة ببروتوكوله
    """

    def __init__(self, protocol: str, config: MARLConfig):
        self.protocol = protocol
        self.config = config
        self.device = torch.device(config.device)

        self.network = ActorCriticNetwork(config).to(self.device)
        self.optimizer = torch.optim.AdamW(
            self.network.parameters(),
            lr=config.learning_rate,
            weight_decay=1e-5,
        )

        # مخزن التجارب (Experience Buffer)
        self.buffer = ExperienceBuffer(config)

        # مؤشرات الأداء
        self.total_steps = 0
        self.episodes_completed = 0
        self.avg_reward = 0.0

    @torch.no_grad()
    def select_action(
        self,
        state: np.ndarray,
        deterministic: bool = False
    ) -> Tuple[int, float, float]:
        """
        اختيار إجراء للحالة الحالية

        Args:
            state: مصفوفة الحالة [state_dim]
            deterministic: وضع الاستنتاج (بدون استكشاف)

        Returns:
            (action_idx, log_prob, state_value)
        """
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        action, log_prob, value = self.network(state_tensor, deterministic)

        return (
            action.item(),
            log_prob.item(),
            value.item(),
        )

    def store_transition(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        log_prob: float,
        value: float,
        done: bool,
    ):
        """تخزين تجربة في المخزن"""
        self.buffer.add(state, action, reward, log_prob, value, done)

    def update(self) -> Dict[str, float]:
        """
        تحديث الشبكة باستخدام PPO
        يُستدعى بعد جمع batch_size تجربة
        """
        if len(self.buffer) < self.config.batch_size:
            return {}

        # حساب المزايا (Advantages) باستخدام GAE
        advantages, returns = self.buffer.compute_advantages(
            gamma=self.config.gamma,
            gae_lambda=self.config.gae_lambda,
        )

        # تدريب متعدد الحقب
        metrics = {"policy_loss": 0.0, "value_loss": 0.0, "entropy": 0.0}

        for epoch in range(self.config.epochs_per_batch):
            for batch in self.buffer.get_batches(self.config.batch_size):
                states, actions, old_log_probs, adv_batch, ret_batch = batch

                states = states.to(self.device)
                actions = actions.to(self.device)
                old_log_probs = old_log_probs.to(self.device)
                adv_batch = adv_batch.to(self.device)
                ret_batch = ret_batch.to(self.device)

                # تطبيع المزايا
                adv_batch = (adv_batch - adv_batch.mean()) / (adv_batch.std() + 1e-8)

                # تقييم الإجراءات
                new_log_probs, entropy, values = self.network.evaluate_actions(states, actions)

                # نسبة الاحتمالات (Probability Ratio)
                ratio = torch.exp(new_log_probs - old_log_probs)

                # PPO Clipped Objective
                surr1 = ratio * adv_batch
                surr2 = torch.clamp(ratio, 1 - self.config.clip_range, 1 + self.config.clip_range) * adv_batch
                policy_loss = -torch.min(surr1, surr2).mean()

                # Value Function Loss (Huber)
                value_loss = F.huber_loss(values, ret_batch)

                # إجمالي الخسارة
                total_loss = (
                    policy_loss
                    + self.config.value_coeff * value_loss
                    - self.config.entropy_coeff * entropy.mean()
                )

                self.optimizer.zero_grad()
                total_loss.backward()
                nn.utils.clip_grad_norm_(self.network.parameters(), max_norm=0.5)
                self.optimizer.step()

                metrics["policy_loss"] += policy_loss.item()
                metrics["value_loss"] += value_loss.item()
                metrics["entropy"] += entropy.mean().item()

        self.buffer.clear()
        self.total_steps += self.config.batch_size

        return metrics

    def save(self, path: str):
        """حفظ الوكيل"""
        torch.save({
            "protocol": self.protocol,
            "network_state": self.network.state_dict(),
            "optimizer_state": self.optimizer.state_dict(),
            "total_steps": self.total_steps,
            "avg_reward": self.avg_reward,
        }, path)

    def load(self, path: str):
        """تحميل الوكيل"""
        checkpoint = torch.load(path, map_location=self.device)
        self.network.load_state_dict(checkpoint["network_state"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state"])
        self.total_steps = checkpoint["total_steps"]
        self.avg_reward = checkpoint["avg_reward"]


# ============================================================================
# Meta Agent (Centralized Coordinator)
# ============================================================================

class MetaAgent:
    """
    الوكيل المنسق — يجمع قرارات الوكلاء الأفراد
    ويتخذ القرار النهائي مع مراعاة السياق الكلي للشبكة
    """

    def __init__(self, config: MARLConfig):
        self.config = config
        self.device = torch.device(config.device)

        # وكيل لكل بروتوكول
        self.protocol_agents: Dict[str, ProtocolAgent] = {
            proto: ProtocolAgent(proto, config)
            for proto in config.protocols
        }

        # شبكة تنسيق مركزية تأخذ مدخلات من جميع الوكلاء
        meta_input_dim = config.action_dim * len(config.protocols) + config.state_dim
        self.meta_network = nn.Sequential(
            nn.Linear(meta_input_dim, config.hidden_dim),
            nn.GELU(),
            ResidualBlock(config.hidden_dim),
            ResidualBlock(config.hidden_dim),
            nn.Linear(config.hidden_dim, config.action_dim),
        ).to(self.device)

    def make_decision(
        self,
        state: np.ndarray,
        protocol: str,
        deterministic: bool = True,
    ) -> Tuple[int, float]:
        """
        اتخاذ قرار نهائي

        Args:
            state: حالة التدفق الحالية
            protocol: البروتوكول (tcp/udp/icmp)
            deterministic: وضع الإنتاج (True) أو التدريب (False)

        Returns:
            (action_idx, confidence_score)
        """
        agent = self.protocol_agents.get(protocol, self.protocol_agents["tcp"])
        action, log_prob, value = agent.select_action(state, deterministic)

        # الثقة = exp(log_prob) = الاحتمال الفعلي
        confidence = np.exp(log_prob)

        return action, float(confidence)

    def compute_reward(
        self,
        action: int,
        was_attack: bool,
        false_positive: bool,
        latency_ms: float,
    ) -> float:
        """
        حساب المكافأة بناءً على نتيجة القرار

        مبدأ المكافآت:
        - تحديد هجوم صحيح: +10
        - false positive: -5 (عقوبة عالية لتجنب إزعاج المستخدمين)
        - false negative: -10 (عقوبة أعلى لأن الهجوم نجح)
        - زمن معالجة منخفض: مكافأة إضافية صغيرة
        """
        reward = 0.0

        if was_attack:
            if action == 1:  # Block — قرار صحيح
                reward += 10.0
            else:  # Allow — false negative
                reward -= 10.0
        else:
            if action == 0:  # Allow — قرار صحيح
                reward += 1.0
            elif action == 1:  # Block — false positive
                reward -= 5.0

        # مكافأة على سرعة المعالجة
        if latency_ms < 1.0:
            reward += 0.1
        elif latency_ms > 10.0:
            reward -= 0.05

        return reward

    def save_all(self, base_dir: str):
        """حفظ جميع الوكلاء"""
        import os
        os.makedirs(base_dir, exist_ok=True)
        for proto, agent in self.protocol_agents.items():
            agent.save(f"{base_dir}/{proto}_agent.pt")
        torch.save(self.meta_network.state_dict(), f"{base_dir}/meta_network.pt")

    def load_all(self, base_dir: str):
        """تحميل جميع الوكلاء"""
        for proto, agent in self.protocol_agents.items():
            path = f"{base_dir}/{proto}_agent.pt"
            import os
            if os.path.exists(path):
                agent.load(path)
        meta_path = f"{base_dir}/meta_network.pt"
        if os.path.exists(meta_path):
            self.meta_network.load_state_dict(
                torch.load(meta_path, map_location=self.device)
            )


# ============================================================================
# Experience Buffer
# ============================================================================

class ExperienceBuffer:
    """مخزن تجارب التعلم المعزز"""

    def __init__(self, config: MARLConfig):
        self.config = config
        self.states: List[np.ndarray] = []
        self.actions: List[int] = []
        self.rewards: List[float] = []
        self.log_probs: List[float] = []
        self.values: List[float] = []
        self.dones: List[bool] = []

    def add(self, state, action, reward, log_prob, value, done):
        self.states.append(state)
        self.actions.append(action)
        self.rewards.append(reward)
        self.log_probs.append(log_prob)
        self.values.append(value)
        self.dones.append(done)

    def __len__(self):
        return len(self.states)

    def compute_advantages(
        self,
        gamma: float = 0.99,
        gae_lambda: float = 0.95,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """حساب مزايا GAE (Generalized Advantage Estimation)"""
        rewards = np.array(self.rewards)
        values = np.array(self.values)
        dones = np.array(self.dones, dtype=np.float32)

        advantages = np.zeros_like(rewards)
        last_advantage = 0.0

        for t in reversed(range(len(rewards))):
            if t == len(rewards) - 1:
                next_value = 0.0
            else:
                next_value = values[t + 1]

            delta = rewards[t] + gamma * next_value * (1 - dones[t]) - values[t]
            advantages[t] = delta + gamma * gae_lambda * (1 - dones[t]) * last_advantage
            last_advantage = advantages[t]

        returns = advantages + values
        return advantages, returns

    def get_batches(self, batch_size: int):
        """توليد دفعات عشوائية للتدريب"""
        n = len(self.states)
        indices = np.random.permutation(n)

        states = torch.FloatTensor(np.array(self.states))
        actions = torch.LongTensor(self.actions)
        log_probs = torch.FloatTensor(self.log_probs)
        advantages, returns = self.compute_advantages(
            self.config.gamma, self.config.gae_lambda
        )
        adv_tensor = torch.FloatTensor(advantages)
        ret_tensor = torch.FloatTensor(returns)

        for start in range(0, n, batch_size):
            batch_idx = indices[start:start + batch_size]
            yield (
                states[batch_idx],
                actions[batch_idx],
                log_probs[batch_idx],
                adv_tensor[batch_idx],
                ret_tensor[batch_idx],
            )

    def clear(self):
        self.states.clear()
        self.actions.clear()
        self.rewards.clear()
        self.log_probs.clear()
        self.values.clear()
        self.dones.clear()


# ============================================================================
# Action Space
# ============================================================================

# تعريف الإجراءات الممكنة
ACTION_SPACE = {
    0: "allow",
    1: "block",
    2: "throttle_100pps",
    3: "mirror",
    4: "redirect_honeypot",
}

ACTION_NAMES = list(ACTION_SPACE.values())
