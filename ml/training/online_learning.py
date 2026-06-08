"""
Thor Firewall — Online Learning Pipeline
خط أنابيب التعلم المستمر (Online Learning)

يُحدَّث النموذج باستمرار بالبيانات الحديثة:
1. يستقبل قرارات الـ Agent مع نتائجها الفعلية
2. يُحدِّث خسارة PPO تدريجياً
3. يُقيِّم الأداء كل N خطوة ويحفظ checkpoint عند التحسن

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch

logger = logging.getLogger("thor.online_learning")

# ============================================================================
# Experience Buffer
# ============================================================================

@dataclass
class FeedbackRecord:
    """سجل تغذية راجعة من القرارات الفعلية"""
    flow_hash:    int
    features:     np.ndarray   # [82]
    action:       int          # 0=allow, 1=block, 2=throttle, ...
    reward:       float        # مكافأة المكتشَفة
    confirmed:    bool         # هل أكّد الإنسان القرار؟
    threat_type:  str          # نوع التهديد الفعلي
    protocol:     str
    timestamp:    float = field(default_factory=time.time)


class ExperienceReplay:
    """
    ذاكرة تجارب بأولوية (Prioritized Experience Replay)

    الأولوية بناءً على:
    - خطأ التنبؤ (TD Error)
    - ندرة نوع التهديد
    - تأكيد الإنسان (Human-in-the-Loop)
    """

    def __init__(self, capacity: int = 500_000):
        self.capacity = capacity
        self._buffer: List[Tuple[float, FeedbackRecord]] = []  # (priority, record)
        self._lock = threading.Lock()

    def add(self, record: FeedbackRecord, priority: float = 1.0):
        with self._lock:
            self._buffer.append((priority, record))
            if len(self._buffer) > self.capacity:
                # إزالة الأقدم بأدنى أولوية
                self._buffer.sort(key=lambda x: (-x[0], x[1].timestamp))
                self._buffer = self._buffer[:self.capacity]

    def sample(self, n: int) -> List[FeedbackRecord]:
        with self._lock:
            if len(self._buffer) < n:
                return [r for _, r in self._buffer]

            # أخذ عينة بأولوية
            priorities = np.array([p for p, _ in self._buffer], dtype=np.float32)
            priorities = priorities / priorities.sum()

            indices = np.random.choice(len(self._buffer), size=n, p=priorities, replace=False)
            return [self._buffer[i][1] for i in indices]

    def __len__(self):
        return len(self._buffer)


# ============================================================================
# Online Trainer
# ============================================================================

class OnlineTrainer:
    """
    مُدرِّب النموذج عبر الإنترنت

    يعمل في thread منفصل ويُحدِّث النموذج باستمرار
    """

    def __init__(
        self,
        checkpoint_dir: str = "ml/checkpoints/online",
        min_samples: int = 1024,
        update_interval: int = 60,
        save_interval: int = 3600,
        eval_interval: int = 900,
    ):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        self.min_samples = min_samples
        self.update_interval = update_interval   # ثانية
        self.save_interval = save_interval       # ثانية
        self.eval_interval = eval_interval       # ثانية

        self.replay = ExperienceReplay(capacity=1_000_000)
        self._feedback_queue: queue.Queue = queue.Queue(maxsize=50_000)

        self._running = False
        self._thread: Optional[threading.Thread] = None

        # إحصاءات
        self.stats = OnlineLearningStats()

        # متعقّب الأداء
        self._best_accuracy = 0.0
        self._last_save = time.time()
        self._last_eval = time.time()

    def submit_feedback(self, records: List[FeedbackRecord]):
        """إرسال تغذية راجعة — non-blocking"""
        for record in records:
            try:
                self._feedback_queue.put_nowait(record)
            except queue.Full:
                logger.warning("Feedback queue full — dropping old record")
                try:
                    self._feedback_queue.get_nowait()
                    self._feedback_queue.put_nowait(record)
                except queue.Empty:
                    pass

    def start(self, meta_agent: Any):
        """بدء حلقة التدريب في thread منفصل"""
        self._meta_agent = meta_agent
        self._running = True
        self._thread = threading.Thread(
            target=self._training_loop,
            daemon=True,
            name="thor-online-trainer",
        )
        self._thread.start()
        logger.info("Online training loop started")

    def stop(self):
        """إيقاف حلقة التدريب"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Online training loop stopped")

    def _training_loop(self):
        """حلقة التدريب الرئيسية"""
        while self._running:
            try:
                # استيعاب التغذية الراجعة الجديدة
                self._ingest_feedback()

                # تدريب إذا كان لديك ما يكفي من العينات
                if len(self.replay) >= self.min_samples:
                    self._update_step()

                # تقييم وحفظ
                now = time.time()
                if now - self._last_eval > self.eval_interval:
                    self._evaluate()
                    self._last_eval = now

                if now - self._last_save > self.save_interval:
                    self._save_checkpoint()
                    self._last_save = now

                time.sleep(self.update_interval)

            except Exception as e:
                logger.error(f"Training loop error: {e}", exc_info=True)
                time.sleep(30)

    def _ingest_feedback(self):
        """استيعاب التغذية الراجعة من Queue"""
        count = 0
        while True:
            try:
                record = self._feedback_queue.get_nowait()
                priority = self._compute_priority(record)
                self.replay.add(record, priority)
                count += 1
            except queue.Empty:
                break

        if count > 0:
            self.stats.total_feedback += count
            logger.debug(f"Ingested {count} feedback records ({len(self.replay)} in replay)")

    def _compute_priority(self, record: FeedbackRecord) -> float:
        """حساب أولوية التجربة"""
        priority = 1.0

        # رفع أولوية التجارب المؤكدة يدوياً
        if record.confirmed:
            priority *= 3.0

        # رفع أولوية التهديدات الحرجة
        if record.threat_type in ("syn-flood", "zero-day", "ransomware", "apt"):
            priority *= 2.0

        # رفع أولوية القرارات غير الصحيحة (False Positive/Negative)
        if (record.action == 1 and record.reward < 0) or \
           (record.action == 0 and record.reward < -0.5):
            priority *= 4.0  # خطأ خطير — تعلّم منه بقوة

        return priority

    def _update_step(self):
        """خطوة تدريب واحدة"""
        batch = self.replay.sample(min(256, len(self.replay)))
        if not batch:
            return

        try:
            # تنظيم البيانات
            states = np.stack([r.features for r in batch])
            actions = np.array([r.action for r in batch], dtype=np.int64)
            rewards = np.array([r.reward for r in batch], dtype=np.float32)

            states_tensor = torch.FloatTensor(states)
            actions_tensor = torch.LongTensor(actions)
            rewards_tensor = torch.FloatTensor(rewards)

            # تحديث كل عميل بروتوكول حسب بياناته
            for proto in ["tcp", "udp", "icmp", "meta"]:
                proto_indices = [i for i, r in enumerate(batch) if r.protocol == proto]
                if not proto_indices or proto not in self._meta_agent.protocol_agents:
                    continue

                agent = self._meta_agent.protocol_agents[proto]

                # إضافة تجارب لـ replay buffer الداخلي
                for idx in proto_indices:
                    record = batch[idx]
                    agent.store_transition(
                        state=states[idx],
                        action=actions[idx],
                        reward=rewards[idx],
                        log_prob=0.0,   # تقريباً — لا نملك القيمة الأصلية
                        value=0.5,
                        done=False,
                    )

                # تشغيل خطوة تحديث PPO
                loss_info = agent.update()
                if loss_info:
                    self.stats.update_steps += 1
                    self.stats.last_loss = loss_info.get("total_loss", 0.0)

        except Exception as e:
            logger.error(f"Update step failed: {e}")

    def _evaluate(self):
        """تقييم الأداء الحالي"""
        try:
            # أخذ عينة تقييم من الـ replay
            eval_batch = self.replay.sample(min(1000, len(self.replay)))
            if not eval_batch:
                return

            correct = 0
            total = len(eval_batch)

            for record in eval_batch:
                try:
                    proto = record.protocol
                    if proto not in self._meta_agent.protocol_agents:
                        continue

                    agent = self._meta_agent.protocol_agents[proto]
                    state_tensor = torch.FloatTensor(record.features).unsqueeze(0)
                    action, _, _ = agent.actor_critic.get_action(state_tensor)

                    # قرار صحيح إذا كانت المكافأة إيجابية للقرار المُتَّخذ
                    predicted_action = action.item()
                    if (predicted_action == record.action and record.reward >= 0) or \
                       (predicted_action != record.action and record.reward < 0):
                        correct += 1
                except Exception:
                    pass

            accuracy = correct / total if total > 0 else 0
            self.stats.eval_accuracy = accuracy

            if accuracy > self._best_accuracy:
                self._best_accuracy = accuracy
                self._save_checkpoint(tag="best")
                logger.info(f"New best accuracy: {accuracy:.4f} — checkpoint saved")
            else:
                logger.info(
                    f"Eval accuracy: {accuracy:.4f} (best: {self._best_accuracy:.4f})"
                )

        except Exception as e:
            logger.error(f"Evaluation failed: {e}")

    def _save_checkpoint(self, tag: str = "latest"):
        """حفظ checkpoint"""
        try:
            path = self.checkpoint_dir / tag
            path.mkdir(exist_ok=True)
            self._meta_agent.save_all(str(path))

            # حفظ metadata
            meta = {
                "timestamp": time.time(),
                "update_steps": self.stats.update_steps,
                "total_feedback": self.stats.total_feedback,
                "best_accuracy": self._best_accuracy,
                "replay_size": len(self.replay),
            }
            (path / "online_meta.json").write_text(json.dumps(meta, indent=2))
            logger.info(f"Checkpoint saved: {path}")

        except Exception as e:
            logger.error(f"Checkpoint save failed: {e}")


@dataclass
class OnlineLearningStats:
    total_feedback: int = 0
    update_steps:   int = 0
    last_loss:      float = 0.0
    eval_accuracy:  float = 0.0
    replay_size:    int = 0
    last_update:    float = field(default_factory=time.time)
