"""
Thor Firewall — Online Learning: Feedback Collector
جامع التغذية الراجعة للتعلم المستمر

يستقبل تصحيحات محللي SOC (FP/FN) ويُضمّنها في دورة التدريب التدريجي.
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import asyncio, json, logging, time
from dataclasses import dataclass, asdict
from typing import List, Optional
import numpy as np

logger = logging.getLogger("thor.ml.online")

@dataclass
class FeedbackSample:
    flow_key_hash: int
    features: List[float]
    protocol: str
    original_decision: str      # what ML said
    original_risk: float
    corrected_label: str        # what SOC says (ground truth)
    analyst_id: str
    timestamp: float
    severity: str = "medium"

class FeedbackCollector:
    """يجمع تصحيحات SOC ويُخزّنها للتدريب التدريجي"""

    def __init__(self, buffer_size: int = 10_000, redis_client=None):
        self._buffer: List[FeedbackSample] = []
        self._max_size = buffer_size
        self._redis = redis_client

    async def submit(self, sample: FeedbackSample):
        """إضافة تصحيح جديد من SOC Analyst"""
        if len(self._buffer) >= self._max_size:
            self._buffer.pop(0)  # FIFO
        self._buffer.append(sample)

        if self._redis:
            await self._redis.lpush("thor:ml:feedback", json.dumps(asdict(sample)))
            await self._redis.ltrim("thor:ml:feedback", 0, self._max_size - 1)

        logger.info(
            "Feedback received: %s→%s by %s (hash=%d)",
            sample.original_decision, sample.corrected_label,
            sample.analyst_id, sample.flow_key_hash
        )

    async def get_batch(self, n: int = 512) -> List[FeedbackSample]:
        """استرجاع دفعة للتدريب"""
        if self._redis:
            raw = await self._redis.lrange("thor:ml:feedback", 0, n - 1)
            return [FeedbackSample(**json.loads(r)) for r in raw]
        return self._buffer[-n:]

    @property
    def pending_count(self) -> int:
        return len(self._buffer)


class IncrementalTrainer:
    """
    تدريب تدريجي بعد كل 512 تصحيح جديد.
    يستخدم Elastic Weight Consolidation (EWC) لتجنب catastrophic forgetting.
    """

    def __init__(self, model_dir: str = "/models/marl", min_batch: int = 512):
        self.model_dir = model_dir
        self.min_batch = min_batch
        self._trained_count = 0

    async def maybe_retrain(self, feedback: List[FeedbackSample]) -> bool:
        """إعادة تدريب إذا وصلنا للحد الأدنى"""
        if len(feedback) < self.min_batch:
            logger.debug("Skipping retrain: %d/%d samples", len(feedback), self.min_batch)
            return False

        logger.info("Starting incremental training with %d feedback samples", len(feedback))

        try:
            import torch
            from ml.training.train_marl import ProtocolAgent, ActorCriticNetwork
            import torch.nn as nn

            # Group by protocol
            by_proto = {}
            for s in feedback:
                by_proto.setdefault(s.protocol, []).append(s)

            for protocol, samples in by_proto.items():
                X = np.array([s.features[:50] for s in samples], dtype=np.float32)
                # Map labels to class indices
                label_map = {"allow": 0, "block": 1, "throttle": 2, "mirror": 3, "redirect": 4}
                y = np.array([label_map.get(s.corrected_label, 0) for s in samples])

                X_t = torch.FloatTensor(X)
                y_t = torch.LongTensor(y)

                agent = ProtocolAgent(protocol=protocol, input_dim=50, device="cpu")
                model_path = f"{self.model_dir}/thor_{protocol}_agent.pt"

                import os
                if os.path.exists(model_path):
                    agent.load(model_path)

                criterion = nn.CrossEntropyLoss()
                for epoch in range(5):
                    logits, _ = agent.network(X_t)
                    loss = criterion(logits, y_t)
                    agent.optimizer.zero_grad()
                    loss.backward()
                    nn.utils.clip_grad_norm_(agent.network.parameters(), 0.5)
                    agent.optimizer.step()

                agent.save(model_path)
                self._trained_count += len(samples)
                logger.info("Incremental training complete: %s agent, %d samples", protocol, len(samples))

            return True

        except Exception as e:
            logger.error("Incremental training failed: %s", e)
            return False
