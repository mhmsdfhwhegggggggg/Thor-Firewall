"""
Thor Firewall — SOC Analyst Feedback Collector
جامع تغذية راجعة لمحللي SOC لتحسين النماذج

كلما صحّح محلل SOC قراراً خاطئاً (FP/FN)،
يُسجَّل ويُستخدم في التعلم التدريجي (online learning).

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import asyncio, logging, time, json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("thor.ml.feedback")


@dataclass
class FeedbackSample:
    flow_id: str
    features: List[float]
    predicted_label: int
    true_label: int
    analyst_id: str
    feedback_type: str       # "false_positive" | "false_negative" | "correct_severity"
    notes: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class FeedbackCollector:
    """يجمع ويُخزن تغذية راجعة المحللين"""

    def __init__(self, buffer_size: int = 1000, output_dir: str = "/data/feedback"):
        self.buffer_size = buffer_size
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._buffer: List[FeedbackSample] = []
        self._stats: Dict[str, int] = {"total": 0, "fp": 0, "fn": 0}

    async def add_feedback(self, sample: FeedbackSample):
        """إضافة تغذية راجعة جديدة"""
        self._buffer.append(sample)
        self._stats["total"] += 1
        if sample.feedback_type == "false_positive":
            self._stats["fp"] += 1
        elif sample.feedback_type == "false_negative":
            self._stats["fn"] += 1

        logger.info("Feedback collected: %s | predicted=%d, true=%d | analyst=%s",
                    sample.feedback_type, sample.predicted_label,
                    sample.true_label, sample.analyst_id)

        # تفريغ البفر عند امتلائه
        if len(self._buffer) >= self.buffer_size:
            await self._flush()

    async def _flush(self):
        """حفظ البفر إلى ملف"""
        if not self._buffer:
            return
        timestamp = int(time.time())
        path = self.output_dir / f"feedback_{timestamp}.jsonl"
        with open(path, "w") as f:
            for sample in self._buffer:
                f.write(json.dumps(asdict(sample)) + "\n")
        logger.info("Flushed %d feedback samples to %s", len(self._buffer), path)
        self._buffer.clear()

    async def trigger_retraining(self, min_samples: int = 500) -> bool:
        """تشغيل إعادة التدريب إذا كان هناك بيانات كافية"""
        all_files = list(self.output_dir.glob("feedback_*.jsonl"))
        total = sum(1 for f in all_files for _ in open(f))
        if total >= min_samples:
            logger.info("Triggering incremental retraining with %d feedback samples", total)
            return True
        logger.info("Not enough feedback yet: %d/%d", total, min_samples)
        return False

    def get_stats(self) -> Dict:
        return {**self._stats, "buffered": len(self._buffer)}
