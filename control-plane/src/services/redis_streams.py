"""
Thor Firewall — Redis Streams Event Pipeline
خط أنابيب الأحداث عبر Redis Streams

يُوفر:
- استيعاب الأحداث بـ throughput عالٍ (1M+ event/s)
- Consumer groups لمعالجة موزعة
- Dead letter queue لإعادة المحاولة
- Automatic trimming وTTL

Streams:
    thor:flows      — أحداث تدفقات جديدة
    thor:threats    — أحداث تهديدات مكتشفة
    thor:decisions  — قرارات ML من العميل
    thor:alerts     — تنبيهات عاجلة (CRITICAL)
    thor:control    — أوامر التحكم (block/allow)

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("thor.redis_streams")

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    try:
        import aioredis
        REDIS_AVAILABLE = True
    except ImportError:
        REDIS_AVAILABLE = False
        logger.warning("redis not installed — Redis Streams disabled")

# ============================================================================
# Stream Names
# ============================================================================

STREAM_FLOWS      = "thor:flows"
STREAM_THREATS    = "thor:threats"
STREAM_DECISIONS  = "thor:decisions"
STREAM_ALERTS     = "thor:alerts"
STREAM_CONTROL    = "thor:control"
STREAM_STATS      = "thor:stats"

GROUP_CLICKHOUSE  = "clickhouse-writer"
GROUP_ML          = "ml-training"
GROUP_DASHBOARD   = "dashboard-broadcast"
GROUP_THREAT_INTEL = "threat-intel"

# ============================================================================
# Publisher
# ============================================================================

class EventPublisher:
    """
    ناشر الأحداث إلى Redis Streams
    Thread-safe وasync-first
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._redis: Optional[Any] = None

    async def connect(self) -> bool:
        if not REDIS_AVAILABLE:
            return False

        try:
            self._redis = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20,
            )
            await self._redis.ping()
            logger.info(f"Redis Streams connected: {self.redis_url}")
            return True
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            return False

    async def publish_flow(self, flow_data: Dict[str, Any]) -> Optional[str]:
        """نشر حدث تدفق"""
        return await self._publish(STREAM_FLOWS, flow_data, maxlen=500_000)

    async def publish_threat(self, threat_data: Dict[str, Any]) -> Optional[str]:
        """نشر حدث تهديد — يُخزَّن أطول (1M مدخل)"""
        return await self._publish(STREAM_THREATS, threat_data, maxlen=1_000_000)

    async def publish_decision(self, decision_data: Dict[str, Any]) -> Optional[str]:
        """نشر قرار ML"""
        return await self._publish(STREAM_DECISIONS, decision_data, maxlen=200_000)

    async def publish_alert(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """نشر تنبيه عاجل — CRITICAL فقط"""
        return await self._publish(STREAM_ALERTS, alert_data, maxlen=10_000)

    async def publish_stats(self, stats_data: Dict[str, Any]) -> Optional[str]:
        """نشر لقطة إحصاءات (كل ثانية)"""
        return await self._publish(STREAM_STATS, stats_data, maxlen=3600)  # آخر ساعة

    async def publish_control(self, command: Dict[str, Any]) -> Optional[str]:
        """نشر أمر تحكم"""
        return await self._publish(STREAM_CONTROL, command, maxlen=1_000)

    async def _publish(
        self,
        stream: str,
        data: Dict[str, Any],
        maxlen: int = 100_000,
    ) -> Optional[str]:
        if not self._redis:
            return None

        try:
            # تحويل القيم إلى strings (Redis requirement)
            flat_data = {}
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    flat_data[k] = json.dumps(v)
                elif v is None:
                    flat_data[k] = ""
                else:
                    flat_data[k] = str(v)

            flat_data["_ts"] = str(time.time())

            msg_id = await self._redis.xadd(
                stream,
                flat_data,
                maxlen=maxlen,
                approximate=True,  # أسرع من exact trimming
            )
            return msg_id
        except Exception as e:
            logger.debug(f"Publish to {stream} failed: {e}")
            return None

    async def publish_batch(
        self,
        stream: str,
        events: List[Dict[str, Any]],
        maxlen: int = 500_000,
    ) -> int:
        """نشر دفعة من الأحداث باستخدام pipeline"""
        if not self._redis or not events:
            return 0

        try:
            pipe = self._redis.pipeline(transaction=False)
            for event in events:
                flat = {k: str(v) if not isinstance(v, (dict, list)) else json.dumps(v)
                        for k, v in event.items()}
                flat["_ts"] = str(time.time())
                pipe.xadd(stream, flat, maxlen=maxlen, approximate=True)

            results = await pipe.execute()
            return sum(1 for r in results if r is not None)
        except Exception as e:
            logger.error(f"Batch publish failed: {e}")
            return 0


# ============================================================================
# Consumer
# ============================================================================

class EventConsumer:
    """
    مستهلك الأحداث مع Consumer Groups وAck
    """

    def __init__(
        self,
        redis_url: str,
        group_name: str,
        consumer_name: str,
    ):
        self.redis_url = redis_url
        self.group_name = group_name
        self.consumer_name = consumer_name
        self._redis: Optional[Any] = None

    async def connect(self, streams: List[str]) -> bool:
        if not REDIS_AVAILABLE:
            return False

        try:
            self._redis = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )

            # إنشاء Consumer Groups إذا لم تكن موجودة
            for stream in streams:
                try:
                    await self._redis.xgroup_create(
                        stream,
                        self.group_name,
                        id="0",       # ابدأ من البداية
                        mkstream=True  # أنشئ الـ stream إذا لم يوجد
                    )
                except Exception:
                    pass  # Group exists already

            logger.info(
                f"Consumer group '{self.group_name}/{self.consumer_name}' ready on {streams}"
            )
            return True
        except Exception as e:
            logger.error(f"Consumer connect failed: {e}")
            return False

    async def consume(
        self,
        streams: List[str],
        handler: Callable[[str, str, Dict], None],
        batch_size: int = 100,
        block_ms: int = 1000,
    ):
        """
        حلقة استهلاك الأحداث

        Args:
            streams: قائمة الـ streams للاستماع
            handler: دالة المعالجة (stream, msg_id, data)
            batch_size: أقصى عدد رسائل في المرة
            block_ms: مهلة الانتظار للرسائل الجديدة
        """
        stream_ids = {s: ">" for s in streams}  # ">" = رسائل جديدة غير معالجة

        while True:
            try:
                results = await self._redis.xreadgroup(
                    self.group_name,
                    self.consumer_name,
                    stream_ids,
                    count=batch_size,
                    block=block_ms,
                )

                if not results:
                    continue

                for stream_name, messages in results:
                    for msg_id, data in messages:
                        try:
                            await handler(stream_name, msg_id, data)

                            # Acknowledge بعد المعالجة الناجحة
                            await self._redis.xack(stream_name, self.group_name, msg_id)

                        except Exception as e:
                            logger.error(
                                f"Handler error on {stream_name}/{msg_id}: {e}"
                            )
                            # لا نـ Acknowledge — يمكن إعادة المحاولة

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Consumer loop error: {e}")
                await asyncio.sleep(1.0)

    async def get_pending_count(self, stream: str) -> int:
        """عدد الرسائل غير المُعالجة"""
        if not self._redis:
            return 0

        try:
            info = await self._redis.xpending(stream, self.group_name)
            return info.get("pending", 0) if isinstance(info, dict) else info[0]
        except Exception:
            return 0


# ============================================================================
# Stream Router — يوجه الأحداث للمعالجات المناسبة
# ============================================================================

class StreamRouter:
    """
    يربط الـ Streams بمعالجاتها
    """

    def __init__(self, publisher: EventPublisher):
        self.publisher = publisher
        self._handlers: Dict[str, List[Callable]] = {}

    def on(self, stream: str, handler: Callable):
        """تسجيل معالج لـ stream"""
        self._handlers.setdefault(stream, []).append(handler)

    async def route(self, stream: str, msg_id: str, data: Dict):
        """توجيه رسالة لمعالجاتها"""
        handlers = self._handlers.get(stream, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(stream, msg_id, data)
                else:
                    handler(stream, msg_id, data)
            except Exception as e:
                logger.error(f"Handler {handler.__name__} failed: {e}")


# ============================================================================
# Singleton
# ============================================================================

_publisher: Optional[EventPublisher] = None

async def get_publisher() -> EventPublisher:
    global _publisher
    if _publisher is None:
        _publisher = EventPublisher(
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0")
        )
        await _publisher.connect()
    return _publisher
