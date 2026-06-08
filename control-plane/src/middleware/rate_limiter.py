"""
Thor Firewall — Rate Limiter Middleware
حماية من هجمات brute-force و DDoS على الـ API

الحدود الافتراضية:
- /api/auth/login:    10 طلبات/دقيقة لكل IP
- /api/v1/threats:    1000 طلبات/دقيقة لكل مستخدم
- /api/v1/*:          200 طلبات/دقيقة لكل مستخدم
- عام:                100 طلبات/دقيقة لكل IP

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, time
from collections import defaultdict
from typing import Dict, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("thor.middleware.ratelimit")


class SlidingWindowCounter:
    """نافذة منزلقة لحساب الطلبات — O(1) memory per bucket"""
    def __init__(self):
        self._buckets: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

    def is_allowed(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
        now = int(time.time())
        window_start = now - window_seconds
        bucket = self._buckets[key]

        # تنظيف القديم
        old_keys = [t for t in bucket if t < window_start]
        for k in old_keys:
            del bucket[k]

        total = sum(bucket.values())
        if total >= limit:
            retry_after = window_seconds - (now - min(bucket.keys(), default=now))
            return False, max(1, retry_after)

        bucket[now] += 1
        return True, 0


_counter = SlidingWindowCounter()

RATE_LIMITS = {
    "/api/auth/login":    (10,   60),   # limit, window_seconds
    "/api/auth/register": (5,    60),
    "/api/v1/threats":    (1000, 60),
    "/api/v1/":           (200,  60),
    "default":            (100,  60),
}


def _get_limit(path: str) -> Tuple[int, int]:
    for prefix, (limit, window) in RATE_LIMITS.items():
        if path.startswith(prefix):
            return limit, window
    return RATE_LIMITS["default"]


def _get_client_key(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    ip = forwarded_for.split(",")[0].strip() if forwarded_for else request.client.host
    user = getattr(getattr(request, "state", None), "user", None)
    user_id = user.sub if user else "anonymous"
    return f"{user_id}:{ip}"


async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if path in ("/health", "/metrics", "/docs", "/openapi.json"):
        return await call_next(request)

    limit, window = _get_limit(path)
    key = f"{path}:{_get_client_key(request)}"
    allowed, retry_after = _counter.is_allowed(key, limit, window)

    if not allowed:
        logger.warning("Rate limit exceeded: %s (path=%s)", key.split(":")[0], path)
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Too many requests",
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after), "X-RateLimit-Limit": str(limit)},
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"]   = str(limit)
    response.headers["X-RateLimit-Window"]  = str(window)
    return response
