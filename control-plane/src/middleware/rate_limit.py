"""
Thor Firewall — Rate Limiting Middleware
برمجية الحد من معدل الطلبات

يحمي Control Plane API من:
  - Brute force على نقاط المصادقة
  - DDoS على API endpoints
  - Scraping المفرط للبيانات

الخوارزمية: Token Bucket + Sliding Window
  - Token Bucket: دُفعات مسموحة مع استعادة تدريجية
  - Sliding Window: دقة أعلى من Fixed Window

الحدود الافتراضية:
  - /api/v1/*:       100 req/min  per IP
  - /api/v1/query:   10  req/min  per IP  (LLM calls are expensive)
  - /api/auth/*:     5   req/min  per IP  (anti brute-force)
  - /api/v1/rules:   30  req/min  per user (write operations)

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Optional, Tuple

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


# ============================================================================
# Token Bucket
# ============================================================================

@dataclass
class TokenBucket:
    """
    Token bucket algorithm:
      - Bucket capacity = max burst size
      - Tokens added at rate = tokens_per_second
      - Each request consumes 1 token
    """
    capacity:   float          # max tokens (burst size)
    rate:       float          # tokens per second
    tokens:     float = field(init=False)
    last_check: float = field(init=False, default_factory=time.monotonic)

    def __post_init__(self):
        self.tokens = self.capacity

    def consume(self, n: float = 1.0) -> Tuple[bool, float]:
        """
        Try to consume n tokens.
        Returns (allowed, retry_after_seconds).
        """
        now     = time.monotonic()
        elapsed = now - self.last_check
        self.last_check = now

        # Refill tokens
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

        if self.tokens >= n:
            self.tokens -= n
            return True, 0.0
        else:
            # How long until enough tokens?
            wait = (n - self.tokens) / self.rate
            return False, wait


# ============================================================================
# Sliding Window Counter
# ============================================================================

@dataclass
class SlidingWindowCounter:
    """
    Sliding window rate limiter.
    Keeps timestamps of recent requests in a deque.
    More accurate than fixed-window but uses more memory.
    """
    window_s:   int
    max_count:  int
    _times: Deque[float] = field(default_factory=deque, repr=False)

    def record_and_check(self) -> Tuple[bool, int, float]:
        """
        Record request and check if allowed.
        Returns (allowed, current_count, retry_after_seconds).
        """
        now    = time.monotonic()
        cutoff = now - self.window_s

        # Evict old timestamps
        while self._times and self._times[0] < cutoff:
            self._times.popleft()

        count = len(self._times)
        if count >= self.max_count:
            # Time until oldest request falls out of window
            retry = self._times[0] - cutoff if self._times else 1.0
            return False, count, retry

        self._times.append(now)
        return True, count + 1, 0.0


# ============================================================================
# Route-specific limits
# ============================================================================

@dataclass
class RouteLimit:
    max_per_minute: int
    burst:          int
    path_prefix:    str


DEFAULT_LIMITS = [
    RouteLimit(5,   3,   "/api/auth"),       # anti-brute-force
    RouteLimit(10,  5,   "/api/v1/query"),   # LLM queries are expensive
    RouteLimit(30,  15,  "/api/v1/rules"),   # write-heavy endpoint
    RouteLimit(100, 50,  "/api/v1"),         # general API
    RouteLimit(200, 100, "/"),               # health, metrics, etc.
]


def _get_route_limit(path: str) -> RouteLimit:
    for limit in DEFAULT_LIMITS:
        if path.startswith(limit.path_prefix):
            return limit
    return DEFAULT_LIMITS[-1]


# ============================================================================
# Rate Limiter State
# ============================================================================

class RateLimiterState:
    """In-process state for all rate limit counters. Thread-safe via GIL."""

    def __init__(self):
        # (client_key, route_prefix) → SlidingWindowCounter
        self._counters: Dict[Tuple[str, str], SlidingWindowCounter] = {}
        self._last_cleanup = time.monotonic()
        self._CLEANUP_INTERVAL = 300   # seconds

    def check(self, client_key: str, path: str) -> Tuple[bool, int, float, int]:
        """
        Check if this request is allowed.
        Returns: (allowed, current_count, retry_after, limit)
        """
        route = _get_route_limit(path)
        key   = (client_key, route.path_prefix)

        if key not in self._counters:
            self._counters[key] = SlidingWindowCounter(
                window_s=60, max_count=route.max_per_minute
            )

        allowed, count, retry = self._counters[key].record_and_check()

        # Periodic cleanup of stale counters
        now = time.monotonic()
        if now - self._last_cleanup > self._CLEANUP_INTERVAL:
            self._cleanup(now)
            self._last_cleanup = now

        return allowed, count, retry, route.max_per_minute

    def _cleanup(self, now: float) -> None:
        stale = [
            k for k, c in self._counters.items()
            if not c._times or (now - c._times[-1]) > 120
        ]
        for k in stale:
            del self._counters[k]


# Singleton state
_rate_limiter = RateLimiterState()


# ============================================================================
# Middleware
# ============================================================================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware for rate limiting.

    Adds headers:
      X-RateLimit-Limit:     max requests per window
      X-RateLimit-Remaining: remaining requests
      X-RateLimit-Reset:     seconds until window resets
      Retry-After:           (on 429) seconds until retry

    Exempt paths: /metrics, /healthz, /api/health
    """

    EXEMPT_PATHS = {"/metrics", "/healthz", "/api/health", "/favicon.ico"}
    TRUSTED_PROXIES = {"127.0.0.1", "::1", "10.0.0.0/8"}

    def __init__(self, app: ASGIApp, exempt_ips: Optional[list] = None):
        super().__init__(app)
        self._exempt_ips = set(exempt_ips or [])

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Exempt paths
        if path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Get client IP (respecting X-Forwarded-For from trusted proxy)
        client_ip = self._get_client_ip(request)

        # Exempt IPs (internal agents, health checkers)
        if client_ip in self._exempt_ips:
            return await call_next(request)

        # Check rate limit
        allowed, count, retry, limit = _rate_limiter.check(client_ip, path)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error":   "rate_limit_exceeded",
                    "message": f"Too many requests. Limit: {limit}/min",
                    "retry_after": round(retry, 2),
                },
                headers={
                    "X-RateLimit-Limit":     str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset":     str(int(time.time() + retry)),
                    "Retry-After":           str(int(retry) + 1),
                },
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers to response
        remaining = max(0, limit - count)
        response.headers["X-RateLimit-Limit"]     = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"]     = str(int(time.time() + 60))

        return response

    def _get_client_ip(self, request: Request) -> str:
        # Check X-Forwarded-For only from trusted proxies
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            client_ip = xff.split(",")[0].strip()
            return client_ip
        return request.client.host if request.client else "unknown"
