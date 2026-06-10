"""
Thor Firewall — Health Check Routes
Checks all system components: PostgreSQL, Redis, ClickHouse, ML, gRPC Agent.
"""
from __future__ import annotations
import asyncio
import logging
import os
import time

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Dict, Optional

from ..db.session import check_connection as check_db

logger = logging.getLogger("thor.health")
router = APIRouter(tags=["health"])


class ComponentHealth(BaseModel):
    status: str       # "ok" | "degraded" | "down"
    latency_ms: Optional[float] = None
    version:    Optional[str]   = None
    detail:     Optional[str]   = None


class HealthResponse(BaseModel):
    status:     str
    components: Dict[str, ComponentHealth]
    timestamp:  float
    version:    str = "1.0.0"


async def _check_redis(redis) -> ComponentHealth:
    try:
        t0   = time.perf_counter()
        pong = await redis.ping()
        ms   = (time.perf_counter() - t0) * 1000
        if pong:
            info = await redis.info("server")
            return ComponentHealth(status="ok", latency_ms=round(ms, 2),
                                   version=info.get("redis_version", "?"))
        return ComponentHealth(status="down", detail="ping failed")
    except Exception as e:
        return ComponentHealth(status="down", detail=str(e)[:100])


async def _check_clickhouse() -> ComponentHealth:
    url = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
    try:
        t0  = time.perf_counter()
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{url}/ping")
        ms  = (time.perf_counter() - t0) * 1000
        if r.status_code == 200:
            return ComponentHealth(status="ok", latency_ms=round(ms, 2))
        return ComponentHealth(status="degraded", detail=f"HTTP {r.status_code}")
    except Exception as e:
        return ComponentHealth(status="down", detail=str(e)[:100])


async def _check_ml_inference() -> ComponentHealth:
    url = os.environ.get("ML_INFERENCE_URL", "http://thor-ml:8080")
    try:
        t0  = time.perf_counter()
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(f"{url}/health")
        ms  = (time.perf_counter() - t0) * 1000
        if r.status_code == 200:
            data = r.json()
            return ComponentHealth(
                status     = "ok" if data.get("model_loaded") else "degraded",
                latency_ms = round(ms, 2),
                detail     = "model_not_loaded" if not data.get("model_loaded") else None,
            )
        return ComponentHealth(status="degraded", detail=f"HTTP {r.status_code}")
    except Exception as e:
        return ComponentHealth(status="down", detail=str(e)[:100])


async def _check_agent_grpc() -> ComponentHealth:
    url = os.environ.get("AGENT_GRPC_URL", "http://thor-agent:50051")
    try:
        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=3.0) as c:
            r  = await c.get(f"{url}/healthz")
        ms = (time.perf_counter() - t0) * 1000
        if r.status_code == 200:
            return ComponentHealth(status="ok", latency_ms=round(ms, 2))
        return ComponentHealth(status="degraded", detail=f"HTTP {r.status_code}")
    except Exception as e:
        return ComponentHealth(status="down", detail=str(e)[:100])


async def _check_postgres() -> ComponentHealth:
    try:
        t0  = time.perf_counter()
        ok  = await check_db()
        ms  = (time.perf_counter() - t0) * 1000
        if ok:
            return ComponentHealth(status="ok", latency_ms=round(ms, 2))
        return ComponentHealth(status="down", detail="connection failed")
    except Exception as e:
        return ComponentHealth(status="down", detail=str(e)[:100])


@router.get("/health", response_model=HealthResponse, summary="System health")
async def health(request: Request):
    redis = getattr(request.app.state, "redis", None)

    tasks = {
        "postgresql":   asyncio.create_task(_check_postgres()),
        "redis":        asyncio.create_task(_check_redis(redis) if redis else asyncio.coroutine(lambda: ComponentHealth(status="down", detail="not configured"))()),
        "clickhouse":   asyncio.create_task(_check_clickhouse()),
        "ml_inference": asyncio.create_task(_check_ml_inference()),
        "agent_grpc":   asyncio.create_task(_check_agent_grpc()),
    }

    results = {}
    for name, task in tasks.items():
        try:
            results[name] = await asyncio.wait_for(task, timeout=6.0)
        except asyncio.TimeoutError:
            results[name] = ComponentHealth(status="down", detail="timeout")
        except Exception as e:
            results[name] = ComponentHealth(status="down", detail=str(e)[:80])

    all_ok       = all(c.status == "ok"       for c in results.values())
    any_down     = any(c.status == "down"     for c in results.values())
    overall      = "ok" if all_ok else ("degraded" if not any_down else "degraded")

    return HealthResponse(
        status     = overall,
        components = results,
        timestamp  = time.time(),
    )


@router.get("/healthz", summary="Simple liveness probe")
async def healthz():
    """Kubernetes liveness probe — returns 200 if process is alive."""
    return {"status": "ok", "ts": time.time()}


@router.get("/readyz", summary="Readiness probe")
async def readyz(request: Request):
    """Kubernetes readiness probe — checks DB and Redis."""
    redis  = getattr(request.app.state, "redis", None)
    db_ok  = await check_db()
    red_ok = False
    if redis:
        try:
            red_ok = await asyncio.wait_for(redis.ping(), timeout=2.0)
        except Exception:
            pass

    ready = db_ok and red_ok
    return {"ready": ready, "db": db_ok, "redis": red_ok}
