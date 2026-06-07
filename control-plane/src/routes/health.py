"""Thor Firewall — Health Check Routes"""
import time
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Dict

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    components: Dict[str, str]


_start_time = time.time()


@router.get("/health", response_model=HealthResponse, summary="Health check")
async def health_check(request: Request):
    """
    System health check endpoint.
    Returns status of all components.
    """
    components = {}

    # Check Redis
    try:
        await request.app.state.redis.ping()
        components["redis"] = "healthy"
    except Exception as e:
        components["redis"] = f"unhealthy: {e}"

    # TODO: Check ClickHouse, Agent gRPC, LLM server
    components["clickhouse"] = "not_configured"
    components["agent_grpc"] = "not_configured"
    components["llm_server"] = "not_configured"

    all_healthy = all(v == "healthy" or v == "not_configured" for v in components.values())

    return HealthResponse(
        status="healthy" if all_healthy else "degraded",
        version="0.1.0",
        uptime_seconds=time.time() - _start_time,
        components=components,
    )


@router.get("/health/ready", summary="Readiness check")
async def readiness():
    """Kubernetes readiness probe."""
    return {"ready": True}


@router.get("/health/live", summary="Liveness check")
async def liveness():
    """Kubernetes liveness probe."""
    return {"alive": True}
