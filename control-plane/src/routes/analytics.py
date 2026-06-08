"""Thor Firewall — Analytics API Routes"""
from typing import Optional
from fastapi import APIRouter, Request, Query
from pydantic import BaseModel

router = APIRouter()


class NetworkStats(BaseModel):
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bits_per_second: float
    active_flows: int
    blocked_flows: int
    suspicious_flows: int
    throughput_mbps: float
    avg_flow_duration_s: float


class SystemStats(BaseModel):
    agent_cpu_pct: float
    agent_memory_mb: float
    bpf_map_utilization: float
    rl_inference_latency_us: float
    llm_queries_per_min: float


@router.get("/analytics/network", response_model=NetworkStats, summary="Network statistics")
async def network_stats(request: Request):
    """Real-time network statistics from the agent."""
    redis = request.app.state.redis

    data = await redis.hgetall("stats:network")

    return NetworkStats(
        total_packets=int(data.get("total_packets", 0)),
        total_bytes=int(data.get("total_bytes", 0)),
        packets_per_second=float(data.get("pps", 0)),
        bits_per_second=float(data.get("bps", 0)),
        active_flows=int(data.get("active_flows", 0)),
        blocked_flows=int(data.get("blocked_flows", 0)),
        suspicious_flows=int(data.get("suspicious_flows", 0)),
        throughput_mbps=float(data.get("throughput_mbps", 0)),
        avg_flow_duration_s=float(data.get("avg_flow_duration_s", 0)),
    )


@router.get("/analytics/system", response_model=SystemStats, summary="System statistics")
async def system_stats(request: Request):
    """Agent and system resource usage."""
    redis = request.app.state.redis
    data = await redis.hgetall("stats:system")

    return SystemStats(
        agent_cpu_pct=float(data.get("agent_cpu_pct", 0)),
        agent_memory_mb=float(data.get("agent_memory_mb", 0)),
        bpf_map_utilization=float(data.get("bpf_map_utilization", 0)),
        rl_inference_latency_us=float(data.get("rl_inference_latency_us", 0)),
        llm_queries_per_min=float(data.get("llm_queries_per_min", 0)),
    )


@router.get("/analytics/top-threats", summary="Top threat sources")
async def top_threats(
    request: Request,
    window_hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=100),
):
    """Get top threat sources and attack patterns."""
    redis = request.app.state.redis
    data = await redis.zrevrange("stats:top_attackers", 0, limit - 1, withscores=True)
    return [{"ip": ip, "threat_count": int(score)} for ip, score in data]
