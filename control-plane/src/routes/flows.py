"""
Thor Firewall — Flow Management API Routes
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
import time

router = APIRouter()


class FlowFilter(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    min_risk: Optional[float] = Field(None, ge=0.0, le=1.0)
    state: Optional[str] = None
    limit: int = Field(100, ge=1, le=10000)
    offset: int = Field(0, ge=0)


class FlowResponse(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    state: str
    risk_score: float
    packets: int
    bytes: int
    pps: float
    first_seen: float
    last_seen: float
    decision: Optional[str]
    explanation: Optional[str]
    tags: List[str]


class FlowListResponse(BaseModel):
    total: int
    flows: List[FlowResponse]
    page_info: dict


@router.get("/flows", response_model=FlowListResponse, summary="List active flows")
async def list_flows(
    request: Request,
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    protocol: Optional[str] = Query(None, description="tcp/udp/icmp"),
    min_risk: Optional[float] = Query(None, ge=0.0, le=1.0),
    state: Optional[str] = Query(None, description="allowed/blocked/suspicious/new"),
    limit: int = Query(100, ge=1, le=10000),
    offset: int = Query(0, ge=0),
):
    """
    List all active network flows with filtering and pagination.

    Returns flow details including AI risk scores and decisions.
    """
    redis = request.app.state.redis

    # Get flows from Redis
    pattern = "flow:*"
    flow_keys = await redis.keys(pattern)

    flows = []
    for key in flow_keys[offset:offset + limit]:
        flow_data = await redis.hgetall(key)
        if not flow_data:
            continue

        # Apply filters
        if src_ip and flow_data.get("src_ip") != src_ip:
            continue
        if dst_ip and flow_data.get("dst_ip") != dst_ip:
            continue
        if protocol and flow_data.get("protocol") != protocol:
            continue
        if state and flow_data.get("state") != state:
            continue
        risk = float(flow_data.get("risk_score", 0))
        if min_risk and risk < min_risk:
            continue

        flows.append(FlowResponse(
            flow_id=key.replace("flow:", ""),
            src_ip=flow_data.get("src_ip", ""),
            dst_ip=flow_data.get("dst_ip", ""),
            src_port=int(flow_data.get("src_port", 0)),
            dst_port=int(flow_data.get("dst_port", 0)),
            protocol=flow_data.get("protocol", ""),
            state=flow_data.get("state", "unknown"),
            risk_score=risk,
            packets=int(flow_data.get("packets", 0)),
            bytes=int(flow_data.get("bytes", 0)),
            pps=float(flow_data.get("pps", 0)),
            first_seen=float(flow_data.get("first_seen", 0)),
            last_seen=float(flow_data.get("last_seen", time.time())),
            decision=flow_data.get("decision"),
            explanation=flow_data.get("explanation"),
            tags=flow_data.get("tags", "").split(",") if flow_data.get("tags") else [],
        ))

    return FlowListResponse(
        total=len(flow_keys),
        flows=flows,
        page_info={"limit": limit, "offset": offset, "returned": len(flows)},
    )


@router.get("/flows/{flow_id}", response_model=FlowResponse, summary="Get flow details")
async def get_flow(flow_id: str, request: Request):
    """Get detailed information about a specific flow."""
    redis = request.app.state.redis
    flow_data = await redis.hgetall(f"flow:{flow_id}")

    if not flow_data:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")

    return FlowResponse(
        flow_id=flow_id,
        src_ip=flow_data.get("src_ip", ""),
        dst_ip=flow_data.get("dst_ip", ""),
        src_port=int(flow_data.get("src_port", 0)),
        dst_port=int(flow_data.get("dst_port", 0)),
        protocol=flow_data.get("protocol", ""),
        state=flow_data.get("state", "unknown"),
        risk_score=float(flow_data.get("risk_score", 0)),
        packets=int(flow_data.get("packets", 0)),
        bytes=int(flow_data.get("bytes", 0)),
        pps=float(flow_data.get("pps", 0)),
        first_seen=float(flow_data.get("first_seen", 0)),
        last_seen=float(flow_data.get("last_seen", time.time())),
        decision=flow_data.get("decision"),
        explanation=flow_data.get("explanation"),
        tags=flow_data.get("tags", "").split(",") if flow_data.get("tags") else [],
    )


@router.post("/flows/{flow_id}/block", summary="Manually block a flow")
async def block_flow(flow_id: str, reason: str, request: Request):
    """Manually block a flow (admin override)."""
    redis = request.app.state.redis

    await redis.hset(f"flow:{flow_id}", mapping={
        "state": "blocked",
        "decision": "block",
        "block_reason": reason,
        "blocked_at": str(time.time()),
        "blocked_by": "admin",
    })

    # Publish event for real-time update
    await redis.publish("thor:events", f'{{"type":"flow_blocked","flow_id":"{flow_id}","reason":"{reason}"}}')

    return {"status": "blocked", "flow_id": flow_id}


@router.delete("/flows/{flow_id}/block", summary="Unblock a flow")
async def unblock_flow(flow_id: str, request: Request):
    """Remove a manual block from a flow."""
    redis = request.app.state.redis

    await redis.hset(f"flow:{flow_id}", mapping={
        "state": "allowed",
        "decision": "allow",
    })

    return {"status": "unblocked", "flow_id": flow_id}
