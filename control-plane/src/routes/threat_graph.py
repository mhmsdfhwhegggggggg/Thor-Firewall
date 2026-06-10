"""
Thor Firewall — Threat Graph API Routes
واجهة برمجية لـ Threat Graph (مكافئ CrowdStrike Threat Graph)

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/graph", tags=["Threat Graph"])


class FlowEventIn(BaseModel):
    src_ip:    str
    dst_ip:    str
    protocol:  str = "TCP"
    dst_port:  int = 0
    bytes:     int = 0
    risk_score: float = 0.0


class TagEventIn(BaseModel):
    node_id:  str
    tag:      str
    is_ioc:   bool = False


@router.post("/flows", summary="Ingest flow into threat graph")
async def ingest_flow(ev: FlowEventIn):
    try:
        from ..services.graph_builder import get_graph_builder
        gb = get_graph_builder()
        gb.add_flow(
            src_ip=ev.src_ip, dst_ip=ev.dst_ip,
            protocol=ev.protocol, dst_port=ev.dst_port,
            bytes_=ev.bytes, risk_score=ev.risk_score,
        )
        return {"status": "ingested", "src": ev.src_ip, "dst": ev.dst_ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tag", summary="Add threat tag to a node")
async def add_tag(ev: TagEventIn):
    try:
        from ..services.graph_builder import get_graph_builder
        get_graph_builder().add_threat_tag(ev.node_id, ev.tag, ev.is_ioc)
        return {"status": "tagged", "node_id": ev.node_id, "tag": ev.tag}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/neighbors/{node_id}", summary="Get node neighbors")
async def get_neighbors(
    node_id: str,
    depth:   int = Query(1, ge=1, le=3),
):
    try:
        from ..services.graph_builder import get_graph_builder
        result = get_graph_builder().get_neighbors(node_id, depth=depth)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/high-risk", summary="Get high-risk nodes")
async def high_risk_nodes(
    min_risk: float = Query(0.7, ge=0.0, le=1.0),
    limit:    int   = Query(100, ge=1, le=500),
):
    try:
        from ..services.graph_builder import get_graph_builder
        return {"nodes": get_graph_builder().get_high_risk_nodes(min_risk, limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ioc-nodes", summary="Get IOC-matching nodes")
async def ioc_nodes(limit: int = Query(200, ge=1, le=1000)):
    try:
        from ..services.graph_builder import get_graph_builder
        return {"nodes": get_graph_builder().get_ioc_nodes(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats", summary="Graph statistics")
async def graph_stats():
    try:
        from ..services.graph_builder import get_graph_builder
        return get_graph_builder().stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
