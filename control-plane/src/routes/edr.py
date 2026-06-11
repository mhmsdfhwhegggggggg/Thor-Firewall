"""
EDR API Routes — Agent management, event stream, host actions
"""
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
import logging
from typing import Any

router = APIRouter(prefix="/api/v1/edr", tags=["edr"])
logger = logging.getLogger("thor.api.edr")

class EdrEventBatch(BaseModel):
    hostname:      str
    agent_version: str
    events:        list[dict]
    tenant_id:     str = "default"

class HostActionRequest(BaseModel):
    hostname: str
    action:   str   # isolate, unisolate, kill_process, collect_forensics
    params:   dict  = {}

@router.post("/events", status_code=status.HTTP_202_ACCEPTED,
             summary="Receive EDR event batch from agent")
async def receive_edr_events(batch: EdrEventBatch, request: Request):
    """Endpoint called by Rust EDR agents to submit telemetry"""
    ingester = request.app.state.ingester
    from ..ingestion.universal_ingester import LogFormat, NormalizedEvent
    import time, json

    ids = []
    for ev in batch.events:
        ev["source_host"] = batch.hostname
        ev["source_format"] = "edr_agent"
        ev["tenant_id"] = batch.tenant_id
        ids_batch = await ingester.ingest_raw(
            json.dumps(ev), fmt=LogFormat.JSON,
            source_ip=request.client.host,
            tenant_id=batch.tenant_id,
        )
        ids.extend(ids_batch)

    return {"accepted": len(ids), "hostname": batch.hostname}

@router.get("/agents", summary="List registered EDR agents")
async def list_agents(request: Request):
    """Return list of registered agents with last-seen timestamps"""
    # In production: query agent registry from Redis/Postgres
    return {"agents": [], "total": 0}

@router.post("/action", summary="Send action to EDR agent")
async def send_agent_action(action: HostActionRequest):
    """
    Send action to EDR agent (isolate, kill process, collect forensics).
    In production: publish to Redis pub/sub channel the agent subscribes to.
    """
    allowed = {"isolate", "unisolate", "kill_process", "collect_forensics", "run_scan"}
    if action.action not in allowed:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action.action}")

    logger.warning("Agent action: host=%s action=%s", action.hostname, action.action)
    return {
        "queued":   True,
        "hostname": action.hostname,
        "action":   action.action,
        "params":   action.params,
    }

@router.get("/process-tree/{hostname}", summary="Get live process tree for host")
async def process_tree(hostname: str, request: Request):
    """Request current process tree from EDR agent"""
    return {"hostname": hostname, "status": "requested", "processes": []}
