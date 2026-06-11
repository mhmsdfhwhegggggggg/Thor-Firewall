"""
Cloud Security API Routes — Trigger/poll AWS+Azure collectors, get cloud findings
"""
from fastapi import APIRouter, BackgroundTasks, Request
from pydantic import BaseModel
import logging

router = APIRouter(prefix="/api/v1/cloud", tags=["cloud"])
logger = logging.getLogger("thor.api.cloud")

class CollectRequest(BaseModel):
    provider:       str   # aws | azure
    lookback_hours: int   = 1
    tenant_id:      str   = "default"

@router.post("/collect", summary="Trigger cloud security event collection")
async def trigger_collection(req: CollectRequest, background_tasks: BackgroundTasks,
                              request: Request):
    """Kick off async cloud collection for AWS or Azure"""
    if req.provider == "aws":
        from ..cloud.aws_collector import AWSCollector
        collector = AWSCollector(lookback_hours=req.lookback_hours)
        background_tasks.add_task(_collect_aws, collector, request.app.state.ingester)
    elif req.provider == "azure":
        from ..cloud.azure_collector import AzureCollector
        collector = AzureCollector(lookback_hours=req.lookback_hours)
        background_tasks.add_task(_collect_azure, collector, request.app.state.ingester)
    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown provider: {req.provider}")

    return {"status": "started", "provider": req.provider, "lookback_hours": req.lookback_hours}

@router.get("/status", summary="Cloud collection status")
async def collection_status():
    return {"aws": {"status": "idle"}, "azure": {"status": "idle"}}

async def _collect_aws(collector, ingester):
    import json
    from ..ingestion.universal_ingester import LogFormat
    count = 0
    async for event in collector.collect_cloudtrail():
        await ingester.ingest_raw(json.dumps(event), fmt=LogFormat.JSON)
        count += 1
    async for event in collector.collect_guardduty():
        await ingester.ingest_raw(json.dumps(event), fmt=LogFormat.JSON)
        count += 1
    logger.info("AWS collection complete: %d events", count)

async def _collect_azure(collector, ingester):
    import json
    from ..ingestion.universal_ingester import LogFormat
    count = 0
    async for event in collector.collect_signin_logs():
        await ingester.ingest_raw(json.dumps(event), fmt=LogFormat.JSON)
        count += 1
    async for event in collector.collect_audit_logs():
        await ingester.ingest_raw(json.dumps(event), fmt=LogFormat.JSON)
        count += 1
    logger.info("Azure collection complete: %d events", count)
