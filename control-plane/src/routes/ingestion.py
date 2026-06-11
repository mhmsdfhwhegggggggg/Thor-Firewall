"""
Ingestion API Routes — Multi-format event ingestion endpoints
Splunk HEC-compatible + CEF/LEEF/Syslog/WinEvent + Thor native
"""
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status
from pydantic import BaseModel
import logging, os

router  = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])
logger  = logging.getLogger("thor.api.ingestion")
HEC_TOKEN = os.getenv("HEC_TOKEN", "thor-hec-token")

class RawIngestRequest(BaseModel):
    data: str
    format: str = "auto"
    tenant_id: str = "default"

@router.post("/event", status_code=status.HTTP_202_ACCEPTED,
             summary="Ingest a single event in any supported format")
async def ingest_event(payload: RawIngestRequest, request: Request):
    from ..ingestion.universal_ingester import UniversalIngester, LogFormat
    ingester: UniversalIngester = request.app.state.ingester
    fmt = LogFormat(payload.format) if payload.format != "auto" else LogFormat.JSON
    ids = await ingester.ingest_raw(
        payload.data, fmt=fmt,
        source_ip=request.client.host,
        tenant_id=payload.tenant_id,
    )
    return {"accepted": len(ids), "ids": ids}

@router.post("/batch", status_code=status.HTTP_202_ACCEPTED,
             summary="Ingest batch of events (newline-delimited JSON)")
async def ingest_batch(request: Request):
    body = await request.body()
    ingester = request.app.state.ingester
    from ..ingestion.universal_ingester import LogFormat
    ids = await ingester.ingest_raw(body, fmt=LogFormat.JSON,
                                     source_ip=request.client.host)
    return {"accepted": len(ids), "ids": ids}

# Splunk HEC-compatible endpoints
@router.post("/splunk/services/collector/event",
             summary="Splunk HEC-compatible event ingestion")
async def splunk_hec(request: Request, authorization: str = Header("")):
    token = authorization.removeprefix("Splunk ").strip()
    if token != HEC_TOKEN:
        raise HTTPException(status_code=403, detail={"text": "Invalid token", "code": 4})
    ingester = request.app.state.ingester
    return await ingester.ingest_splunk_hec(request, token)

@router.get("/stats", summary="Ingestion pipeline statistics")
async def ingestion_stats(request: Request):
    return request.app.state.ingester.get_stats()
