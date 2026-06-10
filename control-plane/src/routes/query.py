"""
Thor ThorQL — Query API Routes
نقاط نهاية REST لتنفيذ ThorQL queries
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from ..thorql.executor import ThorQLExecutor, ThorQLParser
from ..thorql.saved_hunts import BUILT_IN_HUNTS

router = APIRouter(prefix="/api/v1/query", tags=["ThorQL"])

# Executor singleton (ClickHouse client injected via dependency injection later)
_executor = ThorQLExecutor(clickhouse_client=None, soar_engine=None)


class QueryRequest(BaseModel):
    query:     str
    format:    str = "json"   # json | csv | table
    explain:   bool = False    # إعادة الـ SQL المُولَّد


class QueryResponse(BaseModel):
    query:        str
    sql:          Optional[str] = None
    rows:         list = []
    row_count:    int = 0
    latency_ms:   float = 0.0
    alert_triggered: Optional[str] = None
    soar_triggered:  Optional[str] = None
    error:        Optional[str] = None


@router.post("/execute", response_model=QueryResponse, summary="Execute a ThorQL query")
async def execute_query(req: QueryRequest):
    """
    نفّذ ThorQL query وأعد النتائج.

    أمثلة:
    - `flows WHERE dst_port = 22 LAST 1h | SORT BY risk_score DESC | LIMIT 20`
    - `threats WHERE severity = "critical" LAST 24h`
    - `flows WHERE risk_score > 0.8 LAST 4h | GROUP BY src_ip | SORT BY count DESC`
    """
    try:
        result = await _executor.execute(req.query)
        return QueryResponse(
            query          = req.query,
            sql            = result["sql"] if req.explain else None,
            rows           = result.get("rows", []),
            row_count      = result.get("row_count", 0),
            latency_ms     = result.get("latency_ms", 0),
            alert_triggered= result.get("alert_triggered"),
            soar_triggered = result.get("soar_triggered"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query execution failed: {e}")


@router.get("/explain", summary="Parse and explain a ThorQL query without executing")
async def explain_query(q: str):
    """
    حلّل ThorQL query وأعد الـ SQL المُولَّد بدون تنفيذ.
    مفيد للتحقق من صحة الـ query قبل التنفيذ.
    """
    parser     = ThorQLParser()
    from ..thorql.executor import ThorQLTranspiler
    transpiler = ThorQLTranspiler()
    try:
        pq  = parser.parse(q)
        sql = transpiler.to_sql(pq)
        return {
            "original":  q,
            "parsed": {
                "source":       pq.source,
                "table":        pq.table,
                "where":        pq.where_clauses,
                "time_window":  pq.time_seconds,
                "group_by":     pq.group_by,
                "sort_by":      pq.sort_by,
                "sort_desc":    pq.sort_desc,
                "limit":        pq.limit,
                "has_enrich":   pq.enrich,
                "has_alert":    pq.alert_msg is not None,
                "has_soar":     pq.soar_action is not None,
            },
            "generated_sql": sql,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/hunts", summary="List built-in threat hunting queries")
async def list_hunts():
    """
    أعد مكتبة استعلامات الصيد الجاهزة.
    كل استعلام مرتبط بـ MITRE ATT&CK ID.
    """
    return {
        "hunts": [
            {
                "id":          hid,
                "name":        h.name,
                "description": h.description,
                "mitre_id":    h.mitre_id,
                "severity":    h.severity,
                "query":       h.query.strip(),
            }
            for hid, h in BUILT_IN_HUNTS.items()
        ],
        "total": len(BUILT_IN_HUNTS),
    }


@router.post("/hunts/{hunt_id}/execute", summary="Execute a saved threat hunt")
async def execute_hunt(hunt_id: str):
    """نفّذ استعلام صيد محفوظ"""
    if hunt_id not in BUILT_IN_HUNTS:
        raise HTTPException(status_code=404,
                             detail=f"Hunt '{hunt_id}' not found. Available: {list(BUILT_IN_HUNTS.keys())}")
    hunt = BUILT_IN_HUNTS[hunt_id]
    try:
        result = await _executor.execute(hunt.query.strip())
        return {
            "hunt_id":    hunt_id,
            "hunt_name":  hunt.name,
            "mitre_id":   hunt.mitre_id,
            "rows":       result.get("rows", []),
            "row_count":  result.get("row_count", 0),
            "latency_ms": result.get("latency_ms", 0),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
