"""
Thor Firewall — Case Management API
نقاط نهاية API لإدارة قضايا الأمن السيبراني

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import time, uuid
import logging
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("thor.api.cases")
router = APIRouter(prefix="/api/v1/cases", tags=["cases"])

# ──────────────────────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    title: str = Field(..., min_length=5, max_length=200)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    description: str = Field(..., min_length=10)
    assignee: Optional[str] = None
    sla_hours: int = Field(default=24, ge=1, le=720)
    incident_ids: List[str] = Field(default_factory=list)

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = Field(default=None, pattern="^(new|investigating|escalated|resolved|closed)$")
    assignee: Optional[str] = None
    notes: Optional[str] = None

class NoteCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=10_000)
    author: str

class CaseResponse(BaseModel):
    id: str; title: str; severity: str; status: str
    assignee: Optional[str]; created_at: float; updated_at: float
    description: str; notes: str; incident_count: int; sla_hours: int
    closed_at: Optional[float] = None

# ──────────────────────────────────────────────────────────────────────────────
# In-memory store (replace with ClickHouse in production)
# ──────────────────────────────────────────────────────────────────────────────

_cases: dict = {}

def _new_case(data: CaseCreate) -> dict:
    now = time.time()
    case_id = f"CASE-{str(uuid.uuid4())[:8].upper()}"
    return {
        "id": case_id, "title": data.title, "severity": data.severity,
        "status": "new", "assignee": data.assignee,
        "created_at": now, "updated_at": now,
        "description": data.description, "notes": "",
        "incident_count": len(data.incident_ids),
        "sla_hours": data.sla_hours,
        "incident_ids": data.incident_ids, "closed_at": None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[CaseResponse])
async def list_cases(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    assignee: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
):
    """قائمة القضايا مع فلترة"""
    cases = list(_cases.values())

    if status:
        cases = [c for c in cases if c["status"] == status]
    if severity:
        cases = [c for c in cases if c["severity"] == severity]
    if assignee:
        cases = [c for c in cases if c.get("assignee") == assignee]

    # Sort by severity then created_at
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    cases.sort(key=lambda c: (sev_order.get(c["severity"], 0), -c["created_at"]), reverse=True)

    return cases[offset:offset + limit]


@router.post("", response_model=CaseResponse, status_code=201)
async def create_case(data: CaseCreate):
    """إنشاء قضية جديدة"""
    case = _new_case(data)
    _cases[case["id"]] = case
    logger.info("Case created: %s | %s [%s]", case["id"], case["title"], case["severity"])
    return case


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(case_id: str):
    """تفاصيل قضية"""
    case = _cases.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case


@router.patch("/{case_id}", response_model=CaseResponse)
async def update_case(case_id: str, data: CaseUpdate):
    """تحديث حالة أو تفاصيل قضية"""
    case = _cases.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    updates = data.model_dump(exclude_none=True)
    for k, v in updates.items():
        case[k] = v
    case["updated_at"] = time.time()

    if data.status == "closed" and not case.get("closed_at"):
        case["closed_at"] = time.time()

    logger.info("Case updated: %s | status=%s", case_id, case["status"])
    return case


@router.post("/{case_id}/notes", response_model=CaseResponse)
async def add_note(case_id: str, note: NoteCreate):
    """إضافة ملاحظة تحقيق"""
    case = _cases.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    import datetime
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    new_note = f"\n---\n**{note.author}** @ {timestamp}\n{note.content}"
    case["notes"] = (case.get("notes") or "") + new_note
    case["updated_at"] = time.time()
    return case


@router.delete("/{case_id}", status_code=204)
async def close_case(case_id: str):
    """إغلاق قضية"""
    case = _cases.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    case["status"] = "closed"
    case["closed_at"] = time.time()
    case["updated_at"] = time.time()
    logger.info("Case closed: %s", case_id)


@router.get("/stats/summary")
async def cases_summary():
    """ملخص إحصائي للقضايا"""
    by_status = {}
    by_severity = {}
    for c in _cases.values():
        by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        by_severity[c["severity"]] = by_severity.get(c["severity"], 0) + 1

    return {
        "total": len(_cases),
        "by_status": by_status,
        "by_severity": by_severity,
        "avg_sla_hours": (sum(c["sla_hours"] for c in _cases.values()) / max(len(_cases), 1)),
    }
