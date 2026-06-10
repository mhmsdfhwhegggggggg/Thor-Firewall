"""
Thor Firewall — Reporting API Routes
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import time
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


@router.get("/compliance", summary="Generate compliance report (JSON)")
async def compliance_report(
    framework: str = Query("all", description="soc2 | iso27001 | nca_ecc | all"),
    evidence:  bool = Query(True),
):
    try:
        from ..reporting.report_engine import get_report_engine
        engine = get_report_engine()
        report = await engine.build_compliance_report(framework, include_evidence=evidence)
        return {"report": {"title": report.title, "report_type": report.report_type,
                           "generated_at": report.generated_at, "metadata": report.metadata,
                           "sections": [{"title": s.title, "content": s.content}
                                        for s in report.sections]}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compliance.html", summary="Generate compliance report (HTML)", response_class=HTMLResponse)
async def compliance_report_html(framework: str = Query("all")):
    try:
        from ..reporting.report_engine import get_report_engine
        engine = get_report_engine()
        report = await engine.build_compliance_report(framework)
        return HTMLResponse(content=engine.to_html(report))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/executive", summary="Weekly executive summary (JSON)")
async def executive_report(period_days: int = Query(7)):
    try:
        from ..reporting.report_engine import get_report_engine
        engine = get_report_engine()
        report = await engine.build_executive_summary(period_days)
        return {"report": {"title": report.title, "report_type": report.report_type,
                           "generated_at": report.generated_at, "metadata": report.metadata,
                           "sections": [{"title": s.title, "content": s.content}
                                        for s in report.sections]}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/executive.html", summary="Weekly executive summary (HTML)", response_class=HTMLResponse)
async def executive_report_html(period_days: int = Query(7)):
    try:
        from ..reporting.report_engine import get_report_engine
        engine = get_report_engine()
        report = await engine.build_executive_summary(period_days)
        return HTMLResponse(content=engine.to_html(report))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
