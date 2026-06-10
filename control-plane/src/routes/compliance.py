"""
Thor Firewall — Compliance API Routes
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])


@router.get("/evaluate", summary="Auto-evaluate compliance across all frameworks")
async def evaluate_compliance(
    frameworks: str = Query("soc2,iso27001,nca_ecc",
                            description="Comma-separated frameworks: soc2,iso27001,nca_ecc")
):
    try:
        from ..compliance.auto_evaluator import ComplianceAutoEvaluator
        fw_list   = [f.strip() for f in frameworks.split(",")]
        evaluator = ComplianceAutoEvaluator()
        reports   = await evaluator.evaluate(fw_list)
        return {
            "frameworks": {
                name: evaluator.to_dict(report)
                for name, report in reports.items()
            },
            "summary": {
                name: {
                    "score":  report.overall_score,
                    "pass":   report.pass_count,
                    "fail":   report.fail_count,
                    "partial": report.partial_count,
                }
                for name, report in reports.items()
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/soc2", summary="SOC2 Type II evaluation")
async def soc2():
    try:
        from ..compliance.auto_evaluator import SOC2AutoEvaluator, ComplianceAutoEvaluator
        report    = await SOC2AutoEvaluator().evaluate_all()
        evaluator = ComplianceAutoEvaluator()
        return evaluator.to_dict(report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/iso27001", summary="ISO 27001:2022 evaluation")
async def iso27001():
    try:
        from ..compliance.auto_evaluator import ISO27001AutoEvaluator, ComplianceAutoEvaluator
        report    = await ISO27001AutoEvaluator().evaluate_all()
        evaluator = ComplianceAutoEvaluator()
        return evaluator.to_dict(report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nca-ecc", summary="NCA-ECC (Saudi Arabia) evaluation")
async def nca_ecc():
    try:
        from ..compliance.auto_evaluator import NCAECCAutoEvaluator, ComplianceAutoEvaluator
        report    = await NCAECCAutoEvaluator().evaluate_all()
        evaluator = ComplianceAutoEvaluator()
        return evaluator.to_dict(report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/evidence", summary="Collect compliance evidence")
async def collect_evidence():
    try:
        from ..compliance.evidence_collector import EvidenceCollector
        collector = EvidenceCollector()
        evidences = await collector.collect_all()
        return {
            "evidence_count": len(evidences),
            "evidences":      [e.to_dict() for e in evidences],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard", summary="Compliance dashboard summary")
async def compliance_dashboard():
    try:
        from ..compliance.auto_evaluator import ComplianceAutoEvaluator
        evaluator = ComplianceAutoEvaluator()
        reports   = await evaluator.evaluate(["soc2", "iso27001", "nca_ecc"])
        return {
            "overall_compliance": round(
                sum(r.overall_score for r in reports.values()) / max(len(reports), 1), 1
            ),
            "frameworks": {
                name: {
                    "score":   report.overall_score,
                    "pass":    report.pass_count,
                    "fail":    report.fail_count,
                    "partial": report.partial_count,
                    "status":  "PASS" if report.overall_score >= 80 else "FAIL",
                }
                for name, report in reports.items()
            },
            "requires_attention": [
                {
                    "framework":   name,
                    "control_id":  c.control_id,
                    "control_name": c.control_name,
                    "score":       c.score_pct,
                    "remediation": c.remediation,
                }
                for name, report in reports.items()
                for c in report.controls
                if c.score < 0.8 and c.remediation
            ][:10],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
