"""
Thor Firewall — Forensics API Routes
واجهة برمجية للتحليل الجنائي الشبكي

توفر:
  GET  /forensics/flows           — بحث في تدفقات الشبكة المُسجَّلة
  GET  /forensics/threats         — أحداث التهديدات التاريخية
  GET  /forensics/timeline        — سلسلة زمنية للإحصاءات
  GET  /forensics/top-talkers     — أكثر الـ IPs نشاطاً
  GET  /forensics/attack-heatmap  — خريطة جغرافية للهجمات
  GET  /forensics/ip/{ip}         — تحقيق شامل في IP
  GET  /forensics/export/{table}  — تصدير CSV للـ SIEM
  POST /forensics/hunt            — IoC Hunting (بحث بـ IOCs متعددة)
"""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, BackgroundTasks
from pydantic import BaseModel, Field, validator

from ..services.clickhouse import (
    ThorClickHouseClient,
    FlowRow, ThreatRow,
    get_clickhouse,
)

logger = logging.getLogger("thor.forensics")

router = APIRouter(prefix="/forensics", tags=["forensics"])


# ============================================================================
# Request / Response Models
# ============================================================================

class TimeRange(BaseModel):
    """نطاق زمني للاستعلام"""
    start: datetime
    end: datetime

    @validator("end")
    def end_after_start(cls, v, values):
        if "start" in values and v <= values["start"]:
            raise ValueError("end must be after start")
        return v

    @validator("start", "end", pre=True)
    def parse_dt(cls, v):
        if isinstance(v, str):
            # دعم ISO format بدون timezone (نفترض UTC)
            if v.endswith("Z"):
                v = v[:-1] + "+00:00"
            dt = datetime.fromisoformat(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        return v


class FlowQueryResponse(BaseModel):
    total: int
    offset: int
    limit: int
    flows: List[Dict[str, Any]]


class HuntRequest(BaseModel):
    """طلب IoC Hunting"""
    iocs: List[str] = Field(..., min_items=1, max_items=1000,
                            description="قائمة IoCs: IP addresses, CIDR blocks")
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    days_back: int = Field(7, ge=1, le=365)


class HuntResult(BaseModel):
    total_iocs: int
    matched_iocs: int
    total_flows: int
    total_threats: int
    matches: List[Dict[str, Any]]


# ============================================================================
# Helpers
# ============================================================================

def _resolve_time_range(
    start: Optional[str],
    end: Optional[str],
    hours_back: int = 24,
) -> tuple[datetime, datetime]:
    """يُحوّل معلمات الاستعلام إلى نطاق زمني"""
    now = datetime.now(tz=timezone.utc)

    if end:
        try:
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(400, f"Invalid end datetime: {end}")
    else:
        end_dt = now

    if start:
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(400, f"Invalid start datetime: {start}")
    else:
        start_dt = end_dt - timedelta(hours=hours_back)

    if start_dt >= end_dt:
        raise HTTPException(400, "start must be before end")

    max_range = timedelta(days=365)
    if (end_dt - start_dt) > max_range:
        raise HTTPException(400, "Time range cannot exceed 365 days")

    return start_dt, end_dt


def _validate_ip(ip: str) -> str:
    """التحقق من صحة عنوان IP"""
    try:
        return str(ipaddress.IPv4Address(ip))
    except ValueError:
        raise HTTPException(400, f"Invalid IPv4 address: {ip}")


# ============================================================================
# Endpoints
# ============================================================================

@router.get("/flows", response_model=FlowQueryResponse)
async def query_flows(
    start:    Optional[str] = Query(None, description="ISO 8601 datetime (UTC)"),
    end:      Optional[str] = Query(None, description="ISO 8601 datetime (UTC)"),
    hours:    int           = Query(24, ge=1, le=8760, description="ساعات سابقة (بديل لـ start/end)"),
    src_ip:   Optional[str] = Query(None, description="عنوان IP المصدر"),
    dst_ip:   Optional[str] = Query(None, description="عنوان IP الوجهة"),
    dst_port: Optional[int] = Query(None, ge=1, le=65535),
    protocol: Optional[str] = Query(None, regex="^(TCP|UDP|ICMP|tcp|udp|icmp)$"),
    min_risk: float         = Query(0.0, ge=0.0, le=1.0),
    decision: Optional[str] = Query(None, regex="^(allow|block|throttle|mirror|redirect)$"),
    limit:    int           = Query(100, ge=1, le=10000),
    offset:   int           = Query(0, ge=0),
    ch:       ThorClickHouseClient = Depends(get_clickhouse),
):
    """
    البحث في تدفقات الشبكة المُسجَّلة

    يدعم فلترة بـ: وقت، IP مصدر/وجهة، منفذ، بروتوكول، نقاط خطر، قرار
    """
    start_dt, end_dt = _resolve_time_range(start, end, hours)

    if src_ip:
        src_ip = _validate_ip(src_ip)
    if dst_ip:
        dst_ip = _validate_ip(dst_ip)

    flows = await ch.query_flows(
        start=start_dt, end=end_dt,
        src_ip=src_ip, dst_ip=dst_ip,
        dst_port=dst_port, protocol=protocol,
        min_risk=min_risk, decision=decision,
        limit=limit, offset=offset,
    )

    return FlowQueryResponse(
        total=len(flows),  # العدد الفعلي — TODO: count() منفصلة
        offset=offset,
        limit=limit,
        flows=flows,
    )


@router.get("/threats")
async def query_threats(
    start:        Optional[str] = Query(None),
    end:          Optional[str] = Query(None),
    hours:        int           = Query(24, ge=1, le=8760),
    severity:     Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
    threat_type:  Optional[str] = Query(None),
    src_ip:       Optional[str] = Query(None),
    mitre_tactic: Optional[str] = Query(None),
    limit:        int           = Query(200, ge=1, le=5000),
    ch:           ThorClickHouseClient = Depends(get_clickhouse),
):
    """
    استعلام أحداث التهديدات التاريخية

    يمكن الفلترة بالخطورة، نوع التهديد، IP المصدر، أو تكتيك MITRE ATT&CK
    """
    start_dt, end_dt = _resolve_time_range(start, end, hours)

    if src_ip:
        src_ip = _validate_ip(src_ip)

    threats = await ch.query_threats(
        start=start_dt, end=end_dt,
        severity=severity, threat_type=threat_type,
        src_ip=src_ip, mitre_tactic=mitre_tactic,
        limit=limit,
    )

    return {"total": len(threats), "threats": threats}


@router.get("/timeline")
async def get_timeline(
    start:       Optional[str] = Query(None),
    end:         Optional[str] = Query(None),
    hours:       int           = Query(24, ge=1, le=8760),
    granularity: str           = Query("5 MINUTE",
                                       regex=r"^(1 MINUTE|5 MINUTE|15 MINUTE|1 HOUR|1 DAY)$"),
    ch:          ThorClickHouseClient = Depends(get_clickhouse),
):
    """
    سلسلة زمنية للإحصاءات الشبكية

    granularity: 1 MINUTE | 5 MINUTE | 15 MINUTE | 1 HOUR | 1 DAY
    """
    start_dt, end_dt = _resolve_time_range(start, end, hours)
    timeline = await ch.query_timeline(start_dt, end_dt, granularity)
    return {"granularity": granularity, "points": len(timeline), "series": timeline}


@router.get("/top-talkers")
async def get_top_talkers(
    start:  Optional[str] = Query(None),
    end:    Optional[str] = Query(None),
    hours:  int           = Query(24, ge=1, le=8760),
    by:     str           = Query("bytes", regex="^(bytes|packets|flows)$"),
    limit:  int           = Query(20, ge=1, le=100),
    ch:     ThorClickHouseClient = Depends(get_clickhouse),
):
    """
    أكثر عناوين IP مصدراً للبيانات

    by: bytes (حجم البيانات) | packets (عدد الحزم) | flows (عدد الاتصالات)
    """
    start_dt, end_dt = _resolve_time_range(start, end, hours)
    talkers = await ch.query_top_talkers(start_dt, end_dt, by=by, limit=limit)
    return {"by": by, "limit": limit, "top_talkers": talkers}


@router.get("/attack-heatmap")
async def get_attack_heatmap(
    start: Optional[str] = Query(None),
    end:   Optional[str] = Query(None),
    hours: int           = Query(168, ge=1, le=8760),  # 7 أيام افتراضياً
    ch:    ThorClickHouseClient = Depends(get_clickhouse),
):
    """
    خريطة جغرافية للهجمات مجمّعة حسب دولة المصدر

    تستخدم لعرض heatmap على الخريطة العالمية في لوحة التحكم
    """
    start_dt, end_dt = _resolve_time_range(start, end, hours)
    heatmap = await ch.query_attack_heatmap(start_dt, end_dt)
    return {"countries": len(heatmap), "heatmap": heatmap}


@router.get("/ip/{ip}")
async def investigate_ip(
    ip:        str = ...,
    days_back: int = Query(30, ge=1, le=365),
    ch:        ThorClickHouseClient = Depends(get_clickhouse),
):
    """
    تحقيق شامل في عنوان IP

    يُرجع:
    - كل التدفقات المُسجَّلة
    - التهديدات المُكتشفة
    - الدول التي تواصل معها
    - أنماط السلوك (أوقات النشاط، المنافذ المُستهدفة)
    - قائمة بتقنيات MITRE ATT&CK المُرصودة
    """
    ip = _validate_ip(ip)
    investigation = await ch.search_ip(ip, days_back=days_back)

    # إضافة ملاحظة التقييم
    avg_risk = investigation.get("flows", {}).get("avg_risk", 0.0)
    threat_count = investigation.get("threats", {}).get("count", 0)

    if avg_risk >= 0.8 or threat_count >= 10:
        verdict = "HIGH_RISK — يُنصح بالحظر الفوري"
        verdict_severity = "critical"
    elif avg_risk >= 0.5 or threat_count >= 3:
        verdict = "MEDIUM_RISK — مراقبة مكثفة مطلوبة"
        verdict_severity = "high"
    elif avg_risk >= 0.2 or threat_count >= 1:
        verdict = "LOW_RISK — متابعة عادية"
        verdict_severity = "medium"
    else:
        verdict = "CLEAN — لم تُرصد أنشطة مشبوهة"
        verdict_severity = "low"

    investigation["verdict"] = verdict
    investigation["verdict_severity"] = verdict_severity

    return investigation


@router.post("/hunt", response_model=HuntResult)
async def ioc_hunt(
    request: HuntRequest,
    ch:      ThorClickHouseClient = Depends(get_clickhouse),
):
    """
    IoC Hunting — بحث عن مؤشرات اختراق متعددة في وقت واحد

    يقبل قائمة من:
    - عناوين IPv4 (مثل 1.2.3.4)
    - CIDR blocks (مثل 10.0.0.0/24)

    يُرجع جميع التدفقات والتهديدات التي تطابق أي IoC
    """
    import asyncio

    now = datetime.now(tz=timezone.utc)
    end_dt = request.end or now
    start_dt = request.start or (end_dt - timedelta(days=request.days_back))

    # التحقق والتصنيف
    ip_iocs: List[str] = []
    cidr_iocs: List[str] = []

    for ioc in request.iocs:
        ioc = ioc.strip()
        if not ioc:
            continue
        try:
            ipaddress.IPv4Address(ioc)
            ip_iocs.append(ioc)
        except ValueError:
            try:
                net = ipaddress.IPv4Network(ioc, strict=False)
                cidr_iocs.append(ioc)
            except ValueError:
                logger.warning("Skipping invalid IoC: %s", ioc)

    if not ip_iocs and not cidr_iocs:
        raise HTTPException(400, "No valid IPv4 IoCs provided")

    # بحث متوازٍ
    matches = []
    total_flows = 0
    total_threats = 0
    matched_iocs = set()

    tasks = []
    for ip in ip_iocs:
        tasks.append(ch.search_ip(ip, days_back=request.days_back))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for ip, result in zip(ip_iocs, results):
        if isinstance(result, Exception):
            logger.error("Hunt error for %s: %s", ip, result)
            continue

        f_count = result.get("flows", {}).get("count", 0)
        t_count = result.get("threats", {}).get("count", 0)

        if f_count > 0 or t_count > 0:
            matched_iocs.add(ip)
            total_flows   += f_count
            total_threats += t_count
            matches.append({
                "ioc": ip,
                "type": "ip",
                "flows": f_count,
                "threats": t_count,
                "avg_risk": result.get("flows", {}).get("avg_risk", 0.0),
                "threat_types": result.get("threats", {}).get("threat_types", []),
                "mitre_techniques": result.get("threats", {}).get("mitre_techniques", []),
            })

    # ترتيب حسب الخطورة
    matches.sort(key=lambda x: (x.get("threats", 0), x.get("avg_risk", 0)), reverse=True)

    return HuntResult(
        total_iocs=len(ip_iocs) + len(cidr_iocs),
        matched_iocs=len(matched_iocs),
        total_flows=total_flows,
        total_threats=total_threats,
        matches=matches,
    )


@router.get("/export/{table}")
async def export_data(
    table:  str,
    start:  Optional[str] = Query(None),
    end:    Optional[str] = Query(None),
    hours:  int           = Query(24, ge=1, le=168),
    format: str           = Query("csv", regex="^(csv)$"),
    ch:     ThorClickHouseClient = Depends(get_clickhouse),
):
    """
    تصدير بيانات بصيغة CSV

    table: thor_flows | thor_threats | thor_decisions
    يُستخدم لاستيراد البيانات في SIEM (Splunk, Elastic, QRadar)
    """
    valid = {"thor_flows", "thor_threats", "thor_decisions"}
    if table not in valid:
        raise HTTPException(400, f"Invalid table. Must be one of: {', '.join(valid)}")

    start_dt, end_dt = _resolve_time_range(start, end, hours)

    try:
        data = await ch.export_csv(table, start_dt, end_dt)
    except Exception as e:
        logger.error("Export failed: %s", e)
        raise HTTPException(500, f"Export failed: {str(e)}")

    filename = f"thor_{table}_{start_dt.strftime('%Y%m%d_%H%M')}_{end_dt.strftime('%Y%m%d_%H%M')}.csv"

    return Response(
        content=data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Thor-Export-Table": table,
            "X-Thor-Export-Rows": "unknown",
        },
    )


@router.get("/health")
async def forensics_health(
    ch: ThorClickHouseClient = Depends(get_clickhouse),
):
    """فحص صحة ClickHouse"""
    try:
        result = await ch._client.query("SELECT 1 AS ping")
        return {
            "status": "healthy",
            "clickhouse": "connected",
            "ping": result.result_rows[0][0] == 1,
        }
    except Exception as e:
        return {
            "status": "degraded",
            "clickhouse": "disconnected",
            "error": str(e),
        }
