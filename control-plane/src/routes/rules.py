"""
Thor Firewall — Firewall Rules Management API Routes
إدارة قواعد جدار الحماية: CRUD كامل مع validation و audit trail
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import time, uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, validator

router = APIRouter(tags=["Rules"])


class RuleCondition(BaseModel):
    field:    str         # src_ip | dst_port | protocol | risk_score
    operator: str         # eq | gt | lt | in | cidr_match
    value:    Any


class FirewallRule(BaseModel):
    rule_id:     Optional[str]   = None
    name:        str
    description: str             = ""
    priority:    int             = Field(100, ge=1, le=65535)
    conditions:  List[RuleCondition]
    action:      str             = "block"   # allow | block | rate_limit | alert
    enabled:     bool            = True
    created_at:  Optional[float] = None
    expires_at:  Optional[float] = None
    created_by:  str             = "system"
    hit_count:   int             = 0

    @validator("action")
    def validate_action(cls, v):
        if v not in ("allow", "block", "rate_limit", "alert", "redirect"):
            raise ValueError(f"Invalid action: {v}")
        return v


# In-memory store (in production → PostgreSQL/Redis)
_rules: Dict[str, dict] = {}


@router.get("/rules", summary="List firewall rules")
async def list_rules(
    enabled_only: bool = Query(False),
    action:       Optional[str] = Query(None),
    limit:        int = Query(100, ge=1, le=1000),
):
    rules = list(_rules.values())
    if enabled_only:
        rules = [r for r in rules if r.get("enabled")]
    if action:
        rules = [r for r in rules if r.get("action") == action]
    rules.sort(key=lambda r: r.get("priority", 100))
    return {
        "total": len(rules),
        "rules": rules[:limit],
    }


@router.post("/rules", summary="Create firewall rule", status_code=201)
async def create_rule(rule: FirewallRule):
    rule.rule_id   = str(uuid.uuid4())
    rule.created_at = time.time()
    _rules[rule.rule_id] = rule.dict()
    return {"status": "created", "rule_id": rule.rule_id, "rule": rule.dict()}


@router.get("/rules/{rule_id}", summary="Get rule by ID")
async def get_rule(rule_id: str):
    rule = _rules.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return rule


@router.put("/rules/{rule_id}", summary="Update rule")
async def update_rule(rule_id: str, updates: dict):
    if rule_id not in _rules:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    _rules[rule_id].update(updates)
    _rules[rule_id]["updated_at"] = time.time()
    return {"status": "updated", "rule": _rules[rule_id]}


@router.delete("/rules/{rule_id}", summary="Delete rule")
async def delete_rule(rule_id: str):
    if rule_id not in _rules:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    del _rules[rule_id]
    return {"status": "deleted", "rule_id": rule_id}


@router.post("/rules/{rule_id}/toggle", summary="Enable/disable rule")
async def toggle_rule(rule_id: str):
    if rule_id not in _rules:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    _rules[rule_id]["enabled"] = not _rules[rule_id].get("enabled", True)
    return {"status": "toggled", "enabled": _rules[rule_id]["enabled"]}


@router.post("/rules/bulk-import", summary="Import rules from JSON")
async def bulk_import(body: dict):
    rules = body.get("rules", [])
    imported = 0
    for r in rules:
        rule_id = str(uuid.uuid4())
        r["rule_id"]    = rule_id
        r["created_at"] = time.time()
        r.setdefault("enabled", True)
        _rules[rule_id] = r
        imported += 1
    return {"status": "imported", "count": imported}


@router.get("/rules/stats/summary", summary="Rules statistics")
async def rules_stats():
    rules = list(_rules.values())
    return {
        "total":        len(rules),
        "enabled":      sum(1 for r in rules if r.get("enabled")),
        "by_action":    {
            a: sum(1 for r in rules if r.get("action") == a)
            for a in ("allow", "block", "rate_limit", "alert")
        },
        "top_hits":     sorted(rules, key=lambda r: r.get("hit_count", 0), reverse=True)[:5],
    }
