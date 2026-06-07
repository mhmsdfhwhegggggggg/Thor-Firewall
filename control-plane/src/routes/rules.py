"""Thor Firewall — Firewall Rules API Routes"""
import time
import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter()


class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    src_ip: Optional[str] = None
    src_cidr: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_cidr: Optional[str] = None
    dst_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = None
    action: str = Field(..., pattern="^(allow|block|throttle|mirror)$")
    priority: int = Field(100, ge=1, le=65535)
    expires_at: Optional[float] = None


class RuleResponse(RuleCreate):
    rule_id: str
    created_at: float
    hit_count: int = 0
    is_active: bool = True


@router.get("/rules", response_model=List[RuleResponse], summary="List all rules")
async def list_rules(request: Request):
    """List all active firewall rules ordered by priority."""
    redis = request.app.state.redis
    keys = await redis.keys("rule:*")
    rules = []
    for key in keys:
        data = await redis.hgetall(key)
        if data:
            rules.append(RuleResponse(**{k: v for k, v in data.items()}, rule_id=key.replace("rule:", "")))
    rules.sort(key=lambda r: r.priority)
    return rules


@router.post("/rules", response_model=RuleResponse, status_code=201, summary="Create a rule")
async def create_rule(rule: RuleCreate, request: Request):
    """Create a new firewall rule. Higher priority number = higher priority."""
    redis = request.app.state.redis
    rule_id = str(uuid.uuid4())[:8]
    now = time.time()

    data = rule.model_dump()
    data.update({"rule_id": rule_id, "created_at": str(now), "hit_count": "0", "is_active": "true"})
    data = {k: str(v) if v is not None else "" for k, v in data.items()}

    await redis.hset(f"rule:{rule_id}", mapping=data)

    # Notify agents of new rule
    await redis.publish("thor:events", f'{{"type":"rule_created","rule_id":"{rule_id}","action":"{rule.action}"}}')

    return RuleResponse(**rule.model_dump(), rule_id=rule_id, created_at=now)


@router.delete("/rules/{rule_id}", summary="Delete a rule")
async def delete_rule(rule_id: str, request: Request):
    """Delete a firewall rule."""
    redis = request.app.state.redis
    result = await redis.delete(f"rule:{rule_id}")
    if result == 0:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    await redis.publish("thor:events", f'{{"type":"rule_deleted","rule_id":"{rule_id}"}}')
    return {"status": "deleted", "rule_id": rule_id}


@router.post("/rules/{rule_id}/toggle", summary="Enable or disable a rule")
async def toggle_rule(rule_id: str, request: Request):
    """Toggle a rule on or off."""
    redis = request.app.state.redis
    current = await redis.hget(f"rule:{rule_id}", "is_active")
    if current is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    new_state = "false" if current == "true" else "true"
    await redis.hset(f"rule:{rule_id}", "is_active", new_state)
    return {"rule_id": rule_id, "is_active": new_state == "true"}
