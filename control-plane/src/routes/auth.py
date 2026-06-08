"""
Thor Firewall — Authentication Routes
نقاط نهاية التوثيق: تسجيل دخول، تجديد token، تسجيل خروج

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, time, uuid
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

from ..auth.jwt_handler import (
    UserRole, create_access_token, create_refresh_token,
    hash_password, verify_password, verify_token, revoke_token,
    generate_api_key,
)
from ..auth.rbac import Permission, require_permission

logger = logging.getLogger("thor.routes.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])
security = HTTPBearer()

# ── In-memory user store (استبدل بـ PostgreSQL) ───────────────────────────────
_USERS: Dict[str, dict] = {
    "admin@thor.local": {
        "id":            "usr_admin_001",
        "email":         "admin@thor.local",
        "hashed_pw":     hash_password("Thor@Admin2024!"),
        "role":          UserRole.ADMIN,
        "name":          "Thor Admin",
        "active":        True,
        "created_at":    time.time(),
        "last_login":    None,
    },
    "analyst@thor.local": {
        "id":            "usr_analyst_001",
        "email":         "analyst@thor.local",
        "hashed_pw":     hash_password("Analyst@2024!"),
        "role":          UserRole.ANALYST,
        "name":          "SOC Analyst",
        "active":        True,
        "created_at":    time.time(),
        "last_login":    None,
    },
}

# Active refresh tokens (استبدل بـ Redis)
_REFRESH_TOKENS: Dict[str, str] = {}   # token → user_id


# ── Schemas ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=8)

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=12, description="Min 12 chars, must include upper/lower/digit/special")
    name: str = Field(..., min_length=2, max_length=100)
    role: UserRole = UserRole.READONLY
    invite_token: Optional[str] = None   # مطلوب للإنتاج

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class RefreshRequest(BaseModel):
    refresh_token: str

class ApiKeyResponse(BaseModel):
    api_key: str
    key_id: str
    note: str = "Store this key securely — it won't be shown again"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request):
    user = _USERS.get(req.email)
    if not user or not verify_password(req.password, user["hashed_pw"]):
        logger.warning("Failed login attempt: %s from %s", req.email, request.client.host)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user["active"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    user["last_login"] = time.time()
    access  = create_access_token(user["id"], user["role"], user["email"])
    refresh = create_refresh_token(user["id"], user["role"])
    _REFRESH_TOKENS[refresh] = user["id"]

    logger.info("User logged in: %s (role=%s)", user["email"], user["role"].value)

    return TokenResponse(
        access_token=access, refresh_token=refresh, expires_in=900,
        user={"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"].value},
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest):
    try:
        payload = verify_token(req.refresh_token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if payload.token_type != "refresh":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Not a refresh token")

    user_id = _REFRESH_TOKENS.get(req.refresh_token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found or expired")

    # Rotate refresh token
    revoke_token(req.refresh_token)
    del _REFRESH_TOKENS[req.refresh_token]

    user = next((u for u in _USERS.values() if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_access  = create_access_token(user["id"], user["role"], user["email"])
    new_refresh = create_refresh_token(user["id"], user["role"])
    _REFRESH_TOKENS[new_refresh] = user["id"]

    return TokenResponse(
        access_token=new_access, refresh_token=new_refresh, expires_in=900,
        user={"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"].value},
    )


@router.post("/logout", status_code=204)
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    revoke_token(credentials.credentials)


@router.post("/register", response_model=dict, status_code=201)
async def register(req: RegisterRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """تسجيل مستخدم جديد — يتطلب دور admin"""
    caller = verify_token(credentials.credentials)
    if caller.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can register users")

    if req.email in _USERS:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    # Password strength
    pw = req.password
    if not any(c.isupper() for c in pw) or not any(c.isdigit() for c in pw) or not any(c in "!@#$%^&*" for c in pw):
        raise HTTPException(status_code=422, detail="Password must contain uppercase, digit and special character")

    user_id = f"usr_{uuid.uuid4().hex[:8]}"
    _USERS[req.email] = {
        "id": user_id, "email": req.email,
        "hashed_pw": hash_password(req.password),
        "role": req.role, "name": req.name,
        "active": True, "created_at": time.time(), "last_login": None,
    }
    logger.info("New user registered: %s (role=%s) by %s", req.email, req.role.value, caller.sub)
    return {"id": user_id, "email": req.email, "role": req.role.value}


@router.post("/agents/keys", response_model=ApiKeyResponse)
async def create_agent_key(
    node_name: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """إنشاء API key لـ agent جديد — يتطلب admin"""
    caller = verify_token(credentials.credentials)
    if caller.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin only")

    raw_key, hashed_key = generate_api_key()
    key_id = f"key_{uuid.uuid4().hex[:8]}"

    from ..middleware.auth_middleware import register_agent_key
    agent_id = f"agent_{uuid.uuid4().hex[:8]}"
    register_agent_key(hashed_key, agent_id, node_name)

    logger.info("Agent key created: node=%s id=%s by=%s", node_name, agent_id, caller.sub)
    return ApiKeyResponse(api_key=raw_key, key_id=key_id)


@router.get("/me")
async def get_me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = verify_token(credentials.credentials)
    user = next((u for u in _USERS.values() if u["id"] == token.sub), None)
    if not user:
        return {"id": token.sub, "role": token.role.value, "type": token.token_type}
    return {
        "id": user["id"], "email": user["email"],
        "name": user["name"], "role": user["role"].value,
        "last_login": user["last_login"],
    }
