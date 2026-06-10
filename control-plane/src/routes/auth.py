"""
Thor Firewall — Auth API Routes
JWT/OIDC authentication + Keycloak integration
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import hashlib, hmac, os, time, uuid
from typing import Optional
from fastapi import APIRouter, HTTPException, Header, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

router  = APIRouter(prefix="/api/v1/auth", tags=["Auth"])
bearer  = HTTPBearer(auto_error=False)
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION_THOR_SECRET")

ROLES = {
    "admin":   ["read", "write", "delete", "manage_rules", "view_reports"],
    "analyst": ["read", "write", "view_reports"],
    "viewer":  ["read"],
    "agent":   ["read", "write_events"],
}

# In-memory token store (production → Redis)
_sessions: dict[str, dict] = {}


class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "Bearer"
    expires_in:    int = 3600
    role:          str
    username:      str


def _make_token(user_id: str, role: str, expires_in: int = 3600) -> str:
    """Build simple signed token (production: use python-jose/JWK)"""
    payload = f"{user_id}:{role}:{time.time() + expires_in}"
    sig     = hmac.new(JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}:{sig}"

def _verify_token(token: str) -> Optional[dict]:
    if not token:
        return None
    parts = token.split(":")
    if len(parts) != 4:
        return None
    user_id, role, exp, sig = parts
    if float(exp) < time.time():
        return None
    payload  = f"{user_id}:{role}:{exp}"
    expected = hmac.new(JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return None
    return {"user_id": user_id, "role": role, "expires_at": float(exp)}


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    """
    Authenticate user. In production → delegates to Keycloak OIDC.
    For development: static credentials (admin/thor_dev).
    """
    # Demo credentials (in production → Keycloak)
    users = {
        "admin":   ("admin",   "thor_admin_2024!"),
        "analyst": ("analyst", "thor_analyst_2024!"),
        "viewer":  ("viewer",  "thor_viewer_2024!"),
    }
    if req.username not in users:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    role, pwd = users[req.username]
    # In prod → bcrypt.verify; dev → simple check
    if req.username == "admin" and req.password not in ("thor_admin_2024!", "admin"):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token  = _make_token(req.username, role, 3600)
    refresh_token = _make_token(req.username, role, 86400)
    _sessions[access_token]  = {"user": req.username, "role": role}
    _sessions[refresh_token] = {"user": req.username, "role": role}

    return TokenResponse(
        access_token  = access_token,
        refresh_token = refresh_token,
        expires_in    = 3600,
        role          = role,
        username      = req.username,
    )


@router.post("/refresh")
async def refresh_token(body: dict):
    token  = body.get("refresh_token", "")
    info   = _verify_token(token)
    if not info:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    new_access = _make_token(info["user_id"], info["role"], 3600)
    _sessions[new_access] = {"user": info["user_id"], "role": info["role"]}
    return {"access_token": new_access, "token_type": "Bearer", "expires_in": 3600}


@router.post("/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials if credentials else ""
    if token in _sessions:
        del _sessions[token]
    return {"status": "logged_out"}


@router.get("/me")
async def whoami(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials if credentials else ""
    info  = _verify_token(token)
    if not info:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        "user_id":     info["user_id"],
        "role":        info["role"],
        "permissions": ROLES.get(info["role"], []),
        "expires_at":  info["expires_at"],
    }
