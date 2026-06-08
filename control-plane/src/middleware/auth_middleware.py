"""
Thor Firewall — Authentication Middleware
middleware للتحقق من JWT في كل request

يدعم:
- Bearer token في Authorization header
- X-API-Key header للـ agents
- Whitelist للمسارات العامة (/health, /docs, /api/auth/*)

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging
from typing import Optional

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..auth.jwt_handler import TokenPayload, verify_token, verify_api_key
from ..auth.rbac import UserRole

logger = logging.getLogger("thor.middleware.auth")

security = HTTPBearer(auto_error=False)

# مسارات مستثناة من التوثيق
PUBLIC_PATHS = {
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/health",
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/metrics",
}

# Mock API keys store (استبدل بـ DB في الإنتاج)
_API_KEYS: dict[str, dict] = {}  # hashed_key → {agent_id, node_name, role}

def register_agent_key(hashed_key: str, agent_id: str, node_name: str):
    _API_KEYS[hashed_key] = {
        "agent_id": agent_id,
        "node_name": node_name,
        "role": UserRole.AGENT,
    }


async def get_current_user(request: Request) -> Optional[TokenPayload]:
    """استخراج والتحقق من هوية المستخدم الحالي"""
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith("/api/auth/"):
        return None

    # 1. Bearer JWT
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            return verify_token(token)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 2. X-API-Key (للـ agents)
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        import hashlib
        hashed = hashlib.sha256(api_key.encode()).hexdigest()
        agent = _API_KEYS.get(hashed)
        if agent:
            import time, secrets
            return TokenPayload(
                sub=agent["agent_id"],
                role=agent["role"],
                email=None,
                exp=int(time.time()) + 3600,
                iat=int(time.time()),
                jti=secrets.token_hex(8),
                token_type="agent",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    # 3. لا يوجد توثيق
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def auth_middleware(request: Request, call_next):
    """Starlette middleware — يُضيف current_user إلى request.state"""
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith("/api/auth/"):
        return await call_next(request)

    try:
        user = await get_current_user(request)
        request.state.user = user
    except HTTPException as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=e.status_code,
            content={"detail": e.detail},
            headers=e.headers or {},
        )

    return await call_next(request)
