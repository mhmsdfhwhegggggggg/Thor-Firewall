"""
Thor Firewall — Auth Middleware (Real PostgreSQL)
Replaces the mock API keys store with real DB lookup.
"""
from __future__ import annotations

import hashlib
import logging
import time

from fastapi import Request, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.jwt_handler import verify_token
from ..db.models import APIKey, User, AuditLog
from ..db.session import get_session_factory

logger = logging.getLogger("thor.auth_middleware")

# Routes that don't require authentication
PUBLIC_ROUTES = {
    "/api/auth/login",
    "/api/auth/refresh",
    "/healthz",
    "/health",
    "/readyz",
    "/metrics",
    "/docs",
    "/openapi.json",
    "/redoc",
}


def _key_prefix(api_key: str) -> str:
    return api_key[:8] if len(api_key) >= 8 else api_key


def _key_hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


async def auth_middleware(request: Request, call_next):
    """
    FastAPI middleware — validates JWT Bearer or X-API-Key.
    Looks up API keys in PostgreSQL (not in-memory mock).
    """
    path = request.url.path

    # Pass through public routes
    if path in PUBLIC_ROUTES or path.startswith("/docs") or path.startswith("/static"):
        return await call_next(request)

    # ── Option A: Bearer JWT ──────────────────────────────────────────────────
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = verify_token(token)
        if payload:
            request.state.user_id   = payload.get("sub")
            request.state.user_role = payload.get("role", "viewer")
            request.state.user_email = payload.get("email", "")
            return await call_next(request)
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # ── Option B: X-API-Key header ────────────────────────────────────────────
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        prefix   = _key_prefix(api_key)
        key_hash = _key_hash(api_key)

        async with get_session_factory()() as db:
            result = await db.execute(
                select(APIKey)
                .where(
                    APIKey.key_prefix == prefix,
                    APIKey.key_hash   == key_hash,
                    APIKey.is_active  == True,
                )
            )
            key_obj = result.scalar_one_or_none()

        if key_obj:
            # Get owner user
            async with get_session_factory()() as db:
                u = await db.execute(select(User).where(User.id == key_obj.user_id))
                user = u.scalar_one_or_none()

            if user and user.is_active:
                request.state.user_id    = str(user.id)
                request.state.user_role  = user.role.value
                request.state.user_email = user.email
                request.state.api_key_id = str(key_obj.id)

                # Update last_used asynchronously (don't block request)
                from sqlalchemy import update
                from datetime import datetime, timezone
                ip = request.client.host if request.client else None
                try:
                    async with get_session_factory()() as db:
                        await db.execute(
                            update(APIKey).where(APIKey.id == key_obj.id).values(
                                last_used=datetime.now(timezone.utc), last_ip=ip,
                            )
                        )
                        await db.commit()
                except Exception:
                    pass

                return await call_next(request)

        raise HTTPException(status_code=401, detail="Invalid API key")

    raise HTTPException(status_code=401, detail="Authentication required")
