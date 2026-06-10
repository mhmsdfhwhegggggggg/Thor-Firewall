"""
Thor Firewall — Authentication Routes (Real PostgreSQL)
=========================================================
نقاط نهاية التوثيق — مستبدلة بـ PostgreSQL حقيقية.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.jwt_handler import (
    UserRole, create_access_token, create_refresh_token,
    hash_password, verify_password, verify_token,
)
from ..auth.rbac import Permission, require_permission
from ..db.models import User, RefreshToken, APIKey, AuditLog
from ..db.session import get_db

logger = logging.getLogger("thor.routes.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])
security = HTTPBearer()


# ── Request / Response schemas ────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email:    str
    password: str = Field(..., min_length=8)

class LoginResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int = 900   # 15 min

class RegisterRequest(BaseModel):
    email:    EmailStr
    name:     str      = Field(..., min_length=2, max_length=128)
    password: str      = Field(..., min_length=12)
    role:     UserRole = UserRole.VIEWER

class UserResponse(BaseModel):
    id:         str
    email:      str
    name:       str
    role:       str
    is_active:  bool
    created_at: str

class RefreshRequest(BaseModel):
    refresh_token: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def _audit(db: AsyncSession, user_id, email, action, ip, status="success", details=None):
    log = AuditLog(
        user_id    = user_id,
        user_email = email,
        action     = action,
        ip_address = ip,
        status     = status,
        details    = details,
    )
    db.add(log)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    ip = request.client.host if request.client else "unknown"

    # Lookup user in PostgreSQL (no more in-memory dict)
    result = await db.execute(select(User).where(User.email == body.email))
    user   = result.scalar_one_or_none()

    if not user or not user.is_active:
        await _audit(db, None, body.email, "login", ip, status="failure",
                     details={"reason": "user_not_found"})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(body.password, user.hashed_pw):
        await _audit(db, str(user.id), user.email, "login", ip, status="failure",
                     details={"reason": "wrong_password"})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create tokens
    access_token  = create_access_token({"sub": str(user.id), "role": user.role.value, "email": user.email})
    refresh_token = create_refresh_token({"sub": str(user.id)})

    # Persist refresh token in PostgreSQL (not in-memory dict)
    rt = RefreshToken(
        user_id    = user.id,
        token_hash = _token_hash(refresh_token),
        expires_at = datetime.now(timezone.utc) + timedelta(days=30),
        ip_address = ip,
        user_agent = request.headers.get("user-agent"),
    )
    db.add(rt)

    # Update last_login
    await db.execute(
        update(User).where(User.id == user.id).values(
            last_login=datetime.now(timezone.utc),
            last_ip=ip,
        )
    )

    await _audit(db, str(user.id), user.email, "login", ip, details={"role": user.role.value})
    return LoginResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=LoginResponse)
async def refresh(
    body: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Rotate refresh token — stored in PostgreSQL."""
    payload = verify_token(body.refresh_token, token_type="refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    token_hash = _token_hash(body.refresh_token)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    rt = result.scalar_one_or_none()
    if not rt:
        raise HTTPException(status_code=401, detail="Token revoked or expired")

    # Revoke old token
    rt.revoked    = True
    rt.revoked_at = datetime.now(timezone.utc)

    # Get user
    result = await db.execute(select(User).where(User.id == rt.user_id))
    user   = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User disabled")

    # Issue new tokens
    access_token  = create_access_token({"sub": str(user.id), "role": user.role.value, "email": user.email})
    new_refresh   = create_refresh_token({"sub": str(user.id)})

    new_rt = RefreshToken(
        user_id    = user.id,
        token_hash = _token_hash(new_refresh),
        expires_at = datetime.now(timezone.utc) + timedelta(days=30),
        ip_address = request.client.host if request.client else None,
    )
    db.add(new_rt)
    return LoginResponse(access_token=access_token, refresh_token=new_refresh)


@router.post("/logout")
async def logout(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Revoke refresh token in PostgreSQL."""
    token_hash = _token_hash(body.refresh_token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    rt = result.scalar_one_or_none()
    if rt:
        rt.revoked    = True
        rt.revoked_at = datetime.now(timezone.utc)
    return {"message": "Logged out"}


@router.post("/register", response_model=UserResponse)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission(Permission.USER_MANAGE)),
):
    """Register new user — admin only, stored in PostgreSQL."""
    # Check duplicate
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email      = body.email,
        name       = body.name,
        hashed_pw  = hash_password(body.password),
        role       = body.role,
        is_active  = True,
    )
    db.add(user)
    await db.flush()  # get ID without committing

    ip = request.client.host if request.client else "unknown"
    await _audit(db, str(user.id), user.email, "register", ip,
                 details={"role": body.role.value})

    return UserResponse(
        id=str(user.id), email=user.email, name=user.name,
        role=user.role.value, is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else "",
    )


@router.get("/me", response_model=UserResponse)
async def me(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(select(User).where(User.id == uuid.UUID(payload["sub"])))
    user   = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserResponse(
        id=str(user.id), email=user.email, name=user.name,
        role=user.role.value, is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else "",
    )
