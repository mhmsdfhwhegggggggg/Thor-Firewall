"""
Thor Firewall — JWT Authentication Handler
معالج JWT لتوثيق المستخدمين والـ agents

يدعم:
- Access tokens (15 دقيقة)
- Refresh tokens (7 أيام)
- Agent API keys (دائمة مع revocation)
- RS256 (production) أو HS256 (dev)

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import hashlib, logging, os, secrets, time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

logger = logging.getLogger("thor.auth.jwt")

# ── Config ────────────────────────────────────────────────────────────────────
JWT_SECRET          = os.getenv("JWT_SECRET", "CHANGE_THIS_IN_PRODUCTION_USE_256BIT_KEY!!")
JWT_ALGORITHM       = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_TTL    = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS",  str(15 * 60)))   # 15 min
REFRESH_TOKEN_TTL   = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", str(7 * 86400))) # 7 days
AGENT_TOKEN_TTL     = int(os.getenv("AGENT_TOKEN_TTL_SECONDS",   str(365 * 86400)))

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserRole(str, Enum):
    ADMIN      = "admin"       # كامل الصلاحيات
    ANALYST    = "analyst"     # قراءة + إدارة قضايا
    READONLY   = "readonly"    # قراءة فقط
    AGENT      = "agent"       # عميل شبكي (لا dashboard)


@dataclass
class TokenPayload:
    sub: str           # user_id أو agent_id
    role: UserRole
    email: Optional[str]
    exp: int
    iat: int
    jti: str           # JWT ID — للـ revocation
    token_type: str    # "access" | "refresh" | "agent"


# ── Revocation store (استبدل بـ Redis في الإنتاج) ─────────────────────────────
_revoked_jtis: set[str] = set()


def _revoke(jti: str):
    _revoked_jtis.add(jti)

def _is_revoked(jti: str) -> bool:
    return jti in _revoked_jtis


# ── Token creation ────────────────────────────────────────────────────────────

def _make_token(
    subject: str,
    role: UserRole,
    token_type: str,
    ttl: int,
    email: Optional[str] = None,
    extra: Optional[Dict] = None,
) -> str:
    now = int(time.time())
    payload = {
        "sub":        subject,
        "role":       role.value,
        "email":      email,
        "token_type": token_type,
        "iat":        now,
        "exp":        now + ttl,
        "jti":        secrets.token_hex(16),
        **(extra or {}),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_access_token(user_id: str, role: UserRole, email: str) -> str:
    return _make_token(user_id, role, "access", ACCESS_TOKEN_TTL, email)

def create_refresh_token(user_id: str, role: UserRole) -> str:
    return _make_token(user_id, role, "refresh", REFRESH_TOKEN_TTL)

def create_agent_token(agent_id: str, node_name: str) -> str:
    return _make_token(
        agent_id, UserRole.AGENT, "agent", AGENT_TOKEN_TTL,
        extra={"node_name": node_name},
    )


# ── Token verification ────────────────────────────────────────────────────────

def verify_token(token: str) -> TokenPayload:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")

    jti = payload.get("jti", "")
    if _is_revoked(jti):
        raise ValueError("Token has been revoked")

    return TokenPayload(
        sub=payload["sub"],
        role=UserRole(payload["role"]),
        email=payload.get("email"),
        exp=payload["exp"],
        iat=payload["iat"],
        jti=jti,
        token_type=payload.get("token_type", "access"),
    )


def revoke_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
        _revoke(payload.get("jti", ""))
    except JWTError:
        pass


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


# ── API Key (للـ agents و integrations) ──────────────────────────────────────

def generate_api_key() -> tuple[str, str]:
    """إعادة (raw_key, hashed_key) — خزّن hashed_key فقط في DB"""
    raw = "thor_" + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed

def verify_api_key(raw: str, hashed: str) -> bool:
    return hashlib.sha256(raw.encode()).hexdigest() == hashed
