"""
Thor Firewall — Authentication Middleware
برمجية الوسيط للمصادقة والتفويض

يدعم:
  1. JWT Bearer tokens (HS256 / RS256)
  2. API Key authentication
  3. mTLS client certificate (للوكلاء الداخليين)
  4. Role-Based Access Control (RBAC)

الأدوار:
  - admin:    وصول كامل
  - operator: قراءة + كتابة القواعد
  - viewer:   قراءة فقط
  - agent:    وكيل thor (mTLS فقط)

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Dict, List, Optional, Set

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("thor.auth")

security_scheme = HTTPBearer(auto_error=False)


# ============================================================================
# Roles & Permissions
# ============================================================================

class Role(str, Enum):
    ADMIN    = "admin"
    OPERATOR = "operator"
    VIEWER   = "viewer"
    AGENT    = "agent"       # internal thor agents only


ROLE_PERMISSIONS: Dict[Role, Set[str]] = {
    Role.ADMIN: {
        "rules:read", "rules:write", "rules:delete",
        "flows:read", "threats:read", "analytics:read",
        "query:read", "settings:write", "agents:read",
        "audit:read", "blocklist:write", "soar:execute",
    },
    Role.OPERATOR: {
        "rules:read", "rules:write",
        "flows:read", "threats:read", "analytics:read",
        "query:read", "blocklist:write",
    },
    Role.VIEWER: {
        "rules:read", "flows:read",
        "threats:read", "analytics:read",
    },
    Role.AGENT: {
        "flows:write", "threats:write",
        "rules:read", "agents:read",
    },
}


@dataclass
class TokenClaims:
    sub:         str           # user ID or agent ID
    role:        Role
    issued_at:   float
    expires_at:  float
    jti:         Optional[str] = None  # JWT ID for revocation
    agent_id:    Optional[str] = None


# ============================================================================
# Token validation
# ============================================================================

class JWTValidator:
    """
    Minimal HS256 JWT validator — no external dependencies required.
    For production RS256, swap in python-jose or PyJWT.
    """

    def __init__(self, secret: str, algorithm: str = "HS256"):
        self.secret    = secret.encode()
        self.algorithm = algorithm
        self._revoked: Set[str] = set()

    def validate(self, token: str) -> TokenClaims:
        import base64, json

        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        # Verify signature
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig_check = hmac.new(self.secret, signing_input, hashlib.sha256).digest()
        sig_b64   = base64.urlsafe_b64decode(parts[2] + "==")
        if not hmac.compare_digest(sig_check, sig_b64):
            raise ValueError("Invalid JWT signature")

        # Decode payload
        payload_json = base64.urlsafe_b64decode(parts[1] + "==").decode()
        payload      = json.loads(payload_json)

        # Validate claims
        now = time.time()
        if payload.get("exp", 0) < now:
            raise ValueError("JWT expired")
        if payload.get("nbf", 0) > now + 5:
            raise ValueError("JWT not yet valid")

        jti = payload.get("jti")
        if jti and jti in self._revoked:
            raise ValueError("JWT has been revoked")

        role_str = payload.get("role", "viewer")
        try:
            role = Role(role_str)
        except ValueError:
            role = Role.VIEWER

        return TokenClaims(
            sub        = payload.get("sub", "unknown"),
            role       = role,
            issued_at  = payload.get("iat", now),
            expires_at = payload.get("exp", now + 3600),
            jti        = jti,
            agent_id   = payload.get("agent_id"),
        )

    def revoke(self, jti: str) -> None:
        self._revoked.add(jti)

    def issue(self, sub: str, role: Role, ttl_seconds: int = 3600, agent_id: Optional[str] = None) -> str:
        """Issue a new HS256 JWT. For development/testing only."""
        import base64, json
        now     = int(time.time())
        header  = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = {
            "sub":   sub,
            "role":  role.value,
            "iat":   now,
            "exp":   now + ttl_seconds,
            "jti":   hashlib.sha256(f"{sub}{now}".encode()).hexdigest()[:16],
        }
        if agent_id:
            payload["agent_id"] = agent_id
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signing     = f"{header}.{payload_b64}".encode()
        sig         = hmac.new(self.secret, signing, hashlib.sha256).digest()
        sig_b64     = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{header}.{payload_b64}.{sig_b64}"


# ============================================================================
# API Key store
# ============================================================================

class APIKeyStore:
    def __init__(self):
        # key_hash → (role, label)
        self._keys: Dict[str, tuple] = {}

    def add_key(self, raw_key: str, role: Role, label: str = "") -> str:
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        self._keys[key_hash] = (role, label)
        return key_hash

    def validate(self, raw_key: str) -> Optional[TokenClaims]:
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        entry    = self._keys.get(key_hash)
        if not entry:
            return None
        role, label = entry
        return TokenClaims(
            sub=label or "api-key-user",
            role=role,
            issued_at=0,
            expires_at=float("inf"),
        )


# ============================================================================
# Auth Middleware
# ============================================================================

_jwt_validator: Optional[JWTValidator] = None
_api_key_store: Optional[APIKeyStore]  = None


def init_auth(secret: str) -> None:
    global _jwt_validator, _api_key_store
    _jwt_validator = JWTValidator(secret)
    _api_key_store = APIKeyStore()

    # Pre-register built-in admin API key from environment
    admin_key = os.environ.get("THOR_ADMIN_API_KEY")
    if admin_key:
        _api_key_store.add_key(admin_key, Role.ADMIN, "env-admin")
        logger.info("Admin API key registered from environment")

    # Pre-register agent API key
    agent_key = os.environ.get("THOR_AGENT_API_KEY")
    if agent_key:
        _api_key_store.add_key(agent_key, Role.AGENT, "thor-agent")
        logger.info("Agent API key registered from environment")

    logger.info("Auth middleware initialized")


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
) -> TokenClaims:
    """
    FastAPI dependency — validates token and returns claims.
    Supports: JWT Bearer, API Key header, mTLS (if configured).
    """
    if _jwt_validator is None:
        raise HTTPException(503, "Auth not initialized")

    # 1. Check X-API-Key header
    api_key = request.headers.get("X-API-Key") or request.headers.get("X-Thor-Api-Key")
    if api_key and _api_key_store:
        claims = _api_key_store.validate(api_key)
        if claims:
            return claims

    # 2. Check Bearer JWT
    if credentials and credentials.credentials:
        try:
            return _jwt_validator.validate(credentials.credentials)
        except ValueError as e:
            raise HTTPException(401, f"Invalid token: {e}")

    # 3. Check mTLS client cert (Nginx/proxy sets this header)
    client_cert_dn = request.headers.get("X-Client-Cert-DN", "")
    if "OU=ThorAgent" in client_cert_dn:
        return TokenClaims(
            sub="agent-mtls",
            role=Role.AGENT,
            issued_at=time.time(),
            expires_at=time.time() + 3600,
        )

    raise HTTPException(401, "Authentication required")


def require_permission(permission: str):
    """
    FastAPI dependency factory for permission checking.

    Usage:
        @router.get("/flows", dependencies=[Depends(require_permission("flows:read"))])
    """
    async def dependency(claims: TokenClaims = Security(get_current_user)):
        allowed = ROLE_PERMISSIONS.get(claims.role, set())
        if permission not in allowed:
            raise HTTPException(
                403,
                f"Role '{claims.role.value}' lacks permission '{permission}'"
            )
        return claims
    return dependency


def issue_token(sub: str, role: str = "viewer", ttl: int = 3600, agent_id: Optional[str] = None) -> str:
    """Convenience function to issue a JWT token."""
    if _jwt_validator is None:
        raise RuntimeError("Auth not initialized")
    return _jwt_validator.issue(sub, Role(role), ttl, agent_id)
