"""
Thor Firewall — Casbin RBAC Authorization
==========================================
تحكم في الوصول المبني على الأدوار باستخدام Casbin.

مستوحى من: https://github.com/casbin/casbin

يتكامل مع:
  - Keycloak (JWT tokens → user roles)
  - FastAPI (middleware + route decorators)
  - pycasbin async adapter

المعمارية:
  - RBAC with domains: كل tenant له domain منفصل
  - Policy: ملف CSV + database adapter (للتحديث الديناميكي)
  - JWT: يُستخرج الدور من Keycloak token
"""

from __future__ import annotations

import os
import logging
from functools import wraps
from typing import Callable, List, Optional

import casbin
import casbin_async_sqlalchemy_adapter
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("thor.auth.casbin")

MODEL_PATH  = os.getenv("CASBIN_MODEL_PATH",  "/app/configs/casbin/rbac_model.conf")
POLICY_PATH = os.getenv("CASBIN_POLICY_PATH", "/app/configs/casbin/rbac_policy.csv")
DOMAIN      = os.getenv("CASBIN_DOMAIN",      "thor")

_enforcer: Optional[casbin.AsyncEnforcer] = None


# ─────────────────────────────────────────────────────────────────────────────
# Enforcer Setup
# ─────────────────────────────────────────────────────────────────────────────

async def get_enforcer() -> casbin.AsyncEnforcer:
    """Lazy singleton — يُهيئ enforcer مرة واحدة."""
    global _enforcer
    if _enforcer is not None:
        return _enforcer

    db_url = os.getenv("DATABASE_URL", "")
    if db_url:
        # Database adapter للتحديث الديناميكي في الإنتاج
        adapter = await casbin_async_sqlalchemy_adapter.Adapter.create(db_url)
        _enforcer = casbin.AsyncEnforcer(MODEL_PATH, adapter)
        logger.info("✅ Casbin enforcer initialized with DB adapter")
    else:
        # CSV adapter للتطوير
        _enforcer = casbin.AsyncEnforcer(MODEL_PATH, POLICY_PATH)
        logger.info("✅ Casbin enforcer initialized with CSV policy")

    await _enforcer.load_policy()
    return _enforcer


# ─────────────────────────────────────────────────────────────────────────────
# JWT Role Extraction (من Keycloak token)
# ─────────────────────────────────────────────────────────────────────────────

def extract_roles_from_token(token_data: dict) -> List[str]:
    """
    يستخرج roles من Keycloak JWT payload.
    
    Keycloak structure:
      - realm_access.roles: ["analyst", "offline_access", ...]
      - resource_access.thor-api.roles: ["analyst", ...]
    """
    roles = []

    # Realm roles
    realm_access = token_data.get("realm_access", {})
    roles.extend(realm_access.get("roles", []))

    # Client-specific roles
    resource_access = token_data.get("resource_access", {})
    client_roles = resource_access.get("thor-api", {}).get("roles", [])
    roles.extend(client_roles)

    # Filter internal Keycloak roles
    filtered = [r for r in roles if not r.startswith(("offline_", "uma_", "default-"))]
    return list(set(filtered))


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Authorization Dependency
# ─────────────────────────────────────────────────────────────────────────────

security = HTTPBearer(auto_error=False)


async def get_current_user_roles(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    """
    FastAPI dependency — يستخرج user info من JWT.
    يُستخدم في route decorators.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Decode token (يعتمد على python-jose)
    from jose import jwt, JWTError
    from jose.exceptions import ExpiredSignatureError

    keycloak_url   = os.getenv("KEYCLOAK_URL",   "http://keycloak:8080")
    keycloak_realm = os.getenv("KEYCLOAK_REALM", "thor")
    jwt_secret     = os.getenv("JWT_SECRET",     "dev_secret")

    try:
        payload = jwt.decode(
            credentials.credentials,
            jwt_secret,
            algorithms=["RS256", "HS256"],
            options={"verify_aud": False},
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
        )

    sub   = payload.get("sub", "unknown")
    roles = extract_roles_from_token(payload)
    email = payload.get("email", "")

    return {
        "sub":    sub,
        "email":  email,
        "roles":  roles,
        "domain": DOMAIN,
        "token":  payload,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Authorization Checks
# ─────────────────────────────────────────────────────────────────────────────

async def authorize(
    user: dict,
    resource: str,
    action: str,
    domain: str = DOMAIN,
) -> bool:
    """
    يتحقق من صلاحية user لتنفيذ action على resource.
    
    Args:
        user: من get_current_user_roles()
        resource: مثل "/api/flows/*" أو "/api/threats/123"
        action: read / write / delete / *
        domain: thor / default
        
    Returns:
        bool: مسموح أم لا
    """
    enforcer = await get_enforcer()
    roles = user.get("roles", [])

    for role in roles:
        allowed = await enforcer.enforce(role, domain, resource, action)
        if allowed:
            logger.debug(f"✅ {user['sub']} [{role}] → {action} {resource}")
            return True

    logger.warning(f"🚫 {user['sub']} {roles} → {action} {resource} DENIED")
    return False


def require_permission(resource_pattern: str, action: str = "read"):
    """
    FastAPI dependency factory للـ route protection.
    
    Usage:
        @router.get("/flows", dependencies=[Depends(require_permission("/api/flows/*", "read"))])
        async def list_flows():
            ...
    """
    async def _check(
        request: Request,
        user: dict = Depends(get_current_user_roles),
    ) -> dict:
        path = request.url.path
        allowed = await authorize(user, path, action)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: {action} {path}",
            )
        return user

    return Depends(_check)


def require_role(*roles: str):
    """
    Dependency للتحقق من وجود role معين.
    
    Usage:
        @router.post("/rules", dependencies=[Depends(require_role("admin", "analyst"))])
        async def create_rule():
            ...
    """
    async def _check(user: dict = Depends(get_current_user_roles)) -> dict:
        user_roles = set(user.get("roles", []))
        required   = set(roles)
        if not user_roles.intersection(required) and "super_admin" not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {', '.join(roles)}",
            )
        return user

    return Depends(_check)


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic Policy Management (RBAC at runtime)
# ─────────────────────────────────────────────────────────────────────────────

async def add_policy(sub: str, domain: str, resource: str, action: str) -> bool:
    """يُضيف policy جديدة ديناميكياً."""
    enforcer = await get_enforcer()
    result = await enforcer.add_policy(sub, domain, resource, action)
    logger.info(f"Policy added: {sub} → {action} {resource} in {domain}")
    return result


async def remove_policy(sub: str, domain: str, resource: str, action: str) -> bool:
    """يُزيل policy."""
    enforcer = await get_enforcer()
    result = await enforcer.remove_policy(sub, domain, resource, action)
    logger.info(f"Policy removed: {sub} → {action} {resource} in {domain}")
    return result


async def add_role_for_user(user: str, role: str, domain: str = DOMAIN) -> bool:
    """يُضيف role لـ user."""
    enforcer = await get_enforcer()
    return await enforcer.add_role_for_user_in_domain(user, role, domain)


async def get_roles_for_user(user: str, domain: str = DOMAIN) -> List[str]:
    """يُرجع roles الـ user."""
    enforcer = await get_enforcer()
    return enforcer.get_roles_for_user_in_domain(user, domain)
