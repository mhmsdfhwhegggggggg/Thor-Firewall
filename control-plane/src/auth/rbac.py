"""
Thor Firewall — Role-Based Access Control (RBAC)
التحكم في الوصول بناءً على الأدوار

مصفوفة الصلاحيات:
┌──────────────────────────┬───────┬─────────┬──────────┬───────┐
│ Resource                 │ admin │ analyst │ readonly │ agent │
├──────────────────────────┼───────┼─────────┼──────────┼───────┤
│ threats:read             │  ✓    │   ✓     │   ✓      │  ✓   │
│ threats:block            │  ✓    │   ✓     │          │  ✓   │
│ cases:read               │  ✓    │   ✓     │   ✓      │       │
│ cases:write              │  ✓    │   ✓     │          │       │
│ compliance:read          │  ✓    │   ✓     │   ✓      │       │
│ compliance:generate      │  ✓    │         │          │       │
│ users:manage             │  ✓    │         │          │       │
│ agents:register          │  ✓    │         │          │       │
│ config:write             │  ✓    │         │          │       │
│ soar:execute             │  ✓    │   ✓     │          │  ✓   │
│ audit:read               │  ✓    │   ✓     │          │       │
│ dashboard:access         │  ✓    │   ✓     │   ✓      │       │
└──────────────────────────┴───────┴─────────┴──────────┴───────┘

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from enum import Enum
from functools import wraps
from typing import Callable, Set

from fastapi import HTTPException, status

from .jwt_handler import TokenPayload, UserRole


class Permission(str, Enum):
    # Threats
    THREATS_READ    = "threats:read"
    THREATS_BLOCK   = "threats:block"
    THREATS_WRITE   = "threats:write"
    # Cases
    CASES_READ      = "cases:read"
    CASES_WRITE     = "cases:write"
    CASES_DELETE    = "cases:delete"
    # Compliance
    COMPLIANCE_READ     = "compliance:read"
    COMPLIANCE_GENERATE = "compliance:generate"
    # Users
    USERS_MANAGE    = "users:manage"
    # Agents
    AGENTS_REGISTER = "agents:register"
    AGENTS_READ     = "agents:read"
    # Config
    CONFIG_READ     = "config:read"
    CONFIG_WRITE    = "config:write"
    # SOAR
    SOAR_EXECUTE    = "soar:execute"
    SOAR_READ       = "soar:read"
    # Audit
    AUDIT_READ      = "audit:read"
    AUDIT_EXPORT    = "audit:export"
    # ML
    ML_READ         = "ml:read"
    ML_RETRAIN      = "ml:retrain"
    # Dashboard
    DASHBOARD_ACCESS = "dashboard:access"
    # UEBA
    UEBA_READ       = "ueba:read"


ROLE_PERMISSIONS: dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: set(Permission),  # كل الصلاحيات

    UserRole.ANALYST: {
        Permission.THREATS_READ, Permission.THREATS_BLOCK,
        Permission.CASES_READ,   Permission.CASES_WRITE,
        Permission.COMPLIANCE_READ,
        Permission.SOAR_EXECUTE, Permission.SOAR_READ,
        Permission.AUDIT_READ,
        Permission.ML_READ,
        Permission.DASHBOARD_ACCESS,
        Permission.UEBA_READ,
        Permission.AGENTS_READ,
        Permission.CONFIG_READ,
    },

    UserRole.READONLY: {
        Permission.THREATS_READ,
        Permission.CASES_READ,
        Permission.COMPLIANCE_READ,
        Permission.SOAR_READ,
        Permission.ML_READ,
        Permission.DASHBOARD_ACCESS,
        Permission.UEBA_READ,
        Permission.CONFIG_READ,
    },

    UserRole.AGENT: {
        Permission.THREATS_READ, Permission.THREATS_BLOCK, Permission.THREATS_WRITE,
        Permission.SOAR_EXECUTE,
        Permission.AGENTS_READ,
        Permission.ML_READ,
    },
}


def has_permission(role: UserRole, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def require_permission(*permissions: Permission):
    """Decorator للـ FastAPI route handlers"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, token: TokenPayload, **kwargs):
            for perm in permissions:
                if not has_permission(token.role, perm):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Permission denied: requires '{perm.value}' (your role: {token.role.value})",
                    )
            return await func(*args, token=token, **kwargs)
        return wrapper
    return decorator


def require_roles(*roles: UserRole):
    """تحقق من الدور مباشرةً"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, token: TokenPayload, **kwargs):
            if token.role not in roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{token.role.value}' not authorized. Required: {[r.value for r in roles]}",
                )
            return await func(*args, token=token, **kwargs)
        return wrapper
    return decorator
