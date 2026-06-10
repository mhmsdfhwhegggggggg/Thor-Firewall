"""
Thor Firewall — PostgreSQL Database Models (SQLAlchemy)
=======================================================
يستبدل تخزين البيانات في الذاكرة بقاعدة بيانات PostgreSQL حقيقية.

النماذج:
  - User           — المستخدمون + دورهم (RBAC)
  - APIKey         — مفاتيح API للـ agents
  - RefreshToken   — رموز التجديد (بدل Dict في الذاكرة)
  - AuditLog       — سجل كل الأحداث للامتثال
  - FirewallPolicy — سياسات الجدار الناري
  - ThreatIOC      — مؤشرات التهديد (IPs, domains, hashes)
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float,
    ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func

import enum


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ─── Enums ────────────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    ADMIN      = "admin"
    ANALYST    = "analyst"
    RESPONDER  = "responder"
    VIEWER     = "viewer"
    API_AGENT  = "api_agent"

class PolicyAction(str, enum.Enum):
    ALLOW    = "allow"
    BLOCK    = "block"
    LOG      = "log"
    THROTTLE = "throttle"
    REDIRECT = "redirect"

class IOCType(str, enum.Enum):
    IPv4       = "ipv4"
    IPv6       = "ipv6"
    DOMAIN     = "domain"
    URL        = "url"
    SHA256     = "sha256"
    SHA1       = "sha1"
    MD5        = "md5"
    EMAIL      = "email"
    USER_AGENT = "user_agent"


# ─── Users ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email       = Column(String(255), nullable=False, unique=True, index=True)
    name        = Column(String(255), nullable=False)
    hashed_pw   = Column(String(255), nullable=False)
    role        = Column(Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active   = Column(Boolean, nullable=False, default=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_secret  = Column(String(64), nullable=True)

    created_at  = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at  = Column(DateTime(timezone=True), onupdate=func.now())
    last_login  = Column(DateTime(timezone=True), nullable=True)
    last_ip     = Column(INET, nullable=True)

    # Relationships
    refresh_tokens = relationship("RefreshToken", back_populates="user",
                                   cascade="all, delete-orphan")
    api_keys       = relationship("APIKey",       back_populates="user",
                                   cascade="all, delete-orphan")
    audit_logs     = relationship("AuditLog",     back_populates="user")

    def __repr__(self):
        return f"<User {self.email} [{self.role}]>"


# ─── Authentication tokens ────────────────────────────────────────────────────

class RefreshToken(Base):
    """Replaces the in-memory _REFRESH_TOKENS dict."""
    __tablename__ = "refresh_tokens"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id    = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(255), nullable=False, unique=True, index=True)
    issued_at  = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked    = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    user_agent = Column(String(512), nullable=True)
    ip_address = Column(INET, nullable=True)

    user       = relationship("User", back_populates="refresh_tokens")


class APIKey(Base):
    """Replaces the in-memory mock API keys store."""
    __tablename__ = "api_keys"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id    = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name       = Column(String(255), nullable=False)          # "Production Agent eth0"
    key_prefix = Column(String(8),   nullable=False, index=True)  # first 8 chars for display
    key_hash   = Column(String(255), nullable=False, unique=True)  # bcrypt of full key
    scopes     = Column(JSONB, nullable=False, default=list)   # ["flows:write", "threats:read"]
    is_active  = Column(Boolean, nullable=False, default=True)
    last_used  = Column(DateTime(timezone=True), nullable=True)
    last_ip    = Column(INET, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # None = no expiry

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user       = relationship("User", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_keys_prefix_active", "key_prefix", "is_active"),
    )


# ─── Audit Log ────────────────────────────────────────────────────────────────

class AuditLog(Base):
    """Immutable audit trail — never delete, only INSERT."""
    __tablename__ = "audit_logs"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id    = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    user_email = Column(String(255), nullable=True)   # denormalized for queries after user deletion
    action     = Column(String(128), nullable=False, index=True)   # "login", "block_ip", "rule_create"
    resource   = Column(String(256), nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(String(512), nullable=True)
    status     = Column(String(32), nullable=False, default="success")  # success / failure
    details    = Column(JSONB, nullable=True)
    timestamp  = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    user       = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_action_ts", "action", "timestamp"),
    )


# ─── Firewall Policies ────────────────────────────────────────────────────────

class FirewallPolicy(Base):
    __tablename__ = "firewall_policies"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    priority    = Column(Integer, nullable=False, default=100, index=True)
    action      = Column(Enum(PolicyAction), nullable=False)
    is_active   = Column(Boolean, nullable=False, default=True, index=True)

    # Match conditions (NULL = match any)
    src_cidr    = Column(String(50), nullable=True)   # e.g. "192.168.0.0/16"
    dst_cidr    = Column(String(50), nullable=True)
    src_port_lo = Column(Integer, nullable=True)
    src_port_hi = Column(Integer, nullable=True)
    dst_port_lo = Column(Integer, nullable=True)
    dst_port_hi = Column(Integer, nullable=True)
    protocol    = Column(Integer, nullable=True)       # 6=TCP, 17=UDP, 1=ICMP, NULL=any

    # Time-based
    expires_at  = Column(DateTime(timezone=True), nullable=True)

    # Metadata
    created_by  = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at  = Column(DateTime(timezone=True), onupdate=func.now())

    # Statistics (updated by trigger / background job)
    hit_count   = Column(Integer, nullable=False, default=0)
    last_hit    = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_policies_active_priority", "is_active", "priority"),
    )


# ─── Threat IOCs ──────────────────────────────────────────────────────────────

class ThreatIOC(Base):
    """Threat Intelligence IOCs — synced from OpenCTI / MISP / manual."""
    __tablename__ = "threat_iocs"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_type    = Column(Enum(IOCType), nullable=False, index=True)
    value       = Column(String(512), nullable=False, index=True)
    confidence  = Column(Float, nullable=False, default=50.0)   # 0-100
    severity    = Column(String(16), nullable=False, default="medium")
    tlp         = Column(String(8),  nullable=False, default="white")

    source      = Column(String(64), nullable=True)   # "opencti", "misp", "manual", "yara"
    source_id   = Column(String(256), nullable=True)  # external ID

    threat_type = Column(String(128), nullable=True)  # "botnet", "c2", "ransomware"
    tags        = Column(JSONB, nullable=True, default=list)
    labels      = Column(JSONB, nullable=True, default=list)
    kill_chain  = Column(JSONB, nullable=True, default=list)

    first_seen  = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen   = Column(DateTime(timezone=True), onupdate=func.now())
    valid_until = Column(DateTime(timezone=True), nullable=True)
    is_active   = Column(Boolean, nullable=False, default=True, index=True)

    # Usage stats
    hit_count   = Column(Integer, nullable=False, default=0)
    last_hit    = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
        Index("ix_ioc_value_active", "value", "is_active"),
    )
