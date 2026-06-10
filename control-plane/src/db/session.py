"""
Thor Firewall — Database Session Manager
=========================================
Async PostgreSQL session using SQLAlchemy 2.0 + asyncpg.
Replaces all in-memory dicts in auth.py / middleware.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import Base

logger = logging.getLogger("thor.db")


def _build_url() -> str:
    """Build PostgreSQL DSN from environment variables."""
    url = os.environ.get("DATABASE_URL", "")
    if url:
        # Convert postgres:// → postgresql+asyncpg://
        return url.replace("postgres://", "postgresql+asyncpg://", 1) \
                  .replace("postgresql://", "postgresql+asyncpg://", 1)
    # Build from parts
    host = os.environ.get("POSTGRES_HOST",     "localhost")
    port = os.environ.get("POSTGRES_PORT",     "5432")
    db   = os.environ.get("POSTGRES_DB",       "thor")
    user = os.environ.get("POSTGRES_USER",     "thor")
    pw   = os.environ.get("POSTGRES_PASSWORD", "thor_dev_password")
    return f"postgresql+asyncpg://{user}:{pw}@{host}:{port}/{db}"


# ── Engine ────────────────────────────────────────────────────────────────────

_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    if _engine is None:
        url = _build_url()
        _engine = create_async_engine(
            url,
            pool_size        = int(os.environ.get("DB_POOL_SIZE",    "10")),
            max_overflow     = int(os.environ.get("DB_MAX_OVERFLOW", "20")),
            pool_pre_ping    = True,        # detect stale connections
            pool_recycle     = 3600,        # recycle every hour
            echo             = os.environ.get("DB_ECHO", "").lower() == "true",
            connect_args     = {"server_settings": {"jit": "off"}},
        )
        logger.info("Database engine created")
    return _engine


def get_session_factory() -> async_sessionmaker:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = async_sessionmaker(
            bind       = get_engine(),
            class_     = AsyncSession,
            expire_on_commit = False,
            autoflush  = False,
        )
    return _SessionLocal


# ── FastAPI dependency ─────────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI Depends() injection for database session."""
    async with get_session_factory()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── App lifecycle ─────────────────────────────────────────────────────────────

async def init_db():
    """Create all tables on startup (idempotent — skips existing)."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialized")


async def check_connection() -> bool:
    """Health check — returns True if DB is reachable."""
    try:
        async with get_session_factory()() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error("DB health check failed: %s", e)
        return False


async def close_db():
    """Close connection pool on shutdown."""
    global _engine
    if _engine:
        await _engine.dispose()
        _engine = None
        logger.info("Database connection pool closed")
