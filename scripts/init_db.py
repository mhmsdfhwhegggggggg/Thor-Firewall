#!/usr/bin/env python3
"""
Thor Firewall — Database Initialization Script
Runs on first deployment to create tables and seed default admin user.

Usage:
    python scripts/init_db.py
    DATABASE_URL=postgresql://... python scripts/init_db.py
"""
from __future__ import annotations
import asyncio, logging, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("thor.init_db")

ADMIN_EMAIL    = os.environ.get("THOR_ADMIN_EMAIL",    "admin@thor.local")
ADMIN_PASSWORD = os.environ.get("THOR_ADMIN_PASSWORD", "Thor@Admin2024!")
ADMIN_NAME     = os.environ.get("THOR_ADMIN_NAME",     "Thor Admin")


async def main():
    from control_plane.src.db.session import init_db, get_session_factory
    from control_plane.src.db.models  import User, UserRole
    from control_plane.src.auth.jwt_handler import hash_password
    from sqlalchemy import select

    logger.info("Initializing database schema...")
    await init_db()
    logger.info("Schema created/verified")

    # Seed admin user if not exists
    async with get_session_factory()() as db:
        result = await db.execute(select(User).where(User.email == ADMIN_EMAIL))
        existing = result.scalar_one_or_none()

        if existing:
            logger.info("Admin user already exists: %s", ADMIN_EMAIL)
        else:
            admin = User(
                email      = ADMIN_EMAIL,
                name       = ADMIN_NAME,
                hashed_pw  = hash_password(ADMIN_PASSWORD),
                role       = UserRole.ADMIN,
                is_active  = True,
            )
            db.add(admin)
            await db.commit()
            logger.info("Admin user created: %s", ADMIN_EMAIL)

    logger.info("Database initialization complete")


if __name__ == "__main__":
    asyncio.run(main())
