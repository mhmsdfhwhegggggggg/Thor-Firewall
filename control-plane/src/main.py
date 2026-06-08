"""
Thor Firewall — Control Plane API
واجهة برمجية للتحكم في نظام Thor Firewall

Stack: FastAPI + WebSockets + gRPC + Redis + ClickHouse
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import redis.asyncio as redis
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from src.routes import flows, rules, threats, analytics, query, health
from src.services.connection_manager import ConnectionManager
from src.services.event_bus import EventBus
from src.models.config import Settings

# ============================================================================
# Configuration
# ============================================================================

settings = Settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("thor.control-plane")

# ============================================================================
# Application Lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """تهيئة وإغلاق الموارد"""
    logger.info("🚀 Thor Control Plane starting up...")

    # Initialize Redis connection pool
    app.state.redis = redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        max_connections=50,
    )
    await app.state.redis.ping()
    logger.info("✅ Redis connected")

    # Initialize WebSocket connection manager
    app.state.ws_manager = ConnectionManager()

    # Initialize Event Bus (for real-time updates)
    app.state.event_bus = EventBus(app.state.redis, app.state.ws_manager)
    asyncio.create_task(app.state.event_bus.listen())
    logger.info("✅ Event bus started")

    logger.info(
        f"🛡️ Thor Control Plane fully operational on port {settings.port}"
    )

    yield

    # Cleanup
    logger.info("Shutting down Thor Control Plane...")
    await app.state.redis.aclose()
    logger.info("👋 Control Plane stopped")


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Thor Firewall Control Plane",
    description="""
    ## Thor Firewall — Next-Generation Firewall API

    Real-time control and monitoring API for Thor Firewall.
    Powered by eBPF/XDP, MARL, GNN, and LLM.

    ### Features
    - 🛡️ Real-time flow monitoring and control
    - 🤖 AI-powered threat analysis
    - 📊 Historical analytics and reporting
    - 💬 Natural language security queries
    - ⚡ WebSocket for live updates
    """,
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ============================================================================
# Middleware
# ============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Prometheus metrics
Instrumentator().instrument(app).expose(app, endpoint="/api/metrics")

# ============================================================================
# Routes
# ============================================================================

app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(flows.router, prefix="/api/v1", tags=["Flows"])
app.include_router(rules.router, prefix="/api/v1", tags=["Rules"])
app.include_router(threats.router, prefix="/api/v1", tags=["Threats"])
app.include_router(analytics.router, prefix="/api/v1", tags=["Analytics"])
app.include_router(query.router, prefix="/api/v1", tags=["AI Query"])


# ============================================================================
# WebSocket — Real-time Event Stream
# ============================================================================

@app.websocket("/ws/live")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = "",
):
    """
    WebSocket endpoint for real-time events

    Events pushed:
    - `flow_blocked`: New flow blocked by AI
    - `threat_detected`: Threat pattern identified
    - `stats_update`: Dashboard statistics (every 1s)
    - `alert`: High-priority security alert
    """
    await app.state.ws_manager.connect(websocket)
    logger.info(f"WebSocket client connected: {websocket.client}")

    try:
        while True:
            # Keep connection alive, handle client messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        app.state.ws_manager.disconnect(websocket)
        logger.info(f"WebSocket client disconnected: {websocket.client}")


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
        workers=1 if settings.debug else 4,
        loop="uvloop",
    )
