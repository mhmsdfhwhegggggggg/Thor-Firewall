"""
Thor Firewall — Control Plane API v0.3
واجهة برمجية للتحكم في نظام Thor Firewall

Stack: FastAPI + WebSockets + gRPC + Redis + ClickHouse + Prometheus
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
from src.routes.forensics import router as forensics_router
from src.services.connection_manager import ConnectionManager
from src.services.event_bus import EventBus
from src.services.clickhouse import ClickHouseConfig, init_clickhouse
from src.services.threat_intel import ThreatIntelService
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
    logger.info("🚀 Thor Control Plane v0.3 starting up...")

    # ── Redis ─────────────────────────────────────────────────────────────
    app.state.redis = redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        max_connections=50,
    )
    await app.state.redis.ping()
    logger.info("✅ Redis connected")

    # ── WebSocket Connection Manager ───────────────────────────────────────
    app.state.ws_manager = ConnectionManager()

    # ── Event Bus ─────────────────────────────────────────────────────────
    app.state.event_bus = EventBus(app.state.redis, app.state.ws_manager)
    asyncio.create_task(app.state.event_bus.listen())
    logger.info("✅ Event bus started")

    # ── ClickHouse (Forensics) ────────────────────────────────────────────
    ch_config = ClickHouseConfig(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        database=os.getenv("CLICKHOUSE_DB", "thor"),
        username=os.getenv("CLICKHOUSE_USER", "thor_agent"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        batch_size=int(os.getenv("CLICKHOUSE_BATCH_SIZE", "5000")),
    )
    app.state.clickhouse = await init_clickhouse(ch_config)
    if app.state.clickhouse._initialized:
        logger.info("✅ ClickHouse connected — forensics enabled")
    else:
        logger.warning("⚠️  ClickHouse unavailable — forensics disabled")

    # ── Threat Intel Service ───────────────────────────────────────────────
    app.state.threat_intel = ThreatIntelService(
        misp_url=os.getenv("MISP_URL", ""),
        misp_key=os.getenv("MISP_KEY", ""),
        redis_client=app.state.redis,
    )
    await app.state.threat_intel.start()
    logger.info("✅ Threat Intel service started")

    logger.info(
        f"🛡️  Thor Control Plane fully operational on port {settings.port} "
        f"(version 0.3.0)"
    )

    yield

    # ────────────────────────────────────────────────────────────────────
    logger.info("Shutting down Thor Control Plane...")
    await app.state.threat_intel.stop()
    if app.state.clickhouse:
        await app.state.clickhouse.close()
    await app.state.redis.aclose()
    logger.info("👋 Control Plane stopped")


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Thor Firewall Control Plane",
    description="""
## Thor Firewall — Next-Generation Firewall API v0.3

Real-time control and monitoring API for Thor Firewall.  
Powered by eBPF/XDP (Linux), WFP (Windows), MARL, GNN, and LLM.

### Core APIs
- 🛡️ **Flows** — real-time flow monitoring and blocking
- 🚨 **Threats** — AI-detected threat events with MITRE ATT&CK mapping
- 📊 **Analytics** — network statistics, time-series, top-talkers
- 🔍 **Forensics** — historical OLAP queries via ClickHouse
- 💬 **AI Query** — natural-language security queries (LLM + RAG)
- 🔄 **Rules** — dynamic policy management

### Real-time
- WebSocket `/ws/live` — live event stream (flows, threats, stats)
- Server-Sent Events planned for v0.4
    """,
    version="0.3.0",
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

# Prometheus metrics endpoint
Instrumentator(
    should_group_status_codes=False,
    should_ignore_untemplated=True,
    should_respect_env_var=True,
    should_instrument_requests_inprogress=True,
    excluded_handlers=["/api/metrics", "/api/health"],
    inprogress_name="thor_cp_inprogress",
    inprogress_labels=True,
).instrument(app).expose(app, endpoint="/api/metrics")

# ============================================================================
# Routes
# ============================================================================

app.include_router(health.router,      prefix="/api",    tags=["Health"])
app.include_router(flows.router,       prefix="/api/v1", tags=["Flows"])
app.include_router(rules.router,       prefix="/api/v1", tags=["Rules"])
app.include_router(threats.router,     prefix="/api/v1", tags=["Threats"])
app.include_router(analytics.router,   prefix="/api/v1", tags=["Analytics"])
app.include_router(query.router,       prefix="/api/v1", tags=["AI Query"])
app.include_router(forensics_router,                     tags=["Forensics"])


# ============================================================================
# WebSocket — Real-time Event Stream
# ============================================================================

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket, token: str = ""):
    """
    WebSocket endpoint — real-time events

    Events:
    - `flow_blocked`     — flow blocked by AI
    - `threat_detected`  — threat pattern identified
    - `stats_update`     — dashboard statistics (every 1s)
    - `alert`            — critical security alert
    """
    await app.state.ws_manager.connect(websocket)
    logger.info("WebSocket client connected: %s", websocket.client)

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        app.state.ws_manager.disconnect(websocket)
        logger.info("WebSocket client disconnected: %s", websocket.client)


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
