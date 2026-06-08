"""
Thor Firewall — Control Plane Entry Point
نقطة الدخول الرئيسية لـ FastAPI application

يجمع:
- Authentication + RBAC middleware
- Rate limiting
- جميع الـ routers
- WebSocket للـ real-time events
- Prometheus metrics
- Structured logging

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, os, time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app, Counter, Histogram, Gauge

from .middleware.auth_middleware import auth_middleware
from .middleware.rate_limiter import rate_limit_middleware
from .routes.auth import router as auth_router
from .routes.cases import router as cases_router

log = structlog.get_logger("thor.api")

# ── Prometheus Metrics ────────────────────────────────────────────────────────
REQUEST_COUNT = Counter("thor_api_requests_total", "API requests", ["method", "path", "status"])
REQUEST_LATENCY = Histogram("thor_api_latency_seconds", "API latency", ["path"])
ACTIVE_WS = Gauge("thor_websocket_connections", "Active WebSocket connections")
THREATS_TOTAL = Counter("thor_threats_total", "Threats detected", ["severity", "threat_type"])
SOAR_EXECUTIONS = Counter("thor_soar_executions_total", "SOAR playbook executions", ["action"])

# ── WebSocket Manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        ACTIVE_WS.inc()

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)
        ACTIVE_WS.dec()

    async def broadcast(self, data: dict):
        dead = []
        for ws in self._connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_manager = ConnectionManager()

# ── App Lifecycle ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("thor_startup", version="1.0.0", env=os.getenv("ENVIRONMENT", "development"))
    yield
    log.info("thor_shutdown")

# ── App Init ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Thor Firewall — Control Plane API",
    version="1.0.0",
    description="Enterprise Security Platform — REST API",
    docs_url="/docs" if os.getenv("ENVIRONMENT") != "production" else None,
    redoc_url="/redoc" if os.getenv("ENVIRONMENT") != "production" else None,
    lifespan=lifespan,
)

# ── Middleware (order matters — outermost = first to run) ─────────────────────
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    t0 = time.perf_counter()
    response = await call_next(request)
    latency = time.perf_counter() - t0
    path = request.url.path
    REQUEST_COUNT.labels(request.method, path, response.status_code).inc()
    REQUEST_LATENCY.labels(path).observe(latency)
    response.headers["X-Response-Time"] = f"{latency*1000:.1f}ms"
    response.headers["X-Thor-Version"] = "1.0.0"
    return response

@app.middleware("http")
async def _rate_limit(request: Request, call_next):
    return await rate_limit_middleware(request, call_next)

@app.middleware("http")
async def _auth(request: Request, call_next):
    return await auth_middleware(request, call_next)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(cases_router)

# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# ── Core Routes ───────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["system"])
async def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": time.time(),
        "environment": os.getenv("ENVIRONMENT", "development"),
    }

@app.get("/api/v1/stats/dashboard", tags=["dashboard"])
async def dashboard_stats(request: Request):
    """إحصاءات الـ dashboard الرئيسي"""
    # في الإنتاج: استعلام من ClickHouse
    return {
        "threats_last_24h": 1247,
        "blocked_last_24h": 1189,
        "active_cases": 4,
        "ml_accuracy": 97.3,
        "agents_online": 12,
        "compliance_score": 94.2,
        "top_threat_types": [
            {"type": "PortScan",   "count": 423, "pct": 33.9},
            {"type": "DDoS",       "count": 287, "pct": 23.0},
            {"type": "BruteForce", "count": 198, "pct": 15.9},
            {"type": "C2",         "count": 127, "pct": 10.2},
        ],
        "risk_by_hour": [
            {"hour": h, "risk": round(0.1 + 0.6 * abs((h - 12) / 12), 2)}
            for h in range(24)
        ],
    }

@app.get("/api/v1/threats", tags=["threats"])
async def list_threats(
    request: Request,
    limit: int = 50,
    severity: str = None,
    threat_type: str = None,
):
    """قائمة التهديدات الأخيرة — في الإنتاج من ClickHouse"""
    import random, time as t
    rng = random.Random(42)
    threats = []
    for i in range(min(limit, 50)):
        sev = rng.choice(["critical","high","medium","low"])
        threats.append({
            "id":          f"thr_{i:04d}",
            "timestamp":   t.time() - rng.randint(0, 86400),
            "src_ip":      f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}",
            "dst_ip":      f"10.0.{rng.randint(0,5)}.{rng.randint(1,254)}",
            "threat_type": rng.choice(["PortScan","DDoS","BruteForce","C2","Exfil","Malware"]),
            "severity":    sev,
            "risk_score":  round(rng.uniform(0.5, 0.99), 3),
            "blocked":     sev in ("critical","high"),
            "mitre_id":    rng.choice(["T1046","T1059","T1071","T1486","T1595"]),
        })
    return {"threats": threats, "total": 1247, "returned": len(threats)}

@app.post("/api/v1/soar/block-ip", tags=["soar"])
async def soar_block_ip(request: Request, body: dict):
    ip = body.get("ip")
    reason = body.get("reason", "manual")
    log.info("soar_block_ip", ip=ip, reason=reason)
    SOAR_EXECUTIONS.labels("block_ip").inc()
    return {"status": "blocked", "ip": ip, "reason": reason, "expires_at": time.time() + body.get("duration_secs", 3600)}

@app.post("/api/v1/soar/isolate-host", tags=["soar"])
async def soar_isolate_host(request: Request, body: dict):
    log.info("soar_isolate_host", host_id=body.get("host_id"))
    SOAR_EXECUTIONS.labels("isolate_host").inc()
    return {"status": "isolated", **body}

# ── WebSocket — Real-time Event Stream ───────────────────────────────────────

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    """بث الأحداث الأمنية في الوقت الفعلي"""
    await ws_manager.connect(ws)
    log.info("ws_connected", client=str(ws.client))
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
        log.info("ws_disconnected")

# ── Error Handlers ────────────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(status_code=404, content={"detail": f"Path not found: {request.url.path}"})

@app.exception_handler(500)
async def server_error(request: Request, exc):
    log.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(
        "src.main:app", host="0.0.0.0", port=port,
        reload=os.getenv("ENVIRONMENT") == "development",
        workers=int(os.getenv("WORKERS", "1")),
        log_level="info",
    )
