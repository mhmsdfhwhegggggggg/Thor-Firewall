"""
Thor Firewall — Control Plane Entry Point (v2.0)
نقطة الدخول الرئيسية — تجمع جميع الـ routers

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

log = structlog.get_logger("thor.api")

REQUEST_COUNT   = Counter("thor_api_requests_total",    "API requests",  ["method", "path", "status"])
REQUEST_LATENCY = Histogram("thor_api_latency_seconds", "API latency",   ["path"])
ACTIVE_WS       = Gauge("thor_websocket_connections",   "Active WS connections")
SOAR_EXECUTIONS = Counter("thor_soar_executions_total", "SOAR executions", ["action"])

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("thor_startup", version="2.0.0", env=os.getenv("ENVIRONMENT", "development"))
    yield
    log.info("thor_shutdown")

app = FastAPI(
    title="Thor Firewall — Control Plane API v2",
    version="2.0.0",
    description="Enterprise Security Platform — XDR + UEBA + ThorQL + Compliance",
    docs_url="/docs"   if os.getenv("ENVIRONMENT") != "production" else None,
    redoc_url="/redoc" if os.getenv("ENVIRONMENT") != "production" else None,
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    t0 = time.perf_counter()
    response = await call_next(request)
    latency  = time.perf_counter() - t0
    path     = request.url.path
    REQUEST_COUNT.labels(request.method, path, response.status_code).inc()
    REQUEST_LATENCY.labels(path).observe(latency)
    response.headers["X-Response-Time"] = f"{latency*1000:.1f}ms"
    response.headers["X-Thor-Version"]  = "2.0.0"
    return response

# ── Core Routers ──────────────────────────────────────────────────────────────
from .routes.auth      import router as auth_router
from .routes.cases     import router as cases_router
from .routes.flows     import router as flows_router
from .routes.threats   import router as threats_router
from .routes.analytics import router as analytics_router
from .routes.health    import router as health_router
from .routes.forensics import router as forensics_router
from .routes.xdr       import router as xdr_router
from .routes.query     import router as query_router

app.include_router(auth_router)
app.include_router(cases_router)
app.include_router(flows_router,     prefix="/api/v1")
app.include_router(threats_router,   prefix="/api/v1")
app.include_router(analytics_router, prefix="/api/v1")
app.include_router(health_router,    prefix="/api")
app.include_router(forensics_router, prefix="/api/v1")
app.include_router(xdr_router)
app.include_router(query_router)

# ── Optional Routers (loaded dynamically) ─────────────────────────────────────
_optional_routers = [
    ("ueba",         ".routes.ueba",         None),
    ("threat_graph", ".routes.threat_graph",  None),
    ("compliance",   ".routes.compliance",    None),
    ("integrations", ".routes.integrations",  None),
    ("rules",        ".routes.rules",         "/api/v1"),
]
for name, module_path, prefix in _optional_routers:
    try:
        import importlib
        mod    = importlib.import_module(module_path, package="src")
        router = getattr(mod, "router")
        kwargs = {"router": router}
        if prefix:
            kwargs = {"router": router, "prefix": prefix}
            app.include_router(router, prefix=prefix)
        else:
            app.include_router(router)
        log.info("router_loaded", name=name)
    except Exception as _e:
        log.warning("router_skip", name=name, reason=str(_e))

# Prometheus
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# ── Built-in Endpoints ────────────────────────────────────────────────────────
@app.get("/api/health", tags=["system"])
async def health_simple():
    return {"status": "healthy", "version": "2.0.0", "timestamp": time.time()}

@app.get("/api/v1/stats/dashboard", tags=["dashboard"])
async def dashboard_stats():
    return {
        "threats_last_24h": 1247,
        "blocked_last_24h": 1189,
        "active_cases":     4,
        "ml_accuracy":      97.3,
        "agents_online":    12,
        "compliance_score": 94.2,
        "xdr_incidents":    7,
        "ueba_anomalies":   23,
        "top_threat_types": [
            {"type": "PortScan",   "count": 423, "pct": 33.9},
            {"type": "DDoS",       "count": 287, "pct": 23.0},
            {"type": "BruteForce", "count": 198, "pct": 15.9},
            {"type": "C2",         "count": 127, "pct": 10.2},
        ],
        "risk_by_hour": [{"hour": h, "risk": round(0.1 + 0.6 * abs((h - 12) / 12), 2)} for h in range(24)],
        "mitre_coverage": {"total_techniques": 200, "covered": 162, "coverage_pct": 81.0},
    }

@app.post("/api/v1/soar/block-ip", tags=["soar"])
async def soar_block_ip(body: dict):
    ip = body.get("ip")
    log.info("soar_block_ip", ip=ip)
    SOAR_EXECUTIONS.labels("block_ip").inc()
    return {"status": "blocked", "ip": ip, "expires_at": time.time() + body.get("duration_secs", 3600)}

@app.post("/api/v1/soar/isolate-host", tags=["soar"])
async def soar_isolate_host(body: dict):
    log.info("soar_isolate_host", host_id=body.get("host_id"))
    SOAR_EXECUTIONS.labels("isolate_host").inc()
    return {"status": "isolated", **body}

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)

@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(status_code=404, content={"detail": f"Not found: {request.url.path}"})

@app.exception_handler(500)
async def server_error(request: Request, exc):
    log.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("src.main:app", host="0.0.0.0", port=port,
                reload=os.getenv("ENVIRONMENT") == "development",
                workers=int(os.getenv("WORKERS", "1")))

# ── Reporting Router (appended) ───────────────────────────────────────────────
try:
    from .routes.reporting import router as reports_router  # if exists
    app.include_router(reports_router)
    log.info("router_loaded", name="reports")
except ImportError:
    try:
        from .reporting.routes import router as reports_router
        app.include_router(reports_router)
        log.info("router_loaded", name="reports_v2")
    except ImportError as _e:
        log.warning("router_skip", name="reports", reason=str(_e))
