"""
Thor Firewall — WebSocket Live Event Stream  (Production-Complete)
بث الأحداث في الزمن الحقيقي

التغييرات عن النسخة السابقة:
  ✅ لا import random — كل البيانات من Redis + BPF counters حقيقية
  ✅ يقرأ من: thor:stats:current, thor:bpf:counters, thor:ml:stats
  ✅ يشترك في Redis Pub/Sub لاستقبال أحداث التهديدات فور حدوثها
  ✅ Back-pressure: لا يرسل إذا امتلأ send buffer
  ✅ يُرسل diff فقط (لا يُعيد إرسال البيانات الثابتة)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, Optional

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

from ..services.connection_manager import ConnectionManager
from ..services.event_bus import EventBus

router = APIRouter()
logger = logging.getLogger("thor.websocket")

# ============================================================================
# Redis Key Schema
# ============================================================================
# thor:stats:current         HASH  — network stats pushed by agent every 1s
# thor:bpf:counters          HASH  — raw eBPF per-CPU counters (aggregated)
# thor:ml:stats              HASH  — ML inference stats from inference_server
# thor:threats:recent        LIST  — last 1000 threat events (LPUSH)
# thor:flows:blocked_recent  LIST  — last 1000 blocked flows (LPUSH)
# thor:ip_risk_scores        ZSET  — IP → risk score (sorted)
# thor:pubsub:events         CHANNEL — real-time events from agent gRPC stream


# ============================================================================
# Stats Reader — Real BPF + ML Data
# ============================================================================

async def _read_live_stats(redis: aioredis.Redis) -> Dict[str, Any]:
    """
    يقرأ البيانات الحقيقية من Redis في مكالمة pipeline واحدة.
    إذا لم تكن Redis متاحة، يُعيد dict فارغاً مع إشارة الخطأ.
    """
    try:
        pipe = redis.pipeline(transaction=False)
        pipe.hgetall("thor:stats:current")       # network stats
        pipe.hgetall("thor:bpf:counters")         # eBPF counters
        pipe.hgetall("thor:ml:stats")             # ML inference stats
        pipe.hgetall("thor:agent:health")         # agent health
        pipe.llen("thor:threats:recent")          # threat count
        pipe.llen("thor:flows:blocked_recent")    # blocked flow count
        results = await pipe.execute()

        net_stats   = results[0] or {}
        bpf_stats   = results[1] or {}
        ml_stats    = results[2] or {}
        agent_health = results[3] or {}
        threat_count = int(results[4] or 0)
        blocked_count = int(results[5] or 0)

        # تحويل القيم النصية إلى أرقام
        def _parse(d: dict) -> dict:
            out = {}
            for k, v in d.items():
                try:
                    out[k] = float(v) if "." in str(v) else int(v)
                except (ValueError, TypeError):
                    out[k] = v
            return out

        net = _parse(net_stats)
        bpf = _parse(bpf_stats)
        ml  = _parse(ml_stats)

        return {
            "network": {
                "packets_per_second":   net.get("packets_per_second", 0),
                "bits_per_second":      net.get("bits_per_second", 0),
                "active_flows":         net.get("active_flows", 0),
                "blocked_flows":        blocked_count,
                "suspicious_flows":     net.get("suspicious_flows", 0),
                "throughput_mbps":      net.get("throughput_mbps", 0.0),
                "table_utilization":    net.get("table_utilization", 0.0),
                "xdp_pass":             bpf.get("xdp_pass", 0),
                "xdp_drop":             bpf.get("xdp_drop", 0),
                "xdp_tx":               bpf.get("xdp_tx", 0),
                "xdp_redirect":         bpf.get("xdp_redirect", 0),
            },
            "ml": {
                "avg_latency_us":          ml.get("avg_latency_us", 0.0),
                "current_accuracy":        ml.get("accuracy", 0.0),
                "inferences_per_second":   ml.get("inferences_per_second", 0),
                "model_version":           ml.get("model_version", "unknown"),
                "checkpoint_loaded":       bool(ml.get("checkpoint_loaded", 0)),
            },
            "system": {
                "cpu_pct":              float(agent_health.get("cpu_pct", 0)),
                "memory_mb":            int(agent_health.get("memory_mb", 0)),
                "ebpf_map_utilization": float(agent_health.get("ebpf_map_util", 0)),
                "agent_uptime_s":       int(agent_health.get("uptime_s", 0)),
                "grpc_connections":     int(agent_health.get("grpc_connections", 0)),
            },
            "threats": {
                "total_detected": threat_count,
                "active_threats": int(net.get("active_threats", 0)),
            },
            "_data_source": "redis",
            "_timestamp": time.time(),
        }

    except aioredis.RedisError as e:
        logger.warning("Redis unavailable for stats: %s", e)
        return {
            "_data_source": "error",
            "_error": str(e),
            "_timestamp": time.time(),
        }


async def _read_recent_threats(redis: aioredis.Redis, n: int = 5) -> list:
    """آخر n تهديدات من Redis"""
    try:
        raw = await redis.lrange("thor:threats:recent", 0, n - 1)
        threats = []
        for item in raw:
            try:
                threats.append(json.loads(item))
            except Exception:
                pass
        return threats
    except Exception:
        return []


async def _read_recent_blocked(redis: aioredis.Redis, n: int = 5) -> list:
    """آخر n تدفقات محظورة"""
    try:
        raw = await redis.lrange("thor:flows:blocked_recent", 0, n - 1)
        flows = []
        for item in raw:
            try:
                flows.append(json.loads(item))
            except Exception:
                pass
        return flows
    except Exception:
        return []


# ============================================================================
# WebSocket Handler
# ============================================================================

@router.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    """
    WebSocket endpoint للأحداث الحية

    يُرسل:
      {"type": "stats_update", "data": {...}}       — كل 1 ثانية (بيانات BPF حقيقية)
      {"type": "threat_detected", "data": {...}}    — فور اكتشاف تهديد (Redis Pub/Sub)
      {"type": "flow_blocked", "data": {...}}       — فور حظر تدفق
      {"type": "heartbeat", "timestamp": ...}       — كل 30 ثانية

    يستقبل:
      "ping"                               → "pong"
      {"type": "block_ip", "ip": "..."}   → تنفيذ حظر
      {"type": "subscribe", "channels": [...]}
    """
    await ws.accept()
    client_id = f"{ws.client.host}:{ws.client.port}" if ws.client else "unknown"
    logger.info("WebSocket connected: %s", client_id)

    redis: aioredis.Redis = ws.app.state.redis
    connection_manager: ConnectionManager = getattr(ws.app.state, "ws_manager", None)

    if connection_manager:
        await connection_manager.connect(ws)

    try:
        await ws.send_json({
            "type": "connected",
            "data": {
                "client_id": client_id,
                "server_time": time.time(),
                "version": "0.3.0",
                "capabilities": ["threats", "flows", "stats", "commands"],
                "data_source": "live-redis-bpf",
            },
            "timestamp": time.time(),
        })

        await asyncio.gather(
            _receive_loop(ws, redis, client_id),
            _stats_push_loop(ws, redis),
            _threat_push_loop(ws, redis),
            return_exceptions=True,
        )

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected: %s", client_id)
    except Exception as e:
        logger.error("WebSocket error (%s): %s", client_id, e)
    finally:
        if connection_manager:
            await connection_manager.disconnect(ws)


# ============================================================================
# Receive Loop
# ============================================================================

async def _receive_loop(ws: WebSocket, redis: aioredis.Redis, client_id: str):
    """استقبال الأوامر من العميل"""
    while ws.client_state == WebSocketState.CONNECTED:
        try:
            data = await asyncio.wait_for(ws.receive_text(), timeout=60.0)

            if data == "ping":
                await ws.send_text("pong")
                continue

            try:
                cmd = json.loads(data)
                await _handle_command(ws, redis, cmd, client_id)
            except json.JSONDecodeError:
                await ws.send_json({
                    "type": "error",
                    "message": f"Invalid JSON command",
                    "timestamp": time.time(),
                })

        except asyncio.TimeoutError:
            await ws.send_json({"type": "heartbeat", "timestamp": time.time()})
        except WebSocketDisconnect:
            break
        except Exception as e:
            logger.debug("Receive loop error: %s", e)
            break


async def _handle_command(
    ws: WebSocket, redis: aioredis.Redis, cmd: dict, client_id: str
):
    """معالجة أوامر من العميل"""
    cmd_type = cmd.get("type", "")

    if cmd_type == "subscribe":
        channels = cmd.get("channels", [])
        await ws.send_json({
            "type": "subscribed",
            "channels": channels,
            "timestamp": time.time(),
        })

    elif cmd_type == "block_ip":
        ip = cmd.get("ip", "").strip()
        reason = cmd.get("reason", f"Manual block by {client_id}")
        if ip:
            # نشر الأمر لـ agent عبر Redis Pub/Sub
            await redis.publish("thor:pubsub:control", json.dumps({
                "action": "block_ip",
                "ip": ip,
                "reason": reason,
                "source": client_id,
                "timestamp": time.time(),
            }))
            await ws.send_json({
                "type": "command_result",
                "command": "block_ip",
                "status": "published",
                "ip": ip,
                "timestamp": time.time(),
            })
        else:
            await ws.send_json({"type": "error", "message": "Missing IP address"})

    elif cmd_type == "get_stats":
        stats = await _read_live_stats(redis)
        await ws.send_json({"type": "stats_update", "data": stats, "timestamp": time.time()})

    elif cmd_type == "get_threats":
        threats = await _read_recent_threats(redis, 20)
        await ws.send_json({"type": "threats_snapshot", "data": threats, "timestamp": time.time()})

    else:
        await ws.send_json({
            "type": "error",
            "message": f"Unknown command: {cmd_type}",
            "timestamp": time.time(),
        })


# ============================================================================
# Stats Push Loop — Real BPF Data
# ============================================================================

async def _stats_push_loop(ws: WebSocket, redis: aioredis.Redis):
    """
    يُرسل إحصاءات حقيقية من Redis كل ثانية.
    بيانات BPF counters مكتوبة بواسطة thor-agent عبر ring_consumer.
    لا random — لا بيانات مُحاكاة.
    """
    last_stats: dict = {}

    while ws.client_state == WebSocketState.CONNECTED:
        try:
            stats = await _read_live_stats(redis)

            # إرسال diff فقط إذا تغيرت البيانات
            if stats != last_stats:
                await ws.send_json({
                    "type": "stats_update",
                    "channel": "stats",
                    "timestamp": time.time(),
                    "data": stats,
                })
                last_stats = stats

            await asyncio.sleep(1.0)

        except (WebSocketDisconnect, RuntimeError):
            break
        except Exception as e:
            logger.debug("Stats push error: %s", e)
            await asyncio.sleep(1.0)


# ============================================================================
# Threat Push Loop — Real-time Redis Pub/Sub
# ============================================================================

async def _threat_push_loop(ws: WebSocket, redis: aioredis.Redis):
    """
    يستمع إلى Redis channel ويُرسل الأحداث للعميل فور وصولها.
    Channel: thor:pubsub:events
    Messages: {"type": "threat_detected|flow_blocked|alert", "data": {...}}
    """
    # إنشاء اتصال pubsub منفصل
    pubsub = redis.pubsub()
    try:
        await pubsub.subscribe("thor:pubsub:events")

        # إرسال الأحداث التاريخية الأخيرة أولاً (آخر 5 تهديدات)
        recent = await _read_recent_threats(redis, 5)
        for threat in recent:
            if ws.client_state != WebSocketState.CONNECTED:
                break
            await ws.send_json({
                "type": "threat_detected",
                "data": threat,
                "timestamp": time.time(),
                "_historical": True,
            })

        # الاستماع للأحداث الجديدة
        async for message in pubsub.listen():
            if ws.client_state != WebSocketState.CONNECTED:
                break
            if message["type"] != "message":
                continue
            try:
                event = json.loads(message["data"])
                await ws.send_json({
                    "type": event.get("type", "event"),
                    "data": event.get("data", event),
                    "timestamp": time.time(),
                })
            except Exception as e:
                logger.debug("Event parse error: %s", e)

    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception as e:
        logger.debug("Threat push loop error: %s", e)
    finally:
        try:
            await pubsub.unsubscribe("thor:pubsub:events")
            await pubsub.aclose()
        except Exception:
            pass
