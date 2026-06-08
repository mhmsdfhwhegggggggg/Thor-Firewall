"""
Thor Firewall — WebSocket Live Event Stream
بث الأحداث في الزمن الحقيقي

يوفر:
- قناة live للتهديدات
- تحديثات الإحصاءات كل ثانية
- أوامر تفاعلية (block/allow/query)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

from ..services.connection_manager import ConnectionManager
from ..services.event_bus import event_bus

router = APIRouter()
logger = logging.getLogger("thor.websocket")

# ============================================================================
# WebSocket Handler
# ============================================================================

@router.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    """
    WebSocket endpoint للأحداث الحية

    رسائل الإدخال:
        "ping"           — يُعيد "pong"
        JSON command     — تنفيذ أمر

    رسائل الإخراج:
        {"type": "stats_update", ...}
        {"type": "threat_detected", ...}
        {"type": "flow_blocked", ...}
        {"type": "alert", ...}
    """
    await ws.accept()
    client_id = f"{ws.client.host}:{ws.client.port}" if ws.client else "unknown"
    logger.info(f"WebSocket connected: {client_id}")

    connection_manager: ConnectionManager = ws.app.state.connection_manager

    try:
        await connection_manager.connect(ws)

        # إرسال رسالة ترحيب
        await ws.send_json({
            "type": "connected",
            "data": {
                "client_id": client_id,
                "server_time": time.time(),
                "version": "0.1.0",
                "capabilities": ["threats", "flows", "stats", "commands"],
            },
            "timestamp": time.time(),
        })

        # تشغيل مهام متوازية
        await asyncio.gather(
            _receive_loop(ws, client_id),
            _stats_broadcast_loop(ws, connection_manager),
            return_exceptions=True,
        )

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {client_id}")
    except Exception as e:
        logger.error(f"WebSocket error ({client_id}): {e}")
    finally:
        await connection_manager.disconnect(ws)


async def _receive_loop(ws: WebSocket, client_id: str):
    """استقبال الأوامر من العميل"""
    while True:
        try:
            data = await asyncio.wait_for(ws.receive_text(), timeout=60.0)

            if data == "ping":
                await ws.send_text("pong")
                continue

            # تفسير كـ JSON command
            try:
                cmd = json.loads(data)
                await _handle_command(ws, cmd, client_id)
            except json.JSONDecodeError:
                await ws.send_json({
                    "type": "error",
                    "message": f"Invalid JSON: {data[:100]}",
                    "timestamp": time.time(),
                })

        except asyncio.TimeoutError:
            # إرسال heartbeat
            await ws.send_json({
                "type": "heartbeat",
                "timestamp": time.time(),
            })
        except WebSocketDisconnect:
            break


async def _handle_command(ws: WebSocket, cmd: dict, client_id: str):
    """معالجة أمر من العميل"""
    cmd_type = cmd.get("type", "")

    if cmd_type == "subscribe":
        channels = cmd.get("channels", [])
        await ws.send_json({
            "type": "subscribed",
            "channels": channels,
            "timestamp": time.time(),
        })

    elif cmd_type == "block_ip":
        ip = cmd.get("ip")
        reason = cmd.get("reason", "Manual block via WebSocket")
        if ip:
            await event_bus.publish("control", {
                "action": "block_ip",
                "ip": ip,
                "reason": reason,
                "source": client_id,
            })
            await ws.send_json({
                "type": "command_result",
                "command": "block_ip",
                "status": "queued",
                "ip": ip,
                "timestamp": time.time(),
            })

    elif cmd_type == "query":
        question = cmd.get("question", "")
        if question:
            await ws.send_json({
                "type": "query_result",
                "question": question,
                "answer": "AI analysis in progress...",
                "timestamp": time.time(),
            })

    else:
        await ws.send_json({
            "type": "error",
            "message": f"Unknown command type: {cmd_type}",
            "timestamp": time.time(),
        })


async def _stats_broadcast_loop(ws: WebSocket, connection_manager: ConnectionManager):
    """بث الإحصاءات كل ثانية"""
    import random  # للبيانات المُحاكاة

    while ws.client_state == WebSocketState.CONNECTED:
        try:
            # في الإنتاج: تُقرأ من ClickHouse/Redis
            stats = {
                "type": "stats_update",
                "channel": "stats",
                "timestamp": time.time(),
                "data": {
                    "network": {
                        "packets_per_second": random.randint(500_000, 2_000_000),
                        "bits_per_second": random.randint(1_000_000_000, 10_000_000_000),
                        "active_flows": random.randint(50_000, 200_000),
                        "blocked_flows": random.randint(1_000, 5_000),
                        "suspicious_flows": random.randint(100, 500),
                        "throughput_mbps": random.uniform(1_000, 10_000),
                        "table_utilization": random.uniform(0.4, 0.8),
                    },
                    "ml": {
                        "avg_latency_us": random.uniform(50, 200),
                        "current_accuracy": random.uniform(0.995, 0.9995),
                        "inferences_per_second": random.randint(100_000, 1_000_000),
                    },
                    "system": {
                        "cpu_pct": random.uniform(2, 15),
                        "memory_mb": random.randint(400, 800),
                        "ebpf_map_utilization": random.uniform(0.4, 0.8),
                    },
                },
            }

            await ws.send_json(stats)
            await asyncio.sleep(1.0)

        except (WebSocketDisconnect, RuntimeError):
            break
        except Exception as e:
            logger.debug(f"Stats broadcast error: {e}")
            await asyncio.sleep(1.0)
