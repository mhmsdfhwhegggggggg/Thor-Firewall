"""Thor Firewall — Event Bus (Redis Pub/Sub → WebSocket)"""
import json
import logging

logger = logging.getLogger("thor.event-bus")


class EventBus:
    """
    Listens to Redis pub/sub channel and broadcasts events
    to all connected WebSocket clients.
    """

    def __init__(self, redis, ws_manager):
        self.redis = redis
        self.ws_manager = ws_manager

    async def listen(self):
        """Main event loop — subscribe to Redis and forward to WebSockets."""
        pubsub = self.redis.pubsub()
        await pubsub.subscribe("thor:events", "thor:alerts", "thor:stats")

        logger.info("Event bus listening on thor:events, thor:alerts, thor:stats")

        async for message in pubsub.listen():
            if message["type"] != "message":
                continue

            try:
                channel = message["channel"]
                data = json.loads(message["data"])

                # Add channel context
                data["channel"] = channel

                await self.ws_manager.broadcast(data)

            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in event: {message['data']}")
            except Exception as e:
                logger.error(f"Event bus error: {e}")

    async def publish_alert(self, alert: dict):
        """Publish a security alert."""
        await self.redis.publish("thor:alerts", json.dumps(alert))

    async def publish_stats(self, stats: dict):
        """Publish dashboard statistics."""
        await self.redis.publish("thor:stats", json.dumps(stats))
