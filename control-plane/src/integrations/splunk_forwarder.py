"""
Splunk HEC Forwarder — Forward Thor events/alerts to existing Splunk infrastructure
Supports batching, SSL verification, token auth, and retry with backoff
"""
from __future__ import annotations
import asyncio, json, logging, os, time
from collections import deque
import aiohttp

logger = logging.getLogger("thor.integrations.splunk")

class SplunkHECForwarder:
    """
    Forward normalized events and alerts to Splunk HEC.
    Thor can co-exist with Splunk — feeding enriched events back.
    Env vars: SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN, SPLUNK_INDEX, SPLUNK_SOURCE
    """

    BATCH_SIZE     = 500
    FLUSH_INTERVAL = 2.0
    MAX_RETRIES    = 3
    RETRY_DELAY    = 5

    def __init__(self):
        self.hec_url    = os.getenv("SPLUNK_HEC_URL", "https://splunk:8088/services/collector")
        self.token      = os.getenv("SPLUNK_HEC_TOKEN", "")
        self.index      = os.getenv("SPLUNK_INDEX", "thor_security")
        self.source     = os.getenv("SPLUNK_SOURCE", "thor_firewall")
        self.verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "true").lower() == "true"
        self._queue: deque = deque()
        self._lock = asyncio.Lock()

    async def start(self):
        asyncio.create_task(self._flush_loop())
        logger.info("Splunk HEC forwarder started → %s", self.hec_url)

    async def forward_event(self, event: dict, sourcetype: str = "thor:event"):
        """Queue a single event for batch forwarding"""
        hec_event = {
            "time":       event.get("timestamp_ms", int(time.time() * 1000)) / 1000.0,
            "host":       event.get("source_host", "thor"),
            "source":     self.source,
            "sourcetype": sourcetype,
            "index":      self.index,
            "event":      event,
        }
        async with self._lock:
            self._queue.append(hec_event)

    async def forward_alert(self, alert: dict):
        await self.forward_event(alert, sourcetype="thor:alert")

    async def _flush_loop(self):
        while True:
            await asyncio.sleep(self.FLUSH_INTERVAL)
            await self._flush()

    async def _flush(self):
        async with self._lock:
            if not self._queue:
                return
            batch = []
            while self._queue and len(batch) < self.BATCH_SIZE:
                batch.append(self._queue.popleft())

        if not batch:
            return

        # Splunk HEC accepts newline-delimited JSON
        payload = "\n".join(json.dumps(e) for e in batch)
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type":  "application/json",
        }

        for attempt in range(self.MAX_RETRIES):
            try:
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.post(
                        self.hec_url, data=payload, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            logger.debug("Forwarded %d events to Splunk", len(batch))
                            return
                        body = await resp.text()
                        logger.error("Splunk HEC error %d: %s", resp.status, body)
            except Exception as e:
                logger.error("Splunk forward attempt %d failed: %s", attempt + 1, e)
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.RETRY_DELAY * (attempt + 1))

        # Re-queue failed batch (limited to avoid memory bloat)
        if len(self._queue) < 50000:
            async with self._lock:
                for e in reversed(batch):
                    self._queue.appendleft(e)
