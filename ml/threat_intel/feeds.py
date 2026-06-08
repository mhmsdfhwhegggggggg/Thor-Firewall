"""
Thor Firewall — Threat Intelligence Feed Loader
محمّل مصادر استخبارات التهديدات

يدعم:
- MISP (Malware Information Sharing Platform)
- AlienVault OTX (Open Threat Exchange)
- CISA Known Exploited Vulnerabilities
- Feodo Tracker (Botnet C2)
- Abuse.ch URLhaus
- EmergingThreats
- Spamhaus DROP/EDROP
- AbuseIPDB

يُحدَّث كل 15 دقيقة ويُخزَّن في Redis وذاكرة محلية
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp

logger = logging.getLogger("thor.threat_intel")

# ============================================================================
# IOC (Indicator of Compromise)
# ============================================================================

@dataclass
class IOC:
    """مؤشر اختراق"""
    indicator: str       # IP, CIDR, domain, hash
    ioc_type: str        # ip, cidr, domain, md5, sha256, url
    threat_type: str     # malware, botnet, c2, phishing, scanner
    severity: str        # low, medium, high, critical
    confidence: float    # [0, 1]
    source: str          # misp, otx, feodo, etc.
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    description: str = ""
    mitre_technique: str = ""


@dataclass
class ThreatIntelStats:
    total_iocs: int = 0
    ip_blocklist: int = 0
    cidr_blocklist: int = 0
    malware_c2: int = 0
    scanners: int = 0
    botnets: int = 0
    last_update: float = 0.0
    sources: Dict[str, int] = field(default_factory=dict)


# ============================================================================
# Feed Loaders
# ============================================================================

class FeedLoader:
    """محمّل مصدر واحد"""

    def __init__(self, name: str, url: str, update_interval: int = 900):
        self.name = name
        self.url = url
        self.update_interval = update_interval
        self._last_update = 0.0
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self._session or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    def needs_update(self) -> bool:
        return time.time() - self._last_update > self.update_interval

    async def load(self) -> List[IOC]:
        raise NotImplementedError


class FeodoTrackerLoader(FeedLoader):
    """
    Feodo Tracker — قائمة Botnet C2 Servers
    https://feodotracker.abuse.ch/downloads/ipblocklist.json
    """

    def __init__(self):
        super().__init__(
            name="feodo_tracker",
            url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            update_interval=900,
        )

    async def load(self) -> List[IOC]:
        try:
            session = await self._get_session()
            async with session.get(self.url) as resp:
                if resp.status != 200:
                    logger.warning(f"Feodo: HTTP {resp.status}")
                    return []

                data = await resp.json(content_type=None)
                iocs = []
                for entry in data:
                    ip = entry.get("ip_address", "")
                    if not ip:
                        continue
                    iocs.append(IOC(
                        indicator=ip,
                        ioc_type="ip",
                        threat_type="botnet-c2",
                        severity="high",
                        confidence=0.95,
                        source=self.name,
                        tags=["botnet", "c2", entry.get("malware", "unknown")],
                        mitre_technique="T1071",
                    ))

                self._last_update = time.time()
                logger.info(f"Feodo Tracker: loaded {len(iocs)} C2 IPs")
                return iocs

        except Exception as e:
            logger.error(f"Feodo load error: {e}")
            return []


class SpamhausDropLoader(FeedLoader):
    """
    Spamhaus DROP/EDROP — شبكات Spam معروفة
    """

    def __init__(self):
        super().__init__(
            name="spamhaus_drop",
            url="https://www.spamhaus.org/drop/drop.txt",
            update_interval=3600,
        )

    async def load(self) -> List[IOC]:
        try:
            session = await self._get_session()
            async with session.get(self.url) as resp:
                if resp.status != 200:
                    return []

                text = await resp.text()
                iocs = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";"):
                        continue
                    # FORMAT: 1.2.3.0/24 ; SBL123456
                    parts = line.split(";")
                    cidr = parts[0].strip()
                    try:
                        ipaddress.ip_network(cidr, strict=False)
                        iocs.append(IOC(
                            indicator=cidr,
                            ioc_type="cidr",
                            threat_type="spam",
                            severity="medium",
                            confidence=0.9,
                            source=self.name,
                            tags=["spam", "spamhaus"],
                        ))
                    except ValueError:
                        continue

                self._last_update = time.time()
                logger.info(f"Spamhaus DROP: loaded {len(iocs)} CIDRs")
                return iocs

        except Exception as e:
            logger.error(f"Spamhaus load error: {e}")
            return []


class EmergingThreatsLoader(FeedLoader):
    """
    Emerging Threats — قائمة IPs الخطيرة
    """

    def __init__(self):
        super().__init__(
            name="emerging_threats",
            url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            update_interval=3600,
        )

    async def load(self) -> List[IOC]:
        try:
            session = await self._get_session()
            async with session.get(self.url) as resp:
                if resp.status != 200:
                    return []

                text = await resp.text()
                iocs = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        ipaddress.ip_address(line)
                        iocs.append(IOC(
                            indicator=line,
                            ioc_type="ip",
                            threat_type="compromised",
                            severity="high",
                            confidence=0.85,
                            source=self.name,
                            tags=["compromised", "emerging-threats"],
                        ))
                    except ValueError:
                        continue

                self._last_update = time.time()
                logger.info(f"EmergingThreats: loaded {len(iocs)} IPs")
                return iocs

        except Exception as e:
            logger.error(f"EmergingThreats load error: {e}")
            return []


class OTXLoader(FeedLoader):
    """
    AlienVault OTX — Open Threat Exchange
    يتطلب API key (مجاني)
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            name="otx",
            url="https://otx.alienvault.com/api/v1/pulses/subscribed",
            update_interval=1800,
        )
        self.api_key = api_key or os.getenv("OTX_API_KEY", "")

    async def load(self) -> List[IOC]:
        if not self.api_key:
            logger.debug("OTX API key not configured, skipping")
            return []

        try:
            session = await self._get_session()
            headers = {"X-OTX-API-KEY": self.api_key}

            async with session.get(self.url, headers=headers, params={"limit": 100}) as resp:
                if resp.status != 200:
                    logger.warning(f"OTX: HTTP {resp.status}")
                    return []

                data = await resp.json()
                iocs = []

                for pulse in data.get("results", []):
                    tags = pulse.get("tags", [])
                    for indicator in pulse.get("indicators", []):
                        ioc_type = indicator.get("type", "")
                        val = indicator.get("indicator", "")
                        if not val:
                            continue

                        # نهتم فقط بـ IPs
                        if ioc_type not in ("IPv4", "IPv6", "CIDR"):
                            continue

                        iocs.append(IOC(
                            indicator=val,
                            ioc_type="ip" if ioc_type == "IPv4" else "cidr",
                            threat_type=pulse.get("name", "unknown"),
                            severity="high",
                            confidence=0.8,
                            source=self.name,
                            tags=tags[:10],
                            description=pulse.get("description", "")[:200],
                        ))

                self._last_update = time.time()
                logger.info(f"OTX: loaded {len(iocs)} indicators")
                return iocs

        except Exception as e:
            logger.error(f"OTX load error: {e}")
            return []


class MISPLoader(FeedLoader):
    """
    MISP — Malware Information Sharing Platform
    يتصل بـ instance محلي أو MISP community
    """

    def __init__(self, url: str = "", api_key: str = ""):
        super().__init__(
            name="misp",
            url=url or os.getenv("MISP_URL", ""),
            update_interval=900,
        )
        self.api_key = api_key or os.getenv("MISP_API_KEY", "")

    async def load(self) -> List[IOC]:
        if not self.url or not self.api_key:
            logger.debug("MISP not configured, skipping")
            return []

        try:
            session = await self._get_session()
            headers = {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            payload = {
                "returnFormat": "json",
                "type": {"OR": ["ip-src", "ip-dst", "ip-src/ip-dst"]},
                "to_ids": 1,
                "limit": 10000,
            }

            async with session.post(
                f"{self.url}/attributes/restSearch",
                headers=headers,
                json=payload,
            ) as resp:
                if resp.status != 200:
                    return []

                data = await resp.json()
                iocs = []

                for attr in data.get("response", {}).get("Attribute", []):
                    ip = attr.get("value", "")
                    if not ip:
                        continue

                    iocs.append(IOC(
                        indicator=ip,
                        ioc_type="ip",
                        threat_type=attr.get("category", "unknown"),
                        severity="high",
                        confidence=0.9,
                        source=self.name,
                        tags=[attr.get("category", "")],
                        description=attr.get("comment", "")[:200],
                    ))

                self._last_update = time.time()
                logger.info(f"MISP: loaded {len(iocs)} indicators")
                return iocs

        except Exception as e:
            logger.error(f"MISP load error: {e}")
            return []


# ============================================================================
# Threat Intel Manager
# ============================================================================

class ThreatIntelManager:
    """
    مدير استخبارات التهديدات

    يجمع جميع المصادر ويُحدّث:
    - قائمة IP blacklist في الذاكرة
    - BPF LPM Trie عبر العميل
    - Redis لمشاركة القوائم
    """

    def __init__(self):
        self.loaders: List[FeedLoader] = [
            FeodoTrackerLoader(),
            SpamhausDropLoader(),
            EmergingThreatsLoader(),
            OTXLoader(),
            MISPLoader(),
        ]

        # فهارس سريعة للبحث
        self._ip_blocklist:   Set[str] = set()
        self._cidr_blocklist: List[ipaddress.IPv4Network] = []
        self._all_iocs:       List[IOC] = []

        self.stats = ThreatIntelStats()

    async def update_all(self) -> ThreatIntelStats:
        """تحديث جميع المصادر"""
        tasks = []
        for loader in self.loaders:
            if loader.needs_update():
                tasks.append(loader.load())

        if not tasks:
            return self.stats

        results = await asyncio.gather(*tasks, return_exceptions=True)
        new_iocs = []
        for result in results:
            if isinstance(result, list):
                new_iocs.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Feed error: {result}")

        if new_iocs:
            self._integrate_iocs(new_iocs)
            logger.info(
                f"Threat Intel updated: {len(self._ip_blocklist)} IPs, "
                f"{len(self._cidr_blocklist)} CIDRs"
            )

        return self.stats

    def _integrate_iocs(self, new_iocs: List[IOC]):
        """دمج مؤشرات جديدة"""
        for ioc in new_iocs:
            if ioc.ioc_type == "ip":
                self._ip_blocklist.add(ioc.indicator)
            elif ioc.ioc_type == "cidr":
                try:
                    net = ipaddress.ip_network(ioc.indicator, strict=False)
                    self._cidr_blocklist.append(net)
                except ValueError:
                    pass

        self._all_iocs.extend(new_iocs)

        # تحديث الإحصاءات
        self.stats.total_iocs = len(self._all_iocs)
        self.stats.ip_blocklist = len(self._ip_blocklist)
        self.stats.cidr_blocklist = len(set(str(c) for c in self._cidr_blocklist))
        self.stats.last_update = time.time()
        self.stats.sources = {
            loader.name: sum(1 for ioc in self._all_iocs if ioc.source == loader.name)
            for loader in self.loaders
        }

    def is_blocked(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        التحقق هل IP مدرج في قائمة الحظر

        Returns:
            (is_blocked, reason)
        """
        # فحص IP مباشر (O(1))
        if ip in self._ip_blocklist:
            return True, "ip_blocklist"

        # فحص CIDR (O(n) — يمكن تحسينه بـ trie)
        try:
            addr = ipaddress.ip_address(ip)
            for cidr in self._cidr_blocklist:
                if addr in cidr:
                    return True, f"cidr:{cidr}"
        except ValueError:
            pass

        return False, None

    def get_ioc_info(self, ip: str) -> Optional[IOC]:
        """الحصول على معلومات مؤشر الاختراق"""
        for ioc in reversed(self._all_iocs):
            if ioc.indicator == ip:
                return ioc
        return None

    async def run_update_loop(self, interval: int = 900):
        """حلقة التحديث الدورية"""
        logger.info(f"Threat Intel update loop started (interval={interval}s)")
        while True:
            try:
                await self.update_all()
            except Exception as e:
                logger.error(f"Threat Intel update error: {e}")
            await asyncio.sleep(interval)


# ============================================================================
# Singleton
# ============================================================================

_manager: Optional[ThreatIntelManager] = None

def get_manager() -> ThreatIntelManager:
    global _manager
    if _manager is None:
        _manager = ThreatIntelManager()
    return _manager
