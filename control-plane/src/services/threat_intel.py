"""
Thor Firewall — Threat Intelligence Service
خدمة استخبارات التهديدات

يتكامل مع:
  - MISP (Malware Information Sharing Platform) — أكبر قاعدة IoCs مفتوحة
  - AlienVault OTX (Open Threat Exchange)
  - Emerging Threats (Proofpoint) — قائمة blacklist مُحدَّثة يومياً
  - TAXII/STIX v2.1 — بروتوكول تبادل استخبارات التهديدات الصناعي
  - Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
  - Cisco Talos IP Reputation
  - AbuseIPDB (crowd-sourced IP reputation)

التخزين المؤقت: Redis (TTL 1 ساعة للـ IPs، 24 ساعة للـ domain)
الوضع الافتراضي: يعمل بدون مفاتيح API (بيانات عامة فقط)
"""

from __future__ import annotations

import asyncio
import gzip
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import httpx
import redis.asyncio as aioredis

logger = logging.getLogger("thor.threat_intel")

# ============================================================================
# Data Models
# ============================================================================

@dataclass
class ThreatIndicator:
    """مؤشر تهديد موحَّد من أي مصدر"""
    ip: str
    score: float                    # [0, 1] — 1 = خطير جداً
    threat_types: List[str]         # ["botnet", "scanner", "c2", "spam", ...]
    country: str = ""
    asn: int = 0
    asn_name: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    is_tor_exit: bool = False
    is_vpn: bool = False
    is_datacenter: bool = False
    confidence: float = 0.8


@dataclass
class STIXBundle:
    """حزمة STIX 2.1"""
    id: str
    type: str = "bundle"
    spec_version: str = "2.1"
    objects: List[Dict] = field(default_factory=list)


# ============================================================================
# Feed Configuration
# ============================================================================

THREAT_FEEDS = {
    # Emerging Threats — قوائم IPs خبيثة مُحدَّثة يومياً (مجانية)
    "emerging_threats_compromised": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip_list",
        "score": 0.85,
        "threat_types": ["compromised"],
        "ttl_hours": 24,
    },
    "emerging_threats_botcc": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "type": "ip_list",
        "score": 0.9,
        "threat_types": ["botnet", "c2"],
        "ttl_hours": 12,
    },
    # Abuse.ch ThreatFox — IoCs من المجتمع الأمني (مجاني)
    "threatfox_recent": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "type": "threatfox_api",
        "score": 0.9,
        "threat_types": ["malware", "c2"],
        "ttl_hours": 6,
    },
    # Feodo Tracker — خوادم C2 المعروفة (Emotet, QakBot, Dridex)
    "feodo_botnet": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        "type": "ip_list",
        "score": 0.95,
        "threat_types": ["botnet", "c2", "banking_trojan"],
        "ttl_hours": 6,
    },
    # CINS Army — مجموعة IPs مُسيئة (مجانية)
    "cins_army": {
        "url": "https://www.cinsscore.com/list/CI_BadGuys.txt",
        "type": "ip_list",
        "score": 0.8,
        "threat_types": ["scanner", "attacker"],
        "ttl_hours": 24,
    },
}

# ============================================================================
# Redis Cache Keys
# ============================================================================

CACHE_PREFIX = "thor:threat_intel"
IP_CACHE_TTL = 3600          # ساعة واحدة للـ IPs
FEED_CACHE_TTL = 86400       # يوم كامل للـ feeds
REPUTATION_TTL = 1800        # 30 دقيقة للـ reputation lookups


# ============================================================================
# Threat Intel Service
# ============================================================================

class ThreatIntelService:
    """
    خدمة استخبارات التهديدات الرئيسية

    تجمع بيانات من مصادر متعددة، تُخزّنها في Redis،
    وتوفر API سريعة للبحث عن أي IP
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,
        misp_url: str = "",
        misp_key: str = "",
        otx_key: str = "",
        abuseipdb_key: str = "",
        feed_refresh_hours: int = 6,
    ):
        self.redis = redis_client
        self.misp_url = misp_url.rstrip("/")
        self.misp_key = misp_key
        self.otx_key = otx_key
        self.abuseipdb_key = abuseipdb_key
        self.feed_refresh_hours = feed_refresh_hours

        self._http = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={"User-Agent": "Thor-Firewall/0.3 (threat-intel)"},
        )
        self._refresh_task: Optional[asyncio.Task] = None
        self._ip_cache: Dict[str, ThreatIndicator] = {}  # in-memory L1 cache

        # مجموعة IPs المحلية التي تُستثنى دائماً
        self._local_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fc00::/7"),
        ]

    async def start(self) -> None:
        """تشغيل الخدمة وتحميل الـ feeds"""
        # تحميل feeds في الخلفية (لا نُعيق بدء الـ API)
        self._refresh_task = asyncio.create_task(self._feed_refresh_loop())
        logger.info("ThreatIntelService started")

    async def stop(self) -> None:
        if self._refresh_task:
            self._refresh_task.cancel()
        await self._http.aclose()
        logger.info("ThreatIntelService stopped")

    # ─────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────

    async def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """
        البحث عن عنوان IP في قواعد التهديدات

        مسار: L1 in-memory cache → L2 Redis cache → MISP/OTX live lookup
        """
        # تحقق: لا ننظر في IPs المحلية
        if self._is_local(ip):
            return None

        # L1 cache
        if ip in self._ip_cache:
            return self._ip_cache[ip]

        # L2 Redis cache
        cache_key = f"{CACHE_PREFIX}:ip:{ip}"
        cached = await self.redis.get(cache_key)
        if cached:
            try:
                data = json.loads(cached)
                indicator = ThreatIndicator(**data)
                self._ip_cache[ip] = indicator  # warm L1
                return indicator
            except Exception:
                pass

        # Live lookup
        indicator = await self._live_lookup(ip)
        if indicator:
            # حفظ في Redis
            await self.redis.setex(
                cache_key,
                IP_CACHE_TTL,
                json.dumps({
                    "ip": indicator.ip,
                    "score": indicator.score,
                    "threat_types": indicator.threat_types,
                    "country": indicator.country,
                    "asn": indicator.asn,
                    "asn_name": indicator.asn_name,
                    "first_seen": indicator.first_seen,
                    "last_seen": indicator.last_seen,
                    "sources": indicator.sources,
                    "tags": indicator.tags,
                    "mitre_techniques": indicator.mitre_techniques,
                    "is_tor_exit": indicator.is_tor_exit,
                    "is_vpn": indicator.is_vpn,
                    "is_datacenter": indicator.is_datacenter,
                    "confidence": indicator.confidence,
                })
            )
            self._ip_cache[ip] = indicator

        return indicator

    async def is_malicious(self, ip: str, threshold: float = 0.5) -> Tuple[bool, float]:
        """
        هل هذا IP خبيث؟ يُعيد (خبيث, نقاط_الخطر)
        """
        # أولاً: تحقق من الـ feeds المحلية (أسرع — Redis set)
        in_feed = await self.redis.sismember(f"{CACHE_PREFIX}:feed_ips", ip)
        if in_feed:
            score_raw = await self.redis.hget(f"{CACHE_PREFIX}:ip_scores", ip)
            score = float(score_raw) if score_raw else 0.85
            return (True, score)

        # ثانياً: live lookup
        indicator = await self.lookup_ip(ip)
        if indicator and indicator.score >= threshold:
            return (True, indicator.score)

        return (False, 0.0)

    async def get_reputation_batch(self, ips: List[str]) -> Dict[str, Optional[ThreatIndicator]]:
        """
        البحث عن دفعة من IPs في وقت واحد (parallel Redis lookups)
        """
        results: Dict[str, Optional[ThreatIndicator]] = {}

        async def _lookup(ip: str):
            results[ip] = await self.lookup_ip(ip)

        await asyncio.gather(*[_lookup(ip) for ip in ips])
        return results

    async def enrich_flow(self, src_ip: str, dst_ip: str) -> Dict:
        """
        إثراء بيانات التدفق بمعلومات التهديدات
        يُستدعى من analytics.py و forensics.py
        """
        src_result, dst_result = await asyncio.gather(
            self.lookup_ip(src_ip),
            self.lookup_ip(dst_ip),
        )

        return {
            "src_ip": {
                "ip": src_ip,
                "is_malicious": src_result is not None and src_result.score > 0.5,
                "score": src_result.score if src_result else 0.0,
                "threat_types": src_result.threat_types if src_result else [],
                "country": src_result.country if src_result else "",
                "sources": src_result.sources if src_result else [],
            },
            "dst_ip": {
                "ip": dst_ip,
                "is_malicious": dst_result is not None and dst_result.score > 0.5,
                "score": dst_result.score if dst_result else 0.0,
                "threat_types": dst_result.threat_types if dst_result else [],
                "country": dst_result.country if dst_result else "",
            },
        }

    # ─────────────────────────────────────────────────────────────────────
    # STIX/TAXII Export
    # ─────────────────────────────────────────────────────────────────────

    async def export_stix_bundle(self, threat_indicators: List[ThreatIndicator]) -> STIXBundle:
        """
        تصدير مؤشرات التهديدات بصيغة STIX 2.1
        لمشاركتها مع SIEMs وشركاء الأمن
        """
        import uuid

        objects = []
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "name": "Thor Firewall",
            "identity_class": "system",
            "description": "Thor Next-Generation Firewall Threat Intelligence",
        }
        objects.append(identity)

        for indicator in threat_indicators:
            stix_id = f"indicator--{uuid.uuid4()}"
            pattern = f"[ipv4-addr:value = '{indicator.ip}']"

            # تعيين نوع تهديد STIX
            stix_types = []
            for t in indicator.threat_types:
                if t in ("botnet", "c2"):
                    stix_types.append("malicious-activity")
                elif t in ("scanner", "port_scan"):
                    stix_types.append("reconnaissance")
                else:
                    stix_types.append("anomalous-activity")

            stix_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": stix_id,
                "name": f"Malicious IP: {indicator.ip}",
                "description": f"Score: {indicator.score:.2f} | Types: {', '.join(indicator.threat_types)}",
                "indicator_types": list(set(stix_types)) or ["anomalous-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": indicator.first_seen or datetime.now(tz=timezone.utc).isoformat(),
                "confidence": int(indicator.confidence * 100),
                "labels": indicator.tags,
                "created_by_ref": identity["id"],
                "external_references": [
                    {
                        "source_name": src,
                        "description": f"Thor Firewall threat feed: {src}",
                    }
                    for src in indicator.sources
                ],
            }

            if indicator.mitre_techniques:
                stix_obj["kill_chain_phases"] = [
                    {"kill_chain_name": "mitre-attack", "phase_name": t}
                    for t in indicator.mitre_techniques
                ]

            objects.append(stix_obj)

        return STIXBundle(id=f"bundle--{uuid.uuid4()}", objects=objects)

    # ─────────────────────────────────────────────────────────────────────
    # MISP Integration
    # ─────────────────────────────────────────────────────────────────────

    async def _misp_lookup(self, ip: str) -> Optional[ThreatIndicator]:
        """البحث في MISP إذا كان مُعرَّفاً"""
        if not self.misp_url or not self.misp_key:
            return None

        try:
            resp = await self._http.post(
                f"{self.misp_url}/attributes/restSearch",
                headers={
                    "Authorization": self.misp_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={
                    "value": ip,
                    "type": "ip-src",
                    "returnFormat": "json",
                    "limit": 10,
                },
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()
            attributes = data.get("response", {}).get("Attribute", [])

            if not attributes:
                return None

            threat_types = list({a.get("category", "other").lower() for a in attributes})
            tags = []
            for attr in attributes:
                for tag in attr.get("Tag", []):
                    tags.append(tag.get("name", ""))

            return ThreatIndicator(
                ip=ip,
                score=0.85,
                threat_types=threat_types,
                sources=["misp"],
                tags=tags[:20],
                confidence=0.9,
            )

        except httpx.HTTPError as e:
            logger.debug("MISP lookup failed for %s: %s", ip, e)
            return None

    # ─────────────────────────────────────────────────────────────────────
    # OTX Integration
    # ─────────────────────────────────────────────────────────────────────

    async def _otx_lookup(self, ip: str) -> Optional[ThreatIndicator]:
        """البحث في AlienVault OTX"""
        if not self.otx_key:
            return None

        try:
            resp = await self._http.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self.otx_key},
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()

            pulse_count = data.get("pulse_info", {}).get("count", 0)
            if pulse_count == 0:
                return None

            pulses = data.get("pulse_info", {}).get("pulses", [])
            threat_types = list({
                tag for p in pulses for tag in p.get("tags", [])
            })
            country = data.get("country_name", "")

            score = min(0.6 + (pulse_count * 0.05), 0.99)

            return ThreatIndicator(
                ip=ip,
                score=score,
                threat_types=threat_types[:5] or ["malicious"],
                country=country,
                sources=["otx"],
                tags=[p.get("name", "")[:50] for p in pulses[:5]],
                confidence=0.8,
            )

        except httpx.HTTPError as e:
            logger.debug("OTX lookup failed for %s: %s", ip, e)
            return None

    # ─────────────────────────────────────────────────────────────────────
    # AbuseIPDB Integration
    # ─────────────────────────────────────────────────────────────────────

    async def _abuseipdb_lookup(self, ip: str) -> Optional[ThreatIndicator]:
        """البحث في AbuseIPDB (crowd-sourced reports)"""
        if not self.abuseipdb_key:
            return None

        try:
            resp = await self._http.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            score_pct = data.get("abuseConfidenceScore", 0)
            if score_pct < 20:
                return None

            return ThreatIndicator(
                ip=ip,
                score=score_pct / 100.0,
                threat_types=["abuse"],
                country=data.get("countryCode", ""),
                asn=data.get("asnNumber", 0) or 0,
                asn_name=data.get("isp", ""),
                is_tor_exit=data.get("isTor", False),
                sources=["abuseipdb"],
                confidence=min(score_pct / 100.0 * 1.1, 1.0),
            )

        except httpx.HTTPError as e:
            logger.debug("AbuseIPDB lookup failed for %s: %s", ip, e)
            return None

    # ─────────────────────────────────────────────────────────────────────
    # Aggregated Live Lookup
    # ─────────────────────────────────────────────────────────────────────

    async def _live_lookup(self, ip: str) -> Optional[ThreatIndicator]:
        """استعلام موازٍ من جميع المصادر المُهيَّأة"""
        tasks = [
            self._misp_lookup(ip),
            self._otx_lookup(ip),
            self._abuseipdb_lookup(ip),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [r for r in results if isinstance(r, ThreatIndicator)]

        if not valid:
            return None

        # دمج النتائج: نأخذ أعلى score وندمج البيانات
        merged = max(valid, key=lambda x: x.score)
        all_sources = []
        all_types = []
        all_tags = []
        for r in valid:
            all_sources.extend(r.sources)
            all_types.extend(r.threat_types)
            all_tags.extend(r.tags)

        merged.sources = list(set(all_sources))
        merged.threat_types = list(set(all_types))[:10]
        merged.tags = list(set(all_tags))[:20]

        return merged

    # ─────────────────────────────────────────────────────────────────────
    # Feed Refresh Loop
    # ─────────────────────────────────────────────────────────────────────

    async def _feed_refresh_loop(self) -> None:
        """تحديث الـ feeds كل `feed_refresh_hours` ساعة"""
        while True:
            logger.info("Refreshing threat intelligence feeds...")
            await self._refresh_all_feeds()
            await asyncio.sleep(self.feed_refresh_hours * 3600)

    async def _refresh_all_feeds(self) -> None:
        """تحميل وتخزين جميع الـ feeds في Redis"""
        tasks = [
            self._load_feed(name, config)
            for name, config in THREAT_FEEDS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        total_ips = 0
        for name, result in zip(THREAT_FEEDS.keys(), results):
            if isinstance(result, Exception):
                logger.warning("Feed %s failed: %s", name, result)
            else:
                total_ips += result
                logger.debug("Feed %s: %d IPs loaded", name, result)

        logger.info("Feed refresh complete: %d total IPs in blacklist", total_ips)

    async def _load_feed(self, name: str, config: dict) -> int:
        """تحميل feed واحد وإضافة IPs إلى Redis set"""
        feed_type = config["type"]
        score = config["score"]
        threat_types = config["threat_types"]

        try:
            if feed_type == "ip_list":
                return await self._load_ip_list_feed(config["url"], score, threat_types)
            elif feed_type == "threatfox_api":
                return await self._load_threatfox_feed(score, threat_types)
            else:
                logger.warning("Unknown feed type: %s", feed_type)
                return 0
        except Exception as e:
            logger.error("Failed to load feed %s: %s", name, e)
            return 0

    async def _load_ip_list_feed(self, url: str, score: float, threat_types: List[str]) -> int:
        """تحميل ملف نصي يحتوي على IPs (سطر واحد لكل IP)"""
        try:
            resp = await self._http.get(url, timeout=30.0)
            resp.raise_for_status()
            text = resp.text
        except httpx.HTTPError as e:
            raise RuntimeError(f"HTTP error loading {url}: {e}")

        count = 0
        pipe = self.redis.pipeline(transaction=False)

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # استخراج IP (قد يكون مع CIDR أو تعليق)
            ip = line.split()[0].split("/")[0]

            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                continue

            if self._is_local(ip):
                continue

            pipe.sadd(f"{CACHE_PREFIX}:feed_ips", ip)
            pipe.hset(f"{CACHE_PREFIX}:ip_scores", ip, str(score))
            count += 1

            # flush كل 5000 إدخال
            if count % 5000 == 0:
                await pipe.execute()
                pipe = self.redis.pipeline(transaction=False)

        if count % 5000 != 0:
            await pipe.execute()

        return count

    async def _load_threatfox_feed(self, score: float, threat_types: List[str]) -> int:
        """تحميل بيانات ThreatFox API"""
        try:
            resp = await self._http.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": 3},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()

            iocs = data.get("data", [])
            count = 0
            pipe = self.redis.pipeline(transaction=False)

            for ioc in iocs:
                if ioc.get("ioc_type") != "ip:port":
                    continue
                ip_port = ioc.get("ioc", "")
                ip = ip_port.split(":")[0] if ":" in ip_port else ip_port

                try:
                    ipaddress.IPv4Address(ip)
                except ValueError:
                    continue

                pipe.sadd(f"{CACHE_PREFIX}:feed_ips", ip)
                pipe.hset(f"{CACHE_PREFIX}:ip_scores", ip, str(score))
                count += 1

            await pipe.execute()
            return count

        except Exception as e:
            raise RuntimeError(f"ThreatFox API error: {e}")

    # ─────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────

    def _is_local(self, ip: str) -> bool:
        """هل هذا عنوان محلي؟"""
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in net for net in self._local_ranges)
        except ValueError:
            return True  # IPv6 أو غير صالح — نتجاهله في IPv4 feeds
