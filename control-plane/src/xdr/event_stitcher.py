"""
Thor XDR — Cross-Source Event Stitcher
يربط أحداثاً من مصادر مختلفة تنتمي لنفس الهجوم.

المصادر المدعومة:
- Network flows (eBPF/XDP agent)
- Endpoint EDR events (مستقبلاً)
- Cloud logs (AWS CloudTrail, Azure Activity)
- Auth logs (Keycloak, Active Directory)
- DNS queries
- Threat Intelligence matches
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import structlog

log = structlog.get_logger("thor.xdr.stitcher")


@dataclass
class RawEvent:
    """حدث خام من أي مصدر"""
    source:      str            # "network", "endpoint", "cloud_aws", "auth", "dns"
    event_type:  str
    timestamp:   float
    src_ip:      Optional[str]  = None
    dst_ip:      Optional[str]  = None
    username:    Optional[str]  = None
    hostname:    Optional[str]  = None
    ioc_hash:    Optional[str]  = None   # file hash أو domain hash
    details:     dict           = field(default_factory=dict)

    @property
    def identity_keys(self) -> List[Tuple[str, str]]:
        """المفاتيح المستخدمة لربط هذا الحدث بأحداث أخرى"""
        keys = []
        if self.src_ip:
            keys.append(("ip", self.src_ip))
        if self.dst_ip:
            keys.append(("ip", self.dst_ip))
        if self.username:
            keys.append(("user", self.username))
        if self.hostname:
            keys.append(("host", self.hostname))
        if self.ioc_hash:
            keys.append(("ioc", self.ioc_hash))
        return keys


@dataclass
class StitchedIncident:
    incident_id:  str
    title:        str
    events:       List[RawEvent]
    identity_key: Tuple[str, str]   # الرابط الأساسي (ip, "1.2.3.4")
    start_time:   float
    end_time:     float
    sources:      List[str]         # المصادر المشاركة
    event_count:  int               = 0

    def __post_init__(self):
        self.event_count = len(self.events)

    @property
    def duration_minutes(self) -> float:
        return (self.end_time - self.start_time) / 60


class EventStitcher:
    """
    Correlation Rules:
    1. same_source_ip       — نفس src_ip في 30 دقيقة
    2. same_target_host     — نفس dst_ip / hostname في ساعة
    3. same_user_identity   — نفس username في 24 ساعة
    4. shared_ioc           — نفس file hash أو domain في 7 أيام
    """

    WINDOWS = {
        "ip":   1800,          # 30 دقيقة
        "host": 3600,          # ساعة
        "user": 86400,         # يوم
        "ioc":  604800,        # أسبوع
    }

    def __init__(self):
        # (key_type, key_value) → [RawEvent]
        self._buckets: Dict[Tuple[str, str], List[RawEvent]] = {}
        self._incidents: List[StitchedIncident] = []

    def ingest(self, event: RawEvent) -> List[StitchedIncident]:
        """
        استوعب حدثاً وأعد قائمة الـ incidents المحدَّثة أو الجديدة.
        """
        new_incidents = []
        for key in event.identity_keys:
            window = self.WINDOWS.get(key[0], 3600)
            cutoff = time.time() - window

            if key not in self._buckets:
                self._buckets[key] = []

            self._buckets[key] = [e for e in self._buckets[key] if e.timestamp > cutoff]
            self._buckets[key].append(event)

            if len(self._buckets[key]) >= 2:
                incident = self._build_incident(key, self._buckets[key])
                if incident:
                    new_incidents.append(incident)
                    self._incidents.append(incident)

        return new_incidents

    def _build_incident(self,
                         key: Tuple[str, str],
                         events: List[RawEvent]) -> Optional[StitchedIncident]:
        if len(events) < 2:
            return None

        sources = list({e.source for e in events})
        if len(sources) < 1:
            return None

        incident_id = hashlib.md5(
            f"{key[0]}:{key[1]}:{int(events[0].timestamp)}".encode()
        ).hexdigest()[:12]

        title = self._generate_title(key, events)

        return StitchedIncident(
            incident_id  = f"INC-{incident_id.upper()}",
            title        = title,
            events       = events.copy(),
            identity_key = key,
            start_time   = min(e.timestamp for e in events),
            end_time     = max(e.timestamp for e in events),
            sources      = sources,
        )

    def _generate_title(self,
                         key: Tuple[str, str],
                         events: List[RawEvent]) -> str:
        key_type, key_val = key
        types = list({e.event_type for e in events})[:3]
        if key_type == "ip":
            return f"Multi-event incident from {key_val}: {', '.join(types)}"
        elif key_type == "user":
            return f"Suspicious user activity: {key_val} ({', '.join(types)})"
        elif key_type == "host":
            return f"Host under attack: {key_val} ({', '.join(types)})"
        else:
            return f"IOC cluster detected: {key_val[:16]}... ({', '.join(types)})"

    def get_recent_incidents(self, limit: int = 50) -> List[StitchedIncident]:
        return sorted(self._incidents, key=lambda i: i.end_time, reverse=True)[:limit]
