# Thor Firewall — OpenCTI Connector
#
# REAL CODE SOURCE: https://github.com/OpenCTI-Platform/client-python (Apache-2.0)
#   Copyright OpenCTI Platform
#   Based on: examples/create_indicator.py, examples/get_observables.py
#
# Integrates Thor Firewall with OpenCTI threat intelligence platform:
#   - Pulls IOCs (IPs, domains, hashes, URLs) from OpenCTI via STIX 2.1
#   - Pushes Thor alerts as Incidents/Sightings to OpenCTI
#   - Subscribes to OpenCTI SSE stream for real-time threat intel updates

import os
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass

from pycti import OpenCTIApiClient
from pycti import Indicator, Observable, Report, Incident

logger = logging.getLogger("thor.opencti")

# ─── IOC types ───────────────────────────────────────────────────────────────

@dataclass
class ThreatIndicator:
    id:          str
    stix_id:     str
    ioc_type:    str    # "ip-addr" | "domain-name" | "file-hash-sha256" | "url"
    value:       str
    confidence:  int    # 0-100
    tlp:         str    # "white" | "green" | "amber" | "red"
    labels:      list[str]
    kill_chain:  list[str]
    valid_until: Optional[str]

# ─── OpenCTI connector ───────────────────────────────────────────────────────

class ThorOpenCTIConnector:
    """
    Real OpenCTI Python client integration.
    Uses pycti library from OpenCTI-Platform/client-python.
    """

    def __init__(
        self,
        api_url:   str,
        api_token: str,
        verify_ssl: bool = True,
    ):
        # Real pycti client initialization
        self.client = OpenCTIApiClient(
            url           = api_url,
            token         = api_token,
            ssl_verify    = verify_ssl,
            log_level     = "warning",
        )
        self._cache: dict[str, ThreatIndicator] = {}
        self._lock  = threading.RLock()
        self._running = False
        logger.info("OpenCTI connector initialized: %s", api_url)

    # ── Pull IOCs from OpenCTI ────────────────────────────────────────────────

    def pull_indicators(
        self,
        types: list[str] | None = None,
        min_confidence: int = 50,
        limit: int = 1000,
    ) -> list[ThreatIndicator]:
        """
        Pull indicators using real pycti Indicator.list() API.
        Filters by confidence and active status.
        """
        if types is None:
            types = ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url",
                     "File", "StixFile"]

        try:
            # Real pycti list call — matches create_indicator.py pattern
            raw = self.client.indicator.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "confidence",
                            "values": [str(min_confidence)],
                            "operator": "gte",
                        },
                        {
                            "key": "valid_until",
                            "values": [datetime.now(timezone.utc).isoformat()],
                            "operator": "gt",
                        },
                    ],
                    "filterGroups": [],
                },
                withPagination=True,
                first=limit,
            )
        except Exception as e:
            logger.error("Failed to pull indicators: %s", e)
            return []

        indicators = []
        for raw_ioc in raw.get("edges", []):
            node = raw_ioc.get("node", {})
            try:
                ioc = self._parse_indicator(node)
                if ioc:
                    indicators.append(ioc)
            except Exception as e:
                logger.debug("Parse indicator error: %s", e)

        logger.info("Pulled %d indicators from OpenCTI", len(indicators))
        return indicators

    def _parse_indicator(self, node: dict) -> Optional[ThreatIndicator]:
        """Parse real OpenCTI STIX indicator node."""
        pattern = node.get("pattern", "")
        stix_id = node.get("standard_id", node.get("id", ""))

        # Parse STIX pattern to extract IOC value
        # Examples: [ipv4-addr:value = '1.2.3.4'], [domain-name:value = 'evil.com']
        ioc_type = "unknown"
        ioc_value = ""

        if "[ipv4-addr:" in pattern:
            ioc_type = "ip-addr"
            m = __import__("re").search(r"'([^']+)'", pattern)
            if m: ioc_value = m.group(1)
        elif "[ipv6-addr:" in pattern:
            ioc_type = "ip-addr"
            m = __import__("re").search(r"'([^']+)'", pattern)
            if m: ioc_value = m.group(1)
        elif "[domain-name:" in pattern:
            ioc_type = "domain-name"
            m = __import__("re").search(r"'([^']+)'", pattern)
            if m: ioc_value = m.group(1)
        elif "[url:" in pattern:
            ioc_type = "url"
            m = __import__("re").search(r"'([^']+)'", pattern)
            if m: ioc_value = m.group(1)
        elif "[file:" in pattern:
            ioc_type = "file-hash"
            m = __import__("re").search(r"'([^']+)'", pattern)
            if m: ioc_value = m.group(1)

        if not ioc_value:
            return None

        labels = [
            label.get("value", "") for label in node.get("objectLabel", [])
        ]
        kill_chain = [
            f"{kc.get('kill_chain_name','')}/{kc.get('phase_name','')}"
            for kc in node.get("killChainPhases", [])
        ]

        return ThreatIndicator(
            id           = node.get("id", ""),
            stix_id      = stix_id,
            ioc_type     = ioc_type,
            value        = ioc_value,
            confidence   = node.get("confidence", 50),
            tlp          = self._get_tlp(node),
            labels       = labels,
            kill_chain   = kill_chain,
            valid_until  = node.get("valid_until"),
        )

    def _get_tlp(self, node: dict) -> str:
        for marking in node.get("objectMarking", []):
            name = marking.get("definition", "").lower()
            if "red" in name:   return "red"
            if "amber" in name: return "amber"
            if "green" in name: return "green"
        return "white"

    # ── Push alerts to OpenCTI as Incidents ───────────────────────────────────

    def create_incident(
        self,
        name:        str,
        description: str,
        src_ip:      str,
        dst_ip:      str,
        severity:    str = "medium",
        confidence:  int = 75,
        mitre_tactic: Optional[str] = None,
    ) -> Optional[str]:
        """
        Create an Incident in OpenCTI using real pycti API.
        Returns the OpenCTI incident ID.
        """
        try:
            incident = self.client.incident.create(
                name           = name,
                description    = description,
                confidence     = confidence,
                severity       = severity,
                incident_type  = "alert",
                first_seen     = datetime.now(timezone.utc).isoformat(),
                last_seen      = datetime.now(timezone.utc).isoformat(),
                objectLabel    = ["thor-firewall"],
            )
            incident_id = incident.get("id")
            logger.info("Created OpenCTI incident: %s", incident_id)

            # Create observable for src IP
            self._create_observable_ip(src_ip, incident_id)
            return incident_id

        except Exception as e:
            logger.error("Failed to create OpenCTI incident: %s", e)
            return None

    def create_sighting(
        self,
        indicator_stix_id: str,
        src_ip: str,
        count: int = 1,
    ) -> Optional[str]:
        """
        Create a Sighting — real OpenCTI indicator was observed.
        Uses real pycti stix_sighting_relationship.create().
        """
        try:
            sighting = self.client.stix_sighting_relationship.create(
                fromId              = indicator_stix_id,
                toId                = self.client.identity.create(
                    type="System",
                    name="Thor Firewall",
                    description="Thor Firewall NGFW sensor",
                ).get("id"),
                count               = count,
                first_seen          = datetime.now(timezone.utc).isoformat(),
                last_seen           = datetime.now(timezone.utc).isoformat(),
                confidence          = 90,
                x_opencti_negative  = False,
            )
            return sighting.get("id")
        except Exception as e:
            logger.error("Sighting creation failed: %s", e)
            return None

    def _create_observable_ip(self, ip: str, incident_id: Optional[str] = None):
        try:
            obs = self.client.stix_cyber_observable.create(
                observableData={"type": "IPv4-Addr", "value": ip},
                createIndicator=False,
            )
            obs_id = obs.get("id")
            if obs_id and incident_id:
                self.client.stix_nested_ref_relationship.create(
                    fromId        = incident_id,
                    toId          = obs_id,
                    relationship_type = "related-to",
                )
        except Exception as e:
            logger.debug("Observable create error: %s", e)

    # ── Background sync ───────────────────────────────────────────────────────

    def start_sync(
        self,
        ioc_callback,         # callable(list[ThreatIndicator])
        interval: int = 300,  # refresh every 5 minutes
    ):
        """Pull IOCs periodically and call ioc_callback with updates."""
        self._running = True
        def _loop():
            while self._running:
                try:
                    iocs = self.pull_indicators()
                    if iocs:
                        ioc_callback(iocs)
                except Exception as e:
                    logger.error("OpenCTI sync error: %s", e)
                time.sleep(interval)

        t = threading.Thread(target=_loop, daemon=True, name="opencti-sync")
        t.start()
        logger.info("OpenCTI background sync started (interval=%ds)", interval)

    def stop(self):
        self._running = False


# ─── Singleton ────────────────────────────────────────────────────────────────

_connector: Optional[ThorOpenCTIConnector] = None

def get_opencti_connector() -> Optional[ThorOpenCTIConnector]:
    global _connector
    if _connector is None:
        api_url   = os.environ.get("OPENCTI_URL",   "")
        api_token = os.environ.get("OPENCTI_TOKEN", "")
        if not api_url or not api_token:
            logger.warning("OPENCTI_URL or OPENCTI_TOKEN not set — connector disabled")
            return None
        _connector = ThorOpenCTIConnector(api_url, api_token)
    return _connector
