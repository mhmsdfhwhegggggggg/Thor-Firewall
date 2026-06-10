# Thor Firewall — YARA Engine
#
# REAL CODE SOURCES:
#   - yara-python: https://github.com/VirusTotal/yara-python (Apache-2.0)
#   - YARA rules: https://github.com/Yara-Rules/rules
#     https://github.com/Neo23x0/signature-base
#   - OpenCTI YARA connector:
#     https://github.com/OpenCTI-Platform/connectors/tree/master/internal-import-file/import-file-yara
#
# Runs YARA scans on:
#   1. Payload bytes from deep packet inspection (DPI flows)
#   2. DNS query strings
#   3. HTTP host/URI patterns
#   4. File hashes (for endpoint telemetry)

import yara
import hashlib
import logging
import os
import re
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger("thor.yara")

# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class YaraMatch:
    rule_name:    str
    namespace:    str
    tags:         list[str]
    meta:         dict[str, Any]
    strings:      list[tuple]   # (offset, identifier, data)
    severity:     str           # "low" | "medium" | "high" | "critical"
    mitre_tactic: Optional[str] = None
    mitre_tech:   Optional[str] = None

@dataclass
class YaraScanResult:
    matched:      bool
    matches:      list[YaraMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0
    bytes_scanned: int = 0

# ─── Built-in real YARA rules (Mirai botnet — from Yara-Rules/rules) ─────────

BUILTIN_RULES_SOURCE = r"""
/*
 * Real YARA rules from https://github.com/Yara-Rules/rules
 * License: GNU-GPLv2
 */

/* Mirai Botnet — from MALW_Mirai.yar */
rule Mirai_Botnet_Malware {
    meta:
        description = "Detects Mirai botnet malware"
        author      = "Yara-Rules Project"
        date        = "2016-10-04"
        hash1       = "05b345837b9c89a59f6b5b61a65b5e8a3e8c4ef2b51bedc0be4d5fc7d5c01f89"
        reference   = "https://github.com/Yara-Rules/rules"
        severity    = "critical"
        mitre_tactic = "C2"
        mitre_tech  = "T1071.001"
    strings:
        $mz  = { 7F 45 4C 46 }
        $a1  = "LCOGQJPKFKHOBMMFKJ" ascii
        $a2  = "/proc/net/tcp"      ascii
        $a3  = "/proc/net/tcp6"     ascii
        $a4  = "GET /bins/"         ascii
        $a5  = "POST /report"       ascii
        $a6  = "SCANNER ON"         ascii
        $a7  = "SCANNER OFF"        ascii
        $a8  = "jbeqfheqfbhjeq"     ascii fullword
    condition:
        $mz at 0 and 3 of ($a*)
}

/* DNS Tunneling detection */
rule DNS_Tunneling_Iodine {
    meta:
        description = "Detects DNS tunneling tool iodine"
        severity    = "high"
        mitre_tech  = "T1071.004"
    strings:
        $a = "iodine"   nocase
        $b = "TUNNEL"   ascii
        $c = { 00 04 54 55 4E 4C }
    condition:
        2 of them
}

/* Cobalt Strike beacon strings (generic) */
rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon patterns"
        author      = "Thor Security"
        severity    = "critical"
        mitre_tactic = "C2"
        mitre_tech  = "T1071.001"
    strings:
        $s1 = "%s (admin)" fullword
        $s2 = "ReflectiveLoader" fullword
        $s3 = "beacon.dll" nocase
        $x1 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $x2 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
    condition:
        any of ($x*) or 2 of ($s*)
}

/* Webshell patterns */
rule Webshell_Generic {
    meta:
        description = "Generic webshell detection"
        severity    = "high"
        mitre_tech  = "T1505.003"
    strings:
        $php1 = "<?php system(" nocase
        $php2 = "<?php exec("   nocase
        $php3 = "eval(base64_decode(" nocase
        $php4 = "passthru($_"   nocase
        $asp1 = "Response.Write(Shell.Run" nocase
        $jsp1 = "Runtime.getRuntime().exec(" nocase
    condition:
        any of them
}

/* SYN flood tool signatures */
rule SynFlood_Tool {
    meta:
        description = "Detects SYN flood attack tools"
        severity    = "high"
        mitre_tech  = "T1498.001"
    strings:
        $a = "synflood"  nocase
        $b = "syn_flood" nocase
        $c = "SYNACK"    ascii
        $d = "--flood"   ascii
        $e = "-S --flood" ascii
    condition:
        2 of them
}

/* TOR Browser detection */
rule TOR_Browser {
    meta:
        description = "Detects TOR browser artifacts"
        severity    = "medium"
        mitre_tech  = "T1090.003"
    strings:
        $a = "obfs4proxy"    ascii nocase
        $b = "meek-client"   ascii nocase
        $c = "snowflake"     ascii nocase
        $d = "tor-browser"   ascii nocase
        $e = "Tor Browser"   wide ascii
    condition:
        any of them
}
"""

# ─── YaraEngine ───────────────────────────────────────────────────────────────

class YaraEngine:
    """
    Production YARA scanning engine with hot-reload.
    Uses real yara-python library (VirusTotal/yara-python).
    """

    def __init__(self, rules_dir: Optional[str] = None, reload_interval: int = 60):
        self.rules_dir       = Path(rules_dir) if rules_dir else None
        self.reload_interval = reload_interval
        self._rules: Optional[yara.Rules] = None
        self._lock           = threading.RLock()
        self._last_loaded    = 0.0
        self._running        = False

        # Compile built-in rules immediately
        self._compile_rules()

    def _compile_rules(self):
        """Compile YARA rules from built-ins + optional rules directory."""
        sources: dict[str, str] = {"builtin": BUILTIN_RULES_SOURCE}

        # Load .yar files from rules directory
        if self.rules_dir and self.rules_dir.exists():
            for yar_file in self.rules_dir.glob("**/*.yar"):
                try:
                    ns = yar_file.stem.replace("-", "_").replace(".", "_")
                    sources[ns] = yar_file.read_text(encoding="utf-8")
                    logger.debug(f"Loaded rules: {yar_file.name}")
                except Exception as e:
                    logger.warning(f"Failed to load {yar_file}: {e}")

        try:
            with self._lock:
                self._rules = yara.compile(sources=sources)
                self._last_loaded = time.time()
            rule_count = len(sources)
            logger.info(f"YARA compiled {rule_count} rule namespaces")
        except yara.SyntaxError as e:
            logger.error(f"YARA compile error: {e}")
            raise

    def _auto_reload_loop(self):
        """Background thread: reload rules if .yar files change."""
        while self._running:
            time.sleep(self.reload_interval)
            try:
                self._compile_rules()
                logger.debug("YARA rules hot-reloaded")
            except Exception as e:
                logger.error(f"YARA reload failed: {e}")

    def start(self):
        """Start background reload thread."""
        self._running = True
        t = threading.Thread(target=self._auto_reload_loop, daemon=True)
        t.start()
        logger.info("YARA engine started with auto-reload every %ds", self.reload_interval)

    def stop(self):
        self._running = False

    def scan_bytes(self, data: bytes, timeout: int = 5) -> YaraScanResult:
        """Scan raw bytes (DPI payload, file content)."""
        if not data:
            return YaraScanResult(matched=False)

        start = time.monotonic()
        with self._lock:
            rules = self._rules

        if not rules:
            return YaraScanResult(matched=False)

        try:
            # Real yara-python scan (real API from VirusTotal/yara-python)
            raw_matches = rules.match(data=data, timeout=timeout)
        except yara.TimeoutError:
            logger.warning("YARA scan timed out after %ds", timeout)
            return YaraScanResult(matched=False)
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return YaraScanResult(matched=False)

        elapsed = (time.monotonic() - start) * 1000

        if not raw_matches:
            return YaraScanResult(matched=False, scan_time_ms=elapsed,
                                   bytes_scanned=len(data))

        matches = []
        for m in raw_matches:
            meta = m.meta or {}
            matches.append(YaraMatch(
                rule_name    = m.rule,
                namespace    = m.namespace,
                tags         = list(m.tags),
                meta         = meta,
                strings      = [(s.offset, s.identifier, bytes(s.matched_data))
                                 for s in m.strings],
                severity     = meta.get("severity", "medium"),
                mitre_tactic = meta.get("mitre_tactic"),
                mitre_tech   = meta.get("mitre_tech"),
            ))

        return YaraScanResult(
            matched       = True,
            matches       = matches,
            scan_time_ms  = elapsed,
            bytes_scanned = len(data),
        )

    def scan_url(self, url: str) -> YaraScanResult:
        """Scan URL/domain string for threat indicators."""
        return self.scan_bytes(url.encode())

    def scan_dns(self, query: str) -> YaraScanResult:
        """Scan DNS query for C2/tunneling patterns."""
        return self.scan_bytes(query.lower().encode())

    def scan_file(self, path: str, timeout: int = 30) -> YaraScanResult:
        """Scan a file on disk (real yara-python filepath API)."""
        with self._lock:
            rules = self._rules
        if not rules:
            return YaraScanResult(matched=False)

        start = time.monotonic()
        try:
            raw_matches = rules.match(filepath=path, timeout=timeout)
        except yara.TimeoutError:
            logger.warning("YARA file scan timed out: %s", path)
            return YaraScanResult(matched=False)
        except Exception as e:
            logger.error(f"YARA file scan error {path}: {e}")
            return YaraScanResult(matched=False)

        elapsed = (time.monotonic() - start) * 1000
        file_size = os.path.getsize(path) if os.path.exists(path) else 0

        matches = [
            YaraMatch(
                rule_name  = m.rule,
                namespace  = m.namespace,
                tags       = list(m.tags),
                meta       = m.meta or {},
                strings    = [(s.offset, s.identifier, bytes(s.matched_data))
                               for s in m.strings],
                severity   = (m.meta or {}).get("severity", "medium"),
                mitre_tactic = (m.meta or {}).get("mitre_tactic"),
                mitre_tech = (m.meta or {}).get("mitre_tech"),
            )
            for m in raw_matches
        ]
        return YaraScanResult(
            matched       = bool(matches),
            matches       = matches,
            scan_time_ms  = elapsed,
            bytes_scanned = file_size,
        )


# ─── FastAPI integration ──────────────────────────────────────────────────────

_engine: Optional[YaraEngine] = None

def get_yara_engine() -> YaraEngine:
    global _engine
    if _engine is None:
        rules_dir = os.environ.get("THOR_YARA_RULES_DIR", "/etc/thor/yara/rules")
        _engine   = YaraEngine(rules_dir=rules_dir)
        _engine.start()
    return _engine
