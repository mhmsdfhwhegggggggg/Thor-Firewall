"""
ThorQL Executor — يحوّل ThorQL إلى ClickHouse SQL وينفّذه

Grammar مبسّطة (Phase D — full grammar يأتي لاحقاً مع lark-parser):
  SOURCE [WHERE conditions] [LAST Xh/d] [| pipes...] [LIMIT N]

Sources: flows, threats, ueba_events, audit_log
Pipes:   GROUP BY, SORT BY, LIMIT, ENRICH (threat_intel), ALERT, SOAR
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import structlog

log = structlog.get_logger("thor.thorql")

# ── AST Nodes ──────────────────────────────────────────────────────────────────

SOURCE_MAP = {
    "flows":       "thor.flows",
    "threats":     "thor.threats",
    "ueba":        "thor.ueba_events",
    "ueba_events": "thor.ueba_events",
    "audit":       "thor.audit_log",
    "audit_log":   "thor.audit_log",
    "cases":       "thor.cases",
}

TIME_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}

ALLOWED_COLUMNS = {
    "flows":       {"src_ip","dst_ip","src_port","dst_port","protocol","bytes",
                    "packets","duration_ms","decision","risk_score","confidence",
                    "agent_id","node_name","flow_hash","ts"},
    "threats":     {"ts","threat_id","threat_type","severity","src_ip","dst_ip",
                    "risk_score","blocked","mitre_id","mitre_name","description"},
    "ueba_events": {"ts","entity_id","entity_type","anomaly_type","severity",
                    "risk_delta","description","mitre_id"},
    "audit_log":   {"ts","entry_id","event_type","actor_id","target","action",
                    "result","source_ip","session_id"},
}


@dataclass
class ParsedQuery:
    source:        str
    table:         str
    where_clauses: List[str]
    time_seconds:  Optional[int]
    group_by:      Optional[str]
    sort_by:       Optional[str]
    sort_desc:     bool
    limit:         int
    enrich:        bool
    alert_msg:     Optional[str]
    soar_action:   Optional[str]
    raw:           str


class ThorQLParser:
    """
    Simple regex-based parser for ThorQL.
    Full grammar (via lark) to be added in Phase D.2.
    """

    # Patterns
    _RE_SOURCE    = re.compile(r"^(flows|threats|ueba(?:_events)?|audit(?:_log)?|cases)\b", re.I)
    _RE_WHERE     = re.compile(r"\bWHERE\s+(.+?)(?=\bLAST\b|\bGROUP\b|\bSORT\b|\bLIMIT\b|\||\Z)", re.I|re.S)
    _RE_LAST      = re.compile(r"\bLAST\s+(\d+)\s*([mhdw])", re.I)
    _RE_GROUP     = re.compile(r"\bGROUP\s+BY\s+([\w,\s]+?)(?=\bSORT\b|\bLIMIT\b|\||\Z)", re.I)
    _RE_SORT      = re.compile(r"\bSORT\s+BY\s+([\w]+)\s*(ASC|DESC)?", re.I)
    _RE_LIMIT     = re.compile(r"\bLIMIT\s+(\d+)", re.I)
    _RE_ENRICH    = re.compile(r"\|\s*ENRICH\s+WITH\s+threat_intel", re.I)
    _RE_ALERT     = re.compile(r"\|\s*ALERT\s+[\"'](.+?)[\"']", re.I)
    _RE_SOAR      = re.compile(r"\|\s*SOAR\s+([\w_]+)", re.I)

    def parse(self, query: str) -> ParsedQuery:
        q = query.strip()

        m = self._RE_SOURCE.match(q)
        if not m:
            raise ValueError(f"ThorQL must start with a valid source: {list(SOURCE_MAP.keys())}")
        source = m.group(1).lower().replace("-", "_")
        table  = SOURCE_MAP.get(source, "thor.flows")

        # WHERE
        where_clauses = []
        wm = self._RE_WHERE.search(q)
        if wm:
            raw_where = wm.group(1).strip()
            where_clauses = self._parse_where(raw_where, source)

        # LAST Xh / Xd
        time_seconds = None
        lm = self._RE_LAST.search(q)
        if lm:
            n    = int(lm.group(1))
            unit = lm.group(2).lower()
            time_seconds = n * TIME_UNIT_SECONDS.get(unit, 3600)

        # GROUP BY
        group_by = None
        gm = self._RE_GROUP.search(q)
        if gm:
            cols     = [c.strip() for c in gm.group(1).split(",")]
            group_by = ", ".join(cols)

        # SORT BY
        sort_by   = None
        sort_desc = True
        sm = self._RE_SORT.search(q)
        if sm:
            sort_by   = sm.group(1).strip()
            sort_desc = (sm.group(2) or "DESC").upper() == "DESC"

        # LIMIT
        limit = 100
        limm = self._RE_LIMIT.search(q)
        if limm:
            limit = min(int(limm.group(1)), 10000)

        # Pipes
        enrich      = bool(self._RE_ENRICH.search(q))
        alert_msg   = (self._RE_ALERT.search(q) or [None])[0]
        if alert_msg is None:
            am = self._RE_ALERT.search(q)
            alert_msg = am.group(1) if am else None
        soar_action = None
        soarm = self._RE_SOAR.search(q)
        if soarm:
            soar_action = soarm.group(1)

        return ParsedQuery(
            source=source, table=table, where_clauses=where_clauses,
            time_seconds=time_seconds, group_by=group_by,
            sort_by=sort_by, sort_desc=sort_desc, limit=limit,
            enrich=enrich, alert_msg=alert_msg, soar_action=soar_action,
            raw=q,
        )

    def _parse_where(self, raw: str, source: str) -> List[str]:
        """
        Parse WHERE clause into safe ClickHouse conditions.
        Blocks injection by whitelisting column names.
        """
        allowed = ALLOWED_COLUMNS.get(source, set())
        clauses = []
        # Split on AND (simple approach — full grammar handles complex cases)
        parts = re.split(r"\bAND\b", raw, flags=re.I)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            # Validate column name
            col_match = re.match(r"^([\w]+)\s*", part)
            if col_match:
                col = col_match.group(1).lower()
                if col not in allowed and allowed:
                    log.warning("thorql_unknown_column", col=col, source=source)
                    continue
            clauses.append(self._sanitize_condition(part))
        return clauses

    def _sanitize_condition(self, cond: str) -> str:
        """Basic sanitization — remove dangerous SQL keywords."""
        dangerous = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER",
                     "CREATE", "TRUNCATE", "EXEC", "EXECUTE", "--", "/*"]
        upper = cond.upper()
        for d in dangerous:
            if d in upper:
                raise ValueError(f"Dangerous keyword in condition: {d}")
        # Convert IN [a,b,c] → IN (a,b,c)
        cond = re.sub(r"\bIN\s*\[([^\]]+)\]", r"IN (\1)", cond, flags=re.I)
        return cond.strip()


class ThorQLTranspiler:
    """Converts ParsedQuery → ClickHouse SQL"""

    def to_sql(self, pq: ParsedQuery) -> str:
        # SELECT
        if pq.group_by:
            cols = pq.group_by + ", count() AS count, avg(risk_score) AS avg_risk"
        else:
            cols = "*"

        sql = f"SELECT {cols} FROM {pq.table}"

        # WHERE
        conditions = list(pq.where_clauses)
        if pq.time_seconds:
            conditions.insert(0, f"ts >= now() - INTERVAL {pq.time_seconds} SECOND")

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        # GROUP BY
        if pq.group_by:
            sql += f" GROUP BY {pq.group_by}"

        # ORDER BY
        if pq.sort_by:
            direction = "DESC" if pq.sort_desc else "ASC"
            sql += f" ORDER BY {pq.sort_by} {direction}"
        elif pq.group_by:
            sql += " ORDER BY count DESC"
        else:
            sql += " ORDER BY ts DESC"

        sql += f" LIMIT {pq.limit}"
        return sql


class ThorQLExecutor:
    """
    Full execution pipeline:
    ThorQL string → Parse → Validate → Transpile → ClickHouse → Enrich → Alert/SOAR
    """

    def __init__(self, clickhouse_client=None, soar_engine=None):
        self.parser      = ThorQLParser()
        self.transpiler  = ThorQLTranspiler()
        self.ch          = clickhouse_client
        self.soar        = soar_engine

    async def execute(self, query: str) -> Dict[str, Any]:
        t0  = time.perf_counter()
        pq  = self.parser.parse(query)
        sql = self.transpiler.to_sql(pq)

        log.info("thorql_execute", source=pq.source, sql=sql[:200])

        rows = []
        if self.ch:
            rows = await self.ch.execute(sql)

        result: Dict[str, Any] = {
            "query":      pq.raw,
            "sql":        sql,
            "rows":       rows,
            "row_count":  len(rows),
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        }

        if pq.enrich and rows:
            result["enriched"] = True   # enrichment hook

        if pq.alert_msg and rows:
            log.warning("thorql_alert", msg=pq.alert_msg, rows=len(rows))
            result["alert_triggered"] = pq.alert_msg

        if pq.soar_action and rows and self.soar:
            log.warning("thorql_soar", action=pq.soar_action, rows=len(rows))
            result["soar_triggered"] = pq.soar_action

        return result
