"""
Syslog Parser — RFC 3164 + RFC 5424 + BSD syslog
Handles: <PRI>TIMESTAMP HOSTNAME APPNAME[PID]: MESSAGE
"""
import re
import time
from datetime import datetime, timezone
from ..universal_ingester import NormalizedEvent

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_RFC5424 = re.compile(
    r'^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(.*)?$',
    re.DOTALL
)
# RFC 3164: <PRI>MONTH DAY HH:MM:SS HOSTNAME TAG[PID]: MSG
_RFC3164 = re.compile(
    r'^<(\d{1,3})>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)?$',
    re.DOTALL
)

_FACILITY = {
    0:"kern",1:"user",2:"mail",3:"daemon",4:"auth",5:"syslog",
    6:"lpr",7:"news",8:"uucp",9:"clock",10:"authpriv",
    11:"ftp",16:"local0",17:"local1",18:"local2",19:"local3",
    20:"local4",21:"local5",22:"local6",23:"local7"
}
_SEVERITY = {
    0:"CRITICAL",1:"CRITICAL",2:"CRITICAL",3:"HIGH",
    4:"MEDIUM",5:"MEDIUM",6:"INFO",7:"INFO"
}

def parse_syslog(raw: str) -> NormalizedEvent:
    raw = raw.strip()
    ev = NormalizedEvent(raw=raw, source_format="syslog")

    # Try RFC 5424
    m = _RFC5424.match(raw)
    if m:
        pri, version, ts, hostname, appname, procid, msgid, structured, msg = m.groups()
        _fill_from_pri(ev, int(pri))
        ev.source_host   = hostname if hostname != "-" else ""
        ev.actor_process = appname  if appname  != "-" else ""
        ev.actor_pid     = int(procid) if procid and procid.isdigit() else 0
        ev.labels["msgid"] = msgid if msgid != "-" else ""
        ev.labels["message"] = (msg or "").strip()
        ev.action        = appname.split("/")[-1] if appname else ""
        _parse_timestamp_iso(ev, ts)
        return ev

    # Try RFC 3164
    m = _RFC3164.match(raw)
    if m:
        pri, ts_str, hostname, tag, pid, msg = m.groups()
        _fill_from_pri(ev, int(pri))
        ev.source_host   = hostname
        ev.actor_process = tag
        ev.actor_pid     = int(pid) if pid else 0
        ev.labels["message"] = (msg or "").strip()
        ev.action        = tag
        _parse_timestamp_bsd(ev, ts_str)
        return ev

    # Bare syslog (no PRI)
    ev.labels["message"] = raw
    return ev

def _fill_from_pri(ev: NormalizedEvent, pri: int):
    facility = pri >> 3
    severity = pri & 0x07
    ev.log_level         = _SEVERITY.get(severity, "INFO")
    ev.labels["facility"]= _FACILITY.get(facility, str(facility))
    ev.labels["pri"]     = str(pri)

def _parse_timestamp_iso(ev: NormalizedEvent, ts: str):
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        ev.timestamp_ms = int(dt.timestamp() * 1000)
    except Exception:
        pass

def _parse_timestamp_bsd(ev: NormalizedEvent, ts_str: str):
    """Parse 'Jan  5 10:23:45' style timestamp"""
    try:
        year = datetime.utcnow().year
        dt = datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        ev.timestamp_ms = int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
    except Exception:
        pass
