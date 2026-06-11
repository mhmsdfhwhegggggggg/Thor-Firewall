"""
CEF (Common Event Format) Parser — ArcSight standard
Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
"""
import re
import time
from ..universal_ingester import NormalizedEvent

_CEF_HEADER = re.compile(
    r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|?(.*)?$',
    re.DOTALL
)

# Standard CEF extension key mappings → normalized field names
_KEY_MAP = {
    "src": "source_ip",   "dst": "target_ip",
    "spt": "source_port", "dpt": "target_port",
    "suser": "actor_user","duser": "target_user",
    "shost": "source_host","dhost": "target_host",
    "act": "action",      "outcome": "outcome",
    "msg": "message",     "fname": "target_resource",
    "sproc": "actor_process", "spid": "actor_pid",
    "cs1": "custom1",     "cs2": "custom2",
    "cn1": "custom_num1", "deviceDirection": "direction",
    "request": "url",     "requestMethod": "http_method",
    "cat": "category",
}

_SEVERITY_MAP = {
    "0": "INFO", "1": "INFO", "2": "LOW", "3": "LOW",
    "4": "MEDIUM", "5": "MEDIUM", "6": "MEDIUM",
    "7": "HIGH", "8": "HIGH", "9": "CRITICAL", "10": "CRITICAL",
}

def parse_cef(raw: str) -> NormalizedEvent:
    ev = NormalizedEvent(raw=raw, source_format="cef")

    m = _CEF_HEADER.match(raw.strip())
    if not m:
        ev.labels["parse_error"] = "invalid_cef_header"
        return ev

    (version, vendor, product, dev_version, sig_id, name, severity, extensions) = m.groups()

    ev.log_level      = _SEVERITY_MAP.get(severity.strip(), "INFO")
    ev.action         = name.strip()
    ev.labels["vendor"]       = vendor.strip()
    ev.labels["product"]      = product.strip()
    ev.labels["dev_version"]  = dev_version.strip()
    ev.labels["sig_id"]       = sig_id.strip()
    ev.labels["cef_severity"] = severity.strip()

    # Parse extensions: key=value pairs (values may contain spaces but keys don't)
    ext = _parse_extensions(extensions or "")
    for k, v in ext.items():
        mapped = _KEY_MAP.get(k)
        if mapped:
            setattr_safe(ev, mapped, v)
        else:
            ev.labels[k] = v

    # Set timestamp from rt (receive time) or deviceReceiptTime
    for ts_key in ("rt", "deviceReceiptTime", "start", "end"):
        if ts_key in ext:
            try:
                val = ext[ts_key]
                # epoch ms or epoch s
                ts_float = float(val)
                ev.timestamp_ms = int(ts_float) if ts_float > 1e10 else int(ts_float * 1000)
                break
            except (ValueError, TypeError):
                pass

    return ev


def _parse_extensions(ext_str: str) -> dict[str, str]:
    """Parse CEF extension string, handling escaped = and | characters"""
    result = {}
    if not ext_str.strip():
        return result

    # CEF spec: key=value pairs separated by spaces; values can contain spaces
    # Key is always a single word without spaces; split on " word=" boundaries
    pattern = re.compile(r'(\w+)=((?:(?!\s+\w+=).)*)', re.DOTALL)
    for m in pattern.finditer(ext_str):
        key   = m.group(1).strip()
        value = m.group(2).strip()
        # Unescape \= and \|
        value = value.replace("\\=", "=").replace("\\|", "|")
        result[key] = value

    return result


def setattr_safe(obj, attr: str, val: str):
    try:
        field_type = obj.__fields__.get(attr)
        if field_type:
            current = getattr(obj, attr, None)
            if isinstance(current, int):
                setattr(obj, attr, int(val))
            elif isinstance(current, float):
                setattr(obj, attr, float(val))
            else:
                setattr(obj, attr, str(val))
    except Exception:
        obj.labels[attr] = val
