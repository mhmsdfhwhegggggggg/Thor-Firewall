"""
Windows Event Log Parser — EVTX XML format
Handles Security/System/Application events, Sysmon events (EventID 1-29)
"""
import re
import time
import xml.etree.ElementTree as ET
from ..universal_ingester import NormalizedEvent

# Sysmon EventID → action name
_SYSMON_EVENTS = {
    1:  "ProcessCreate",           2:  "FileCreationTimeChanged",
    3:  "NetworkConnect",          4:  "SysmonServiceStateChanged",
    5:  "ProcessTerminated",       6:  "DriverLoaded",
    7:  "ImageLoaded",             8:  "CreateRemoteThread",
    9:  "RawAccessRead",           10: "ProcessAccess",
    11: "FileCreate",              12: "RegistryEventCreate",
    13: "RegistryEventSet",        14: "RegistryEventRename",
    15: "FileCreateStreamHash",    16: "ServiceConfigurationChange",
    17: "PipeEventCreated",        18: "PipeEventConnected",
    19: "WmiEventFilter",          20: "WmiEventConsumer",
    21: "WmiEventConsumerBinding", 22: "DNSQuery",
    23: "FileDelete",              24: "ClipboardCapture",
    25: "ProcessTampering",        26: "FileDeleteDetected",
    27: "FileBlockExecutable",     28: "FileBlockShredding",
    29: "FileExecutableDetected",
}

# High-value Windows Security Event IDs
_SECURITY_EVENTS = {
    4624: "LogonSuccess",          4625: "LogonFailure",
    4648: "ExplicitLogon",         4656: "ObjectOpenHandle",
    4663: "ObjectAccess",          4672: "PrivilegeAssigned",
    4688: "ProcessCreated",        4698: "ScheduledTaskCreated",
    4702: "ScheduledTaskModified", 4720: "AccountCreated",
    4722: "AccountEnabled",        4724: "PasswordReset",
    4728: "GroupMemberAdded",      4732: "LocalGroupMemberAdded",
    4740: "AccountLockout",        4756: "UniversalGroupMemberAdded",
    4768: "KerberosTicketRequest", 4769: "KerberosServiceTicket",
    4776: "NtlmAuth",             4798: "EnumLocalGroupMembership",
    4799: "EnumGlobalGroupMembership",
    7045: "ServiceInstalled",      7040: "ServiceStartTypeChanged",
}

# MITRE mappings for common event IDs
_MITRE_MAP = {
    4625: ["T1110"],               # Brute Force
    4648: ["T1550.003"],           # Pass the Ticket
    4688: ["T1059"],               # Command Execution
    4698: ["T1053.005"],           # Scheduled Task
    4720: ["T1136"],               # Create Account
    7045: ["T1543.003"],           # Create/Modify System Process
    1:    ["T1059"],               # Sysmon: Process Create
    3:    ["T1071"],               # Sysmon: Network Connect
    8:    ["T1055.002"],           # Sysmon: CreateRemoteThread → Process Injection
    22:   ["T1071.004"],           # Sysmon: DNS Query
}

NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}

def parse_winevent(raw: str) -> NormalizedEvent:
    ev = NormalizedEvent(raw=raw, source_format="winevent")

    # Handle both full XML and JSON-serialized events
    if raw.strip().startswith("{"):
        import json
        try:
            obj = json.loads(raw)
            return _parse_json_winevent(obj, ev)
        except Exception:
            pass

    # XML path
    try:
        root = ET.fromstring(raw.strip())
        _parse_xml(root, ev)
    except ET.ParseError as e:
        ev.labels["parse_error"] = str(e)

    return ev

def _parse_xml(root: ET.Element, ev: NormalizedEvent):
    system_el = root.find("w:System", NS)
    if system_el is None:
        system_el = root.find("System")  # no namespace fallback

    if system_el is not None:
        event_id_el = system_el.find("w:EventID", NS) or system_el.find("EventID")
        if event_id_el is not None:
            try:
                event_id = int(event_id_el.text or 0)
                ev.labels["event_id"] = str(event_id)
                ev.action = _SECURITY_EVENTS.get(event_id,
                            _SYSMON_EVENTS.get(event_id, f"EventID_{event_id}"))
                techniques = _MITRE_MAP.get(event_id, [])
                ev.mitre_techniques = techniques
                if event_id >= 4600:
                    ev.category = "auth" if event_id < 4700 else "process"
            except ValueError:
                pass

        computer_el = system_el.find("w:Computer", NS) or system_el.find("Computer")
        if computer_el is not None:
            ev.source_host = computer_el.text or ""

        time_el = system_el.find("w:TimeCreated", NS) or system_el.find("TimeCreated")
        if time_el is not None:
            ts_str = time_el.get("SystemTime", "")
            if ts_str:
                try:
                    from datetime import datetime, timezone
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    ev.timestamp_ms = int(dt.timestamp() * 1000)
                except Exception:
                    pass

        provider_el = system_el.find("w:Provider", NS) or system_el.find("Provider")
        if provider_el is not None:
            ev.labels["provider"] = provider_el.get("Name", "")

    # EventData
    event_data = root.find("w:EventData", NS) or root.find("EventData")
    if event_data is not None:
        for data_el in event_data:
            name = data_el.get("Name", "")
            val  = data_el.text or ""
            if name:
                ev.labels[name] = val
                # Map common fields
                if name in ("SubjectUserName", "TargetUserName", "AccountName"):
                    if not ev.actor_user:
                        ev.actor_user = val
                elif name == "NewProcessName":
                    ev.actor_process = val
                elif name == "ProcessId":
                    try:
                        ev.actor_pid = int(val, 16) if val.startswith("0x") else int(val)
                    except ValueError:
                        pass
                elif name in ("DestinationIp", "DestAddress"):
                    ev.target_ip = val
                elif name in ("DestinationPort", "DestPort"):
                    try:
                        ev.target_port = int(val)
                    except ValueError:
                        pass
                elif name == "Image":
                    ev.actor_process = val.split("\\")[-1] if "\\" in val else val
                elif name == "CommandLine":
                    ev.labels["commandline"] = val


def _parse_json_winevent(obj: dict, ev: NormalizedEvent) -> NormalizedEvent:
    """Parse WEF/Windows Event Collector JSON format"""
    ev.source_host    = obj.get("Computer", obj.get("Hostname", ""))
    ev.actor_user     = obj.get("SubjectUserName", obj.get("TargetUserName", ""))
    event_id          = obj.get("EventID", 0)
    ev.labels["event_id"] = str(event_id)
    ev.action         = _SECURITY_EVENTS.get(int(event_id),
                        _SYSMON_EVENTS.get(int(event_id), f"EventID_{event_id}"))
    ev.mitre_techniques = _MITRE_MAP.get(int(event_id), [])
    ts = obj.get("TimeCreated", obj.get("@timestamp", ""))
    if ts:
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ev.timestamp_ms = int(dt.timestamp() * 1000)
        except Exception:
            pass
    ev.labels.update({k: str(v) for k, v in obj.items() if isinstance(v, str)})
    return ev
