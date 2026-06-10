"""
Thor XDR — MITRE ATT&CK Auto-Mapper
يحدد التكتيكات والتقنيات تلقائياً من نوع الحدث
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MitreTechnique:
    id: str          # T1046
    name: str        # Network Service Discovery
    tactic: str      # Discovery
    sub_technique: Optional[str] = None  # T1046.001


# قاموس mapping من نوع الحدث إلى تقنية MITRE
EVENT_TO_MITRE: dict[str, MitreTechnique] = {
    # Reconnaissance
    "port_scan":         MitreTechnique("T1046",  "Network Service Discovery",      "Reconnaissance"),
    "network_scan":      MitreTechnique("T1595",  "Active Scanning",                "Reconnaissance"),
    "os_fingerprint":    MitreTechnique("T1592",  "Gather Victim Host Information", "Reconnaissance"),

    # Initial Access
    "exploit_public":    MitreTechnique("T1190",  "Exploit Public-Facing App",      "Initial Access"),
    "phishing":          MitreTechnique("T1566",  "Phishing",                       "Initial Access"),
    "brute_force":       MitreTechnique("T1110",  "Brute Force",                    "Credential Access"),

    # Execution
    "command_exec":      MitreTechnique("T1059",  "Command and Scripting Interpreter", "Execution"),
    "powershell":        MitreTechnique("T1059.001", "PowerShell",                   "Execution"),
    "bash_exec":         MitreTechnique("T1059.004", "Unix Shell",                   "Execution"),

    # Persistence
    "cron_job":          MitreTechnique("T1053",  "Scheduled Task/Job",             "Persistence"),
    "registry_run":      MitreTechnique("T1547",  "Boot or Logon Autostart",        "Persistence"),

    # Privilege Escalation
    "sudo_abuse":        MitreTechnique("T1548",  "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "kernel_exploit":    MitreTechnique("T1068",  "Exploitation for Privilege Escalation", "Privilege Escalation"),

    # Defense Evasion
    "log_deletion":      MitreTechnique("T1070",  "Indicator Removal",              "Defense Evasion"),
    "process_inject":    MitreTechnique("T1055",  "Process Injection",              "Defense Evasion"),

    # Credential Access
    "credential_dump":   MitreTechnique("T1003",  "OS Credential Dumping",          "Credential Access"),
    "keylogger":         MitreTechnique("T1056",  "Input Capture",                  "Credential Access"),

    # Discovery
    "account_discovery": MitreTechnique("T1087",  "Account Discovery",              "Discovery"),
    "file_discovery":    MitreTechnique("T1083",  "File and Directory Discovery",   "Discovery"),

    # Lateral Movement
    "lateral_movement":  MitreTechnique("T1021",  "Remote Services",                "Lateral Movement"),
    "pass_the_hash":     MitreTechnique("T1550",  "Use Alternate Authentication",   "Lateral Movement"),

    # Collection
    "data_collection":   MitreTechnique("T1005",  "Data from Local System",         "Collection"),
    "screen_capture":    MitreTechnique("T1113",  "Screen Capture",                 "Collection"),

    # Command & Control
    "c2_beaconing":      MitreTechnique("T1071",  "Application Layer Protocol",     "Command and Control"),
    "dns_tunneling":     MitreTechnique("T1071.004", "DNS",                          "Command and Control"),
    "c2_encrypted":      MitreTechnique("T1573",  "Encrypted Channel",              "Command and Control"),

    # Exfiltration
    "data_exfil":        MitreTechnique("T1048",  "Exfiltration Over Alt Protocol", "Exfiltration"),
    "exfil_c2":          MitreTechnique("T1041",  "Exfiltration Over C2 Channel",   "Exfiltration"),

    # Impact
    "ransomware":        MitreTechnique("T1486",  "Data Encrypted for Impact",      "Impact"),
    "ddos":              MitreTechnique("T1498",  "Network Denial of Service",      "Impact"),
    "dos":               MitreTechnique("T1499",  "Endpoint Denial of Service",     "Impact"),
    "wipe":              MitreTechnique("T1561",  "Disk Wipe",                      "Impact"),
}

# Mapping من threat_type (من ML) إلى event_type
THREAT_TYPE_MAP: dict[str, str] = {
    "PortScan":    "port_scan",
    "DDoS":        "ddos",
    "DoS":         "dos",
    "BruteForce":  "brute_force",
    "C2":          "c2_beaconing",
    "WebAttack":   "exploit_public",
    "Infiltration":"lateral_movement",
    "Bot/C2":      "c2_beaconing",
    "Exfil":       "data_exfil",
    "Malware":     "process_inject",
}


def map_threat_to_mitre(threat_type: str) -> Optional[MitreTechnique]:
    event_type = THREAT_TYPE_MAP.get(threat_type, threat_type.lower().replace(" ", "_"))
    return EVENT_TO_MITRE.get(event_type)


def map_event_to_mitre(event_type: str) -> Optional[MitreTechnique]:
    return EVENT_TO_MITRE.get(event_type)


def get_kill_chain_phase(technique: MitreTechnique) -> int:
    """ترتيب مراحل Kill Chain (0=أول, 10=أخير)"""
    order = {
        "Reconnaissance": 0, "Resource Development": 1, "Initial Access": 2,
        "Execution": 3, "Persistence": 4, "Privilege Escalation": 5,
        "Defense Evasion": 6, "Credential Access": 7, "Discovery": 8,
        "Lateral Movement": 9, "Collection": 10, "Command and Control": 11,
        "Exfiltration": 12, "Impact": 13,
    }
    return order.get(technique.tactic, 99)
