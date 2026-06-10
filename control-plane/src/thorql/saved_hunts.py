"""
Thor ThorQL — Built-in Threat Hunting Queries Library
مكتبة استعلامات الصيد المدمجة (مستوحاة من CrowdStrike OverWatch + Splunk ES)

كل استعلام مرتبط بـ:
- MITRE ATT&CK technique ID
- severity level
- description (بالعربية والإنجليزية)
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class ThorQLHunt:
    name:        str
    description: str
    mitre_id:    str
    query:       str
    severity:    str   # low / medium / high / critical


BUILT_IN_HUNTS: dict[str, ThorQLHunt] = {

    "dns_tunneling": ThorQLHunt(
        name        = "DNS Tunneling Detection",
        description = "كشف نفق DNS لنقل البيانات المخفي | T1071.004",
        mitre_id    = "T1071.004",
        query       = """
flows WHERE protocol = "UDP" AND dst_port = 53
    AND risk_score > 0.5
LAST 4h
GROUP BY src_ip
SORT BY count DESC
LIMIT 50
        """,
        severity    = "high",
    ),

    "c2_beaconing": ThorQLHunt(
        name        = "C2 Beaconing Detection",
        description = "كشف التواصل المنتظم مع خادم Command & Control | T1071",
        mitre_id    = "T1071",
        query       = """
threats WHERE threat_type = "C2"
    AND risk_score > 0.7
LAST 24h
SORT BY risk_score DESC
LIMIT 100
        """,
        severity    = "critical",
    ),

    "lateral_movement": ThorQLHunt(
        name        = "Lateral Movement via Admin Protocols",
        description = "كشف الحركة الجانبية عبر بروتوكولات الإدارة (SSH, RDP, WMI) | T1021",
        mitre_id    = "T1021",
        query       = """
flows WHERE dst_port IN [22, 3389, 445, 5985, 5986, 135, 139]
    AND risk_score > 0.4
LAST 1h
GROUP BY src_ip
SORT BY count DESC
LIMIT 50
        """,
        severity    = "high",
    ),

    "data_exfiltration": ThorQLHunt(
        name        = "Large Outbound Data Transfer",
        description = "كشف تسريب البيانات الكبيرة للخارج | T1048",
        mitre_id    = "T1048",
        query       = """
flows WHERE bytes > 10000000
    AND dst_port NOT IN [80, 443]
LAST 24h
GROUP BY src_ip
SORT BY sum(bytes) DESC
LIMIT 30
        """,
        severity    = "critical",
    ),

    "brute_force": ThorQLHunt(
        name        = "Multi-Service Brute Force",
        description = "كشف هجوم القوة الغاشمة على خدمات متعددة | T1110",
        mitre_id    = "T1110",
        query       = """
flows WHERE dst_port IN [22, 21, 3389, 5900, 23, 25, 110, 143]
    AND risk_score > 0.5
LAST 15m
GROUP BY src_ip
SORT BY count DESC
LIMIT 50
        """,
        severity    = "high",
    ),

    "crypto_mining": ThorQLHunt(
        name        = "Cryptocurrency Mining Detection",
        description = "كشف تعدين العملات المشفرة غير المصرح به | T1496",
        mitre_id    = "T1496",
        query       = """
flows WHERE dst_port IN [3333, 4444, 5555, 9999, 14444, 45700]
    AND risk_score > 0.4
LAST 1h
GROUP BY dst_ip
SORT BY count DESC
LIMIT 30
        """,
        severity    = "medium",
    ),

    "port_scan": ThorQLHunt(
        name        = "Network Port Scanning",
        description = "كشف مسح الشبكة للبحث عن الثغرات | T1046",
        mitre_id    = "T1046",
        query       = """
threats WHERE threat_type = "PortScan"
    AND risk_score > 0.5
LAST 1h
GROUP BY src_ip
SORT BY count DESC
LIMIT 50
        """,
        severity    = "medium",
    ),

    "privilege_escalation": ThorQLHunt(
        name        = "Privilege Escalation Indicators",
        description = "كشف مؤشرات رفع الصلاحيات | T1548",
        mitre_id    = "T1548",
        query       = """
threats WHERE threat_type IN ["BruteForce", "Infiltration"]
    AND severity IN ["high", "critical"]
LAST 4h
SORT BY risk_score DESC
LIMIT 50
        """,
        severity    = "critical",
    ),

    "web_attacks": ThorQLHunt(
        name        = "Web Application Attack Patterns",
        description = "كشف هجمات تطبيقات الويب (SQL Injection, XSS, etc.) | T1190",
        mitre_id    = "T1190",
        query       = """
threats WHERE threat_type = "WebAttack"
    AND risk_score > 0.6
LAST 24h
SORT BY risk_score DESC
LIMIT 100
        """,
        severity    = "high",
    ),

    "insider_threat": ThorQLHunt(
        name        = "Insider Threat — UEBA Anomalies",
        description = "كشف التهديدات الداخلية من الموظفين | T1078",
        mitre_id    = "T1078",
        query       = """
ueba_events WHERE risk_delta > 0.5
    AND severity IN ["high", "critical"]
LAST 24h
SORT BY risk_delta DESC
LIMIT 50
        """,
        severity    = "high",
    ),

    "new_admin_tools": ThorQLHunt(
        name        = "Unusual Admin Tool Usage",
        description = "كشف استخدام أدوات الإدارة بطريقة غير اعتيادية | T1059",
        mitre_id    = "T1059",
        query       = """
flows WHERE dst_port IN [22, 3389, 445, 5985]
    AND risk_score > 0.6
LAST 6h
GROUP BY src_ip, dst_ip
SORT BY risk_score DESC
LIMIT 50
        """,
        severity    = "high",
    ),

    "tor_traffic": ThorQLHunt(
        name        = "Tor Exit Node Communication",
        description = "كشف التواصل عبر شبكة Tor للتمويه | T1090.003",
        mitre_id    = "T1090.003",
        query       = """
threats WHERE threat_type IN ["C2", "Bot/C2"]
    AND risk_score > 0.8
LAST 24h
SORT BY risk_score DESC
LIMIT 50
        """,
        severity    = "critical",
    ),
}
