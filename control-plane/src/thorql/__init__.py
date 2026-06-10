"""
ThorQL — Thor Query Language
لغة استعلام أمنية مرنة مستوحاة من Splunk SPL + SQL

مثال:
  flows WHERE protocol = "TCP" AND dst_port IN [22,3389] LAST 24h
    | WHERE risk_score > 0.8
    | GROUP BY src_ip
    | SORT BY count DESC
    | LIMIT 50
"""
