#!/usr/bin/env python3
"""
Thor Firewall — CTI Bridge
يربط SpiderFoot + Yeti + MISP + OpenCTI في pipeline واحد
يُزامن IoCs و TTPs بين المنصات كل SYNC_INTERVAL_MINUTES دقيقة
"""
import os, time, json, logging, schedule
import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [CTI-BRIDGE] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

MISP_URL  = os.getenv("MISP_URL", "http://misp:80")
MISP_KEY  = os.getenv("MISP_AUTH_KEY", "")
YETI_URL  = os.getenv("YETI_URL", "http://yeti:8080")
OCT_URL   = os.getenv("OPENCTI_URL", "http://opencti:8080")
OCT_TOKEN = os.getenv("OPENCTI_TOKEN", "")
SF_URL    = os.getenv("SPIDERFOOT_URL", "http://spiderfoot:5001")
INTERVAL  = int(os.getenv("SYNC_INTERVAL_MINUTES", "60"))

HEADERS_MISP = {"Authorization": MISP_KEY, "Content-Type": "application/json",
                "Accept": "application/json"}

def get_misp_recent_events(hours=24):
    """جلب آخر أحداث MISP"""
    try:
        r = requests.post(f"{MISP_URL}/events/restSearch",
            headers=HEADERS_MISP,
            json={"returnFormat": "json", "last": f"{hours}h", "limit": 100},
            timeout=30, verify=False)
        r.raise_for_status()
        events = r.json().get("response", [])
        log.info(f"MISP: fetched {len(events)} events from last {hours}h")
        return events
    except Exception as e:
        log.warning(f"MISP fetch failed: {e}")
        return []

def push_iocs_to_yeti(iocs: list):
    """رفع IoCs إلى Yeti"""
    if not iocs:
        return
    for ioc in iocs[:50]:   # حد أقصى 50 لكل دورة
        try:
            requests.post(f"{YETI_URL}/api/v2/observables",
                json={"value": ioc["value"], "type": ioc["type"],
                      "tags": ["misp", "auto-import"],
                      "context": ioc.get("context", {})},
                timeout=10)
        except Exception as e:
            log.debug(f"Yeti push failed for {ioc.get('value')}: {e}")
    log.info(f"Yeti: pushed {min(len(iocs),50)} IoCs")

def push_to_opencti(events: list):
    """رفع أحداث MISP إلى OpenCTI عبر GraphQL"""
    if not OCT_TOKEN or not events:
        return
    headers = {"Authorization": f"Bearer {OCT_TOKEN}",
               "Content-Type": "application/json"}
    for event in events[:10]:
        info = event.get("Event", {})
        try:
            mutation = """mutation($input: ReportAddInput!) {
              reportAdd(input: $input) { id } }"""
            requests.post(f"{OCT_URL}/graphql",
                headers=headers,
                json={"query": mutation, "variables": {"input": {
                    "name": info.get("info", "MISP Event"),
                    "published": info.get("date", ""),
                    "report_types": ["threat-report"],
                    "description": f"Auto-imported from MISP event {info.get('id','')}",
                    "confidence": 75,
                    "labels": ["misp", "auto-import"]
                }}}, timeout=15)
        except Exception as e:
            log.debug(f"OpenCTI push failed: {e}")
    log.info(f"OpenCTI: pushed {min(len(events),10)} events")

def extract_iocs_from_misp(events: list) -> list:
    """استخراج IoCs من أحداث MISP"""
    iocs = []
    type_map = {"ip-src": "IP", "ip-dst": "IP", "domain": "Hostname",
                "hostname": "Hostname", "url": "URL", "md5": "MD5",
                "sha1": "SHA1", "sha256": "SHA256", "email-src": "Email"}
    for event in events:
        attrs = event.get("Event", {}).get("Attribute", [])
        for attr in attrs:
            t = attr.get("type", "")
            if t in type_map:
                iocs.append({"value": attr.get("value", ""),
                             "type": type_map[t],
                             "context": {"misp_event": event.get("Event",{}).get("id"),
                                         "misp_category": attr.get("category")}})
    return iocs

def sync_pipeline():
    log.info("=== CTI Sync Pipeline started ===")
    events = get_misp_recent_events(hours=24)
    if events:
        iocs = extract_iocs_from_misp(events)
        log.info(f"Extracted {len(iocs)} IoCs from MISP")
        push_iocs_to_yeti(iocs)
        push_to_opencti(events)
    log.info("=== CTI Sync Pipeline complete ===")

if __name__ == "__main__":
    log.info(f"CTI Bridge starting — sync every {INTERVAL} minutes")
    # Initial run
    time.sleep(30)   # انتظار حتى تبدأ الخدمات
    sync_pipeline()
    # Schedule recurring
    schedule.every(INTERVAL).minutes.do(sync_pipeline)
    while True:
        schedule.run_pending()
        time.sleep(60)
