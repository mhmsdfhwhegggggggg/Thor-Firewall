"""
Microsoft Teams Webhook Integration — Adaptive Cards for security alerts
"""
import aiohttp, json, logging, os, time
logger = logging.getLogger("thor.integrations.teams")

class TeamsWebhook:
    def __init__(self):
        self.webhook_url = os.getenv("TEAMS_WEBHOOK_URL","")
        self.timeout = aiohttp.ClientTimeout(total=10)

    async def send_alert(self, alert: dict) -> bool:
        if not self.webhook_url:
            return False
        severity = alert.get("severity","unknown").upper()
        color_map = {"CRITICAL":"FF0000","HIGH":"FF6600","MEDIUM":"FFAA00","LOW":"00AA00","INFO":"0078D4"}
        color = color_map.get(severity,"0078D4")
        card = {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Thor Alert: {alert.get('action','Unknown')}",
            "sections": [{
                "activityTitle": f"🚨 {severity} Alert",
                "activitySubtitle": f"{alert.get('action','')} on {alert.get('source_host','')}",
                "facts": [
                    {"name":"Host",       "value": alert.get("source_host","")},
                    {"name":"User",       "value": alert.get("actor_user","N/A")},
                    {"name":"Risk Score", "value": f"{alert.get('risk_score',0):.2f}"},
                    {"name":"MITRE",      "value": ", ".join(alert.get("mitre_techniques",[]))},
                    {"name":"Alert ID",   "value": alert.get("id","")},
                ],
                "markdown": True,
            }],
            "potentialAction": [{
                "@type": "OpenUri", "name": "Investigate",
                "targets": [{"os":"default","uri":"https://thor-dashboard/alerts"}]
            }],
        }
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as s:
                async with s.post(self.webhook_url, json=card,
                                  headers={"Content-Type":"application/json"}) as r:
                    return r.status == 200
        except Exception as e:
            logger.error("Teams webhook error: %s", e)
            return False
