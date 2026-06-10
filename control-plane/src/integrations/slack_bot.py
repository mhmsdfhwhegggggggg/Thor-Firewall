"""
Thor Firewall — Slack Integration
إرسال تنبيهات الأمان لـ Slack بشكل تلقائي

SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, os, time
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("thor.integrations.slack")

SLACK_WEBHOOK_URL  = os.getenv("SLACK_WEBHOOK_URL", "")
SLACK_BOT_TOKEN    = os.getenv("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL      = os.getenv("SLACK_ALERT_CHANNEL", "#security-alerts")
SLACK_API_BASE     = "https://slack.com/api"

SEVERITY_COLORS = {
    "critical": "#FF0000",
    "high":     "#FF6B35",
    "medium":   "#FFC300",
    "low":      "#36A64F",
    "info":     "#439FE0",
}

SEVERITY_EMOJIS = {
    "critical": ":red_circle:",
    "high":     ":large_orange_circle:",
    "medium":   ":large_yellow_circle:",
    "low":      ":large_green_circle:",
    "info":     ":large_blue_circle:",
}


class SlackBot:
    """
    Thor Slack Bot — يرسل تنبيهات ثرية للـ Slack.
    يدعم:
    - Webhook (بسيط)
    - Bot Token (للـ channels الخاصة + thread replies)
    """

    def __init__(self):
        self.webhook_url = SLACK_WEBHOOK_URL
        self.bot_token   = SLACK_BOT_TOKEN
        self.channel     = SLACK_CHANNEL
        self._client     = httpx.AsyncClient(timeout=10.0)

    async def send_threat_alert(
        self,
        threat_type: str,
        severity:    str,
        src_ip:      str,
        risk_score:  float,
        mitre_id:    str = "",
        details:     Dict[str, Any] = None,
    ) -> bool:
        """أرسل تنبيه تهديد للـ Slack"""
        color = SEVERITY_COLORS.get(severity.lower(), "#439FE0")
        emoji = SEVERITY_EMOJIS.get(severity.lower(), ":shield:")
        details = details or {}

        mitre_text = f" | MITRE: `{mitre_id}`" if mitre_id else ""
        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} Thor Security Alert: {threat_type.upper()}",
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                                {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score:.0%}"},
                                {"type": "mrkdwn", "text": f"*Source IP:*\n`{src_ip}`"},
                                {"type": "mrkdwn", "text": f"*Time:*\n<!date^{int(time.time())}^{{date_short}} {{time_secs}}|now>"},
                            ],
                        },
                    ],
                    "footer": f"Thor Firewall{mitre_text}",
                    "ts":     str(int(time.time())),
                }
            ]
        }

        if details.get("description"):
            payload["attachments"][0]["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Details:*\n{details['description']}"},
            })

        payload["attachments"][0]["blocks"].append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text":  {"type": "plain_text", "text": "Block IP"},
                    "style": "danger",
                    "value": f"block:{src_ip}",
                },
                {
                    "type": "button",
                    "text":  {"type": "plain_text", "text": "Investigate"},
                    "value": f"investigate:{src_ip}",
                },
            ],
        })

        return await self._send(payload)

    async def send_ueba_alert(
        self,
        entity_id:    str,
        entity_type:  str,
        risk_score:   int,
        top_anomalies: List[str],
    ) -> bool:
        """أرسل تنبيه UEBA للـ Slack"""
        severity = "critical" if risk_score >= 150 else "high" if risk_score >= 75 else "medium"
        color    = SEVERITY_COLORS.get(severity, "#FFC300")
        emoji    = SEVERITY_EMOJIS.get(severity, ":warning:")
        anomaly_text = "\n".join(f"• {a}" for a in top_anomalies[:5])
        payload = {
            "attachments": [
                {
                    "color": color,
                    "text":  (
                        f"{emoji} *UEBA Alert: Anomalous behavior detected*\n"
                        f">*Entity:* `{entity_id}` ({entity_type})\n"
                        f">*Risk Score:* {risk_score}\n"
                        f">*Top Anomalies:*\n{anomaly_text}"
                    ),
                    "footer": "Thor UEBA Engine",
                    "ts":     str(int(time.time())),
                }
            ]
        }
        return await self._send(payload)

    async def send_soar_notification(
        self,
        action:   str,
        target:   str,
        reason:   str,
        analyst:  str = "THOR-SOAR",
    ) -> bool:
        """أخبر الـ Slack عن SOAR action تلقائي"""
        payload = {
            "text": (
                f":robot_face: *SOAR Action Executed*\n"
                f">*Action:* `{action}`\n"
                f">*Target:* `{target}`\n"
                f">*Reason:* {reason}\n"
                f">*Executed by:* {analyst}\n"
                f">*Time:* <!date^{int(time.time())}^{{date_short}} {{time_secs}}|now>"
            )
        }
        return await self._send(payload)

    async def send_compliance_report(
        self,
        framework:   str,
        score:       float,
        failed_controls: List[str],
    ) -> bool:
        """أرسل تقرير الامتثال الأسبوعي"""
        status = "PASS" if score >= 80 else "FAIL"
        emoji  = ":white_check_mark:" if score >= 80 else ":x:"
        failed_text = "\n".join(f"• {c}" for c in failed_controls[:10]) or "None"
        payload = {
            "attachments": [
                {
                    "color": "#36A64F" if score >= 80 else "#FF0000",
                    "text":  (
                        f"{emoji} *{framework.upper()} Compliance Report — {status}*\n"
                        f">*Score:* {score:.1f}%\n"
                        f">*Failed Controls:*\n{failed_text}"
                    ),
                    "footer": "Thor Compliance Engine",
                    "ts":     str(int(time.time())),
                }
            ]
        }
        return await self._send(payload)

    async def _send(self, payload: dict) -> bool:
        if not self.webhook_url:
            logger.warning("slack_webhook_not_configured")
            return False
        try:
            resp = await self._client.post(self.webhook_url, json=payload)
            ok   = resp.status_code == 200 and resp.text == "ok"
            if not ok:
                logger.error("slack_send_failed", status=resp.status_code, body=resp.text[:200])
            return ok
        except Exception as e:
            logger.error("slack_send_error", error=str(e))
            return False

    async def close(self):
        await self._client.aclose()


_slack_bot: Optional[SlackBot] = None

def get_slack_bot() -> SlackBot:
    global _slack_bot
    if _slack_bot is None:
        _slack_bot = SlackBot()
    return _slack_bot
