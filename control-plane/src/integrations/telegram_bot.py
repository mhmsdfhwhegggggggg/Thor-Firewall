"""
Telegram Bot Integration — Send security alerts to Telegram channels/groups
"""
import aiohttp, logging, os
logger = logging.getLogger("thor.integrations.telegram")

class TelegramBot:
    API_URL = "https://api.telegram.org/bot{token}/{method}"

    def __init__(self):
        self.token   = os.getenv("TELEGRAM_BOT_TOKEN","")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID","")
        self.timeout = aiohttp.ClientTimeout(total=10)

    async def send_alert(self, alert: dict) -> bool:
        if not (self.token and self.chat_id): return False
        severity = alert.get("severity","?").upper()
        emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(severity,"⚪")
        text = (
            f"{emoji} *{severity} ALERT*\n"
            f"Host: `{alert.get('source_host','?')}`\n"
            f"Action: `{alert.get('action','?')}`\n"
            f"User: `{alert.get('actor_user','N/A')}`\n"
            f"Risk: `{alert.get('risk_score',0):.2f}`\n"
            f"MITRE: `{', '.join(alert.get('mitre_techniques',[]))}`\n"
            f"ID: `{alert.get('id','')}`"
        )
        url = self.API_URL.format(token=self.token, method="sendMessage")
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as s:
                async with s.post(url, json={"chat_id":self.chat_id,"text":text,"parse_mode":"Markdown"}) as r:
                    data = await r.json()
                    return data.get("ok", False)
        except Exception as e:
            logger.error("Telegram error: %s", e)
            return False
