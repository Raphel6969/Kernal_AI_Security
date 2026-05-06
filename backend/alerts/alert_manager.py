import sqlite3
import uuid
import json
import asyncio
import threading
from datetime import datetime
from typing import List

import requests

from backend.events.models import SecurityEvent
from backend.alerts.models import WebhookResponse, AlertHistoryResponse

class AlertManager:
    def __init__(self, db_path: str = "data/events.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()
        
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS webhooks (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_history (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.commit()

    def add_webhook(self, url: str) -> WebhookResponse:
        webhook_id = f"wh_{uuid.uuid4().hex[:8]}"
        created_at = datetime.now().timestamp()
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT INTO webhooks (id, url, is_active, created_at) VALUES (?, ?, ?, ?)",
                             (webhook_id, url, 1, created_at))
                conn.commit()
                
        return WebhookResponse(id=webhook_id, url=url, is_active=True, created_at=created_at)

    def remove_webhook(self, webhook_id: str):
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
                conn.commit()

    def get_webhooks(self) -> List[WebhookResponse]:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT id, url, is_active, created_at FROM webhooks")
                rows = cursor.fetchall()
                return [WebhookResponse(id=r[0], url=r[1], is_active=bool(r[2]), created_at=r[3]) for r in rows]

    def get_alert_history(self, limit: int = 50) -> List[AlertHistoryResponse]:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT id, event_id, url, status, timestamp FROM alert_history ORDER BY timestamp DESC LIMIT ?", (limit,))
                rows = cursor.fetchall()
                return [AlertHistoryResponse(id=r[0], event_id=r[1], url=r[2], status=r[3], timestamp=r[4]) for r in rows]

    def _log_alert(self, event_id: str, url: str, status: str):
        alert_id = f"al_{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now().timestamp()
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT INTO alert_history (id, event_id, url, status, timestamp) VALUES (?, ?, ?, ?, ?)",
                             (alert_id, event_id, url, status, timestamp))
                conn.commit()

    async def dispatch(self, event: SecurityEvent):
        """Evaluate event and send webhooks asynchronously if malicious."""
        if event.detection_result.classification != "malicious":
            return
            
        webhooks = self.get_webhooks()
        active_urls = [w.url for w in webhooks if w.is_active]
        if not active_urls:
            return

        # Format the message for both Slack (text) and Discord (content/embeds)
        msg_text = f"🚨 **CRITICAL SECURITY ALERT: Malicious Command Detected** 🚨\n\n**Process ID:** `{event.execve_event.pid}`\n**Command Executed:**\n```bash\n{event.execve_event.command}\n```\n**Risk Score:** `{event.detection_result.risk_score:.1f}/100`\n**Rules Matched:** `{', '.join(event.detection_result.matched_rules) or 'None'}`"
        
        payload = {
            "text": msg_text,  # Slack
            "content": "",     # Discord
            "embeds": [{       # Rich formatting for Discord
                "title": "🚨 Kernel Guard: Malicious Activity Detected",
                "color": 16711680, # Red
                "fields": [
                    {"name": "Process ID", "value": str(event.execve_event.pid), "inline": True},
                    {"name": "Risk Score", "value": f"{event.detection_result.risk_score:.1f}/100", "inline": True},
                    {"name": "Command", "value": f"```bash\n{event.execve_event.command}\n```", "inline": False},
                    {"name": "Matched Rules", "value": ", ".join(event.detection_result.matched_rules) or "None", "inline": False}
                ],
                "footer": {"text": "AI Bouncer Automated Detection"}
            }]
        }

        # Send to all webhooks concurrently in background threads
        async def send_webhook(url: str):
            try:
                # Use requests in a thread to avoid blocking the event loop
                def do_post():
                    response = requests.post(url, json=payload, timeout=5)
                    response.raise_for_status()
                    return "success"
                
                status = await asyncio.to_thread(do_post)
            except Exception as e:
                status = f"failed: {str(e)[:50]}"
                
            self._log_alert(event.id, url, status)

        tasks = [send_webhook(url) for url in active_urls]
        await asyncio.gather(*tasks, return_exceptions=True)

# Global instance
_alert_manager = None
def get_alert_manager() -> AlertManager:
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager
