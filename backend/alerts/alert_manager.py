import os
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

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_DB_PATH = os.path.join(_PROJECT_ROOT, "data", "events.db")

class AlertManager:
    def __init__(self, db_path: str = _DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()
        
    def _init_db(self):
        parent_dir = os.path.dirname(self.db_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            # We are dropping the old table to quickly migrate the schema for the new features
            conn.execute("DROP TABLE IF EXISTS webhooks")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS webhooks (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at REAL NOT NULL,
                    trigger_safe BOOLEAN DEFAULT 0,
                    trigger_suspicious BOOLEAN DEFAULT 0,
                    trigger_malicious BOOLEAN DEFAULT 1
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

    def add_webhook(self, url: str, trigger_safe: bool = False, trigger_suspicious: bool = False, trigger_malicious: bool = True) -> WebhookResponse:
        webhook_id = f"wh_{uuid.uuid4().hex[:8]}"
        created_at = datetime.now().timestamp()
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT INTO webhooks (id, url, is_active, created_at, trigger_safe, trigger_suspicious, trigger_malicious) VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (webhook_id, url, 1, created_at, trigger_safe, trigger_suspicious, trigger_malicious))
                conn.commit()
                
        return WebhookResponse(
            id=webhook_id, 
            url=url, 
            is_active=True, 
            created_at=created_at,
            trigger_safe=trigger_safe,
            trigger_suspicious=trigger_suspicious,
            trigger_malicious=trigger_malicious
        )

    def remove_webhook(self, webhook_id: str):
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
                conn.commit()

    def get_webhooks(self) -> List[WebhookResponse]:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT id, url, is_active, created_at, trigger_safe, trigger_suspicious, trigger_malicious FROM webhooks")
                rows = cursor.fetchall()
                return [
                    WebhookResponse(
                        id=r[0], 
                        url=r[1], 
                        is_active=bool(r[2]), 
                        created_at=r[3],
                        trigger_safe=bool(r[4]),
                        trigger_suspicious=bool(r[5]),
                        trigger_malicious=bool(r[6])
                    ) for r in rows
                ]

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
        """Evaluate event and send webhooks asynchronously if it matches triggers."""
        classification = event.detection_result.classification
        webhooks = self.get_webhooks()
        
        active_urls = []
        for w in webhooks:
            if not w.is_active:
                continue
            if classification == "safe" and w.trigger_safe:
                active_urls.append(w.url)
            elif classification == "suspicious" and w.trigger_suspicious:
                active_urls.append(w.url)
            elif classification == "malicious" and w.trigger_malicious:
                active_urls.append(w.url)
                
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
