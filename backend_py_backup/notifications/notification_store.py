"""Persistent in-app notification feed (SQLite)."""

import os
import sqlite3
import threading
import uuid
from datetime import datetime
from typing import List, Optional

from backend.notifications.models import NotificationResponse

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_DB_PATH = os.path.join(_PROJECT_ROOT, "data", "events.db")


class NotificationStore:
    def __init__(self, db_path: str = _DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notifications (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    read INTEGER DEFAULT 0,
                    session_id TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS departments (
                    name TEXT PRIMARY KEY,
                    email TEXT NOT NULL
                )
                """
            )
            # Seed defaults if empty
            cursor = conn.execute("SELECT COUNT(*) FROM departments")
            if cursor.fetchone()[0] == 0:
                conn.executemany(
                    "INSERT INTO departments (name, email) VALUES (?, ?)",
                    [
                        ("SOC Operations", "soc@yourcompany.com"),
                        ("Security Engineering", "security@yourcompany.com"),
                        ("Incident Response", "ir@yourcompany.com"),
                    ],
                )
            conn.commit()

    def add(
        self,
        *,
        category: str,
        title: str,
        message: str,
        session_id: Optional[str] = None,
    ) -> NotificationResponse:
        notif_id = f"ntf_{uuid.uuid4().hex[:8]}"
        ts = datetime.now().timestamp()
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO notifications (id, category, title, message, timestamp, read, session_id)
                    VALUES (?, ?, ?, ?, ?, 0, ?)
                    """,
                    (notif_id, category, title, message, ts, session_id),
                )
                conn.commit()
        return NotificationResponse(
            id=notif_id,
            category=category,
            title=title,
            message=message,
            timestamp=ts,
            read=False,
            session_id=session_id,
        )

    def list_recent(
        self,
        limit: int = 50,
        session_id: Optional[str] = None,
        unread_only: bool = False,
    ) -> List[NotificationResponse]:
        clauses = []
        params: list = []
        if session_id is not None:
            clauses.append("(session_id IS NULL OR session_id = ?)")
            params.append(session_id)
        if unread_only:
            clauses.append("read = 0")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    f"""
                    SELECT id, category, title, message, timestamp, read, session_id
                    FROM notifications
                    {where}
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    params,
                ).fetchall()
        return [
            NotificationResponse(
                id=r[0],
                category=r[1],
                title=r[2],
                message=r[3],
                timestamp=r[4],
                read=bool(r[5]),
                session_id=r[6],
            )
            for r in rows
        ]

    def unread_count(self, session_id: Optional[str] = None) -> int:
        clauses = ["read = 0"]
        params: list = []
        if session_id is not None:
            clauses.append("(session_id IS NULL OR session_id = ?)")
            params.append(session_id)
        where = " AND ".join(clauses)
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    f"SELECT COUNT(*) FROM notifications WHERE {where}",
                    params,
                ).fetchone()
        return int(row[0]) if row else 0

    def mark_read(self, notif_id: str) -> bool:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    "UPDATE notifications SET read = 1 WHERE id = ?",
                    (notif_id,),
                )
                conn.commit()
                return cur.rowcount > 0

    def mark_all_read(self, session_id: Optional[str] = None) -> int:
        if session_id is not None:
            sql = "UPDATE notifications SET read = 1 WHERE read = 0 AND (session_id IS NULL OR session_id = ?)"
            params = (session_id,)
        else:
            sql = "UPDATE notifications SET read = 1 WHERE read = 0"
            params = ()
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(sql, params)
                conn.commit()
                return cur.rowcount

    def clear_all(self, session_id: Optional[str] = None) -> int:
        if session_id is not None:
            sql = "DELETE FROM notifications WHERE session_id IS NULL OR session_id = ?"
            params = (session_id,)
        else:
            sql = "DELETE FROM notifications"
            params = ()
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(sql, params)
                conn.commit()
                return cur.rowcount

    def list_departments(self) -> dict[str, str]:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT name, email FROM departments ORDER BY name ASC"
                ).fetchall()
        return {r[0]: r[1] for r in rows}

    def add_department(self, name: str, email: str) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO departments (name, email) VALUES (?, ?)",
                    (name.strip(), email.strip()),
                )
                conn.commit()

    def delete_department(self, name: str) -> bool:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    "DELETE FROM departments WHERE name = ?",
                    (name.strip(),),
                )
                conn.commit()
                return cur.rowcount > 0


_store: Optional[NotificationStore] = None


def get_notification_store() -> NotificationStore:
    global _store
    if _store is None:
        _store = NotificationStore()
    return _store
