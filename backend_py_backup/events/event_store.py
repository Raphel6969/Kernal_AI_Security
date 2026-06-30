"""
SQLite-backed event store for security events with in-memory LRU cache for recent events.
Provides persistent storage with same API as in-memory implementation.
"""

import os
import sqlite3
import json
import threading
import uuid
import logging
from typing import List, Optional, OrderedDict
from collections import OrderedDict as ODict
from backend.events.models import SecurityEvent, DetectionResult, ExecveEvent
from backend.config import get_settings


def _row_get(row, key, default=None):
    """Safely get a column value from a row which may be a dict or sqlite3.Row.

    Returns `default` when the key is missing or access fails.
    """
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except Exception:
        try:
            return getattr(row, key, default)
        except Exception:
            return default


class SQLiteEventStore:
    """
    Thread-safe persistent event storage using SQLite with in-memory LRU cache.
    Recent events are cached in memory for fast access; all events persisted to disk.
    """

    def __init__(self, max_events: int = None, db_path: str = None):
        """
        Initialize event store with SQLite backend.

        Args:
            max_events: Maximum number of events to keep in memory cache (uses config default if None)
            db_path: Path to SQLite database file (uses config default if None)
        """
        settings = get_settings()
        self.max_events = (
            max_events if max_events is not None else settings.event_cache_size
        )
        self.db_path = db_path if db_path is not None else settings.db_path
        self._lock = threading.Lock()
        self._cache: ODict = ODict()  # In-memory LRU cache

        # Initialize database
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite database and create tables if needed."""
        # Ensure the parent directory exists (handles first-run on any platform)
        parent_dir = os.path.dirname(self.db_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    agent_id TEXT,
                    session_id TEXT,
                    timestamp REAL NOT NULL,
                    detected_at REAL NOT NULL,
                    pid INTEGER,
                    ppid INTEGER,
                    uid INTEGER,
                    gid INTEGER,
                    command TEXT,
                    argv_str TEXT,
                    comm TEXT,
                    classification TEXT,
                    risk_score REAL,
                    ml_confidence REAL,
                    matched_rules TEXT,
                    explanation TEXT,
                    remediation_action TEXT,
                    remediation_status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            # Migrate existing DBs that don't have the remediation columns yet
            try:
                conn.execute("ALTER TABLE security_events ADD COLUMN agent_id TEXT")
            except Exception:
                pass  # Column already exists
            try:
                conn.execute("ALTER TABLE security_events ADD COLUMN session_id TEXT")
            except Exception:
                pass
            for col, coltype in [
                ("remediation_action", "TEXT"),
                ("remediation_status", "TEXT"),
            ]:
                try:
                    conn.execute(
                        f"ALTER TABLE security_events ADD COLUMN {col} {coltype}"
                    )
                except Exception:
                    pass  # Column already exists
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON security_events(timestamp DESC)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_agent_timestamp 
                ON security_events(agent_id, timestamp DESC)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_classification 
                ON security_events(classification)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_session_timestamp 
                ON security_events(session_id, timestamp DESC)
            """
            )
            conn.commit()
            conn.commit()

    def _event_to_row(self, event: SecurityEvent) -> dict:
        """Convert SecurityEvent to database row dict."""
        return {
            "id": str(uuid.uuid4()),
            "event_id": event.id,
            "agent_id": event.execve_event.agent_id,
            "session_id": getattr(event.execve_event, "session_id", None),
            "timestamp": event.execve_event.timestamp,
            "detected_at": event.detected_at,
            "pid": event.execve_event.pid,
            "ppid": event.execve_event.ppid,
            "uid": event.execve_event.uid,
            "gid": event.execve_event.gid,
            "command": event.execve_event.command,
            "argv_str": event.execve_event.argv_str,
            "comm": event.execve_event.comm,
            "classification": event.detection_result.classification,
            "risk_score": event.detection_result.risk_score,
            "ml_confidence": event.detection_result.ml_confidence,
            "matched_rules": json.dumps(event.detection_result.matched_rules),
            "explanation": event.detection_result.explanation,
            "remediation_action": event.remediation_action,
            "remediation_status": event.remediation_status,
        }

    # Canonical SELECT used everywhere — explicit names defeat column-order bugs on migrated DBs
    _SELECT_COLS = """
        id, event_id, agent_id, session_id, timestamp, detected_at,
        pid, ppid, uid, gid,
        command, argv_str, comm,
        classification, risk_score, ml_confidence,
        matched_rules, explanation,
        remediation_action, remediation_status,
        created_at
    """

    def _row_to_event(self, row) -> Optional[SecurityEvent]:
        """Reconstruct SecurityEvent from a sqlite3.Row (named-column access)."""
        try:
            execve_event = ExecveEvent(
                agent_id=row["agent_id"],
                session_id=_row_get(row, "session_id", None),
                pid=row["pid"] or 0,
                ppid=row["ppid"] or 0,
                uid=row["uid"] or 0,
                gid=row["gid"] or 0,
                command=row["command"] or "",
                argv_str=row["argv_str"] or "",
                timestamp=row["timestamp"],
                comm=row["comm"] or "",
            )
            # Handle matched_rules: could be JSON string, empty string, or None
            matched_rules_str = _row_get(row, "matched_rules") or ""
            matched_rules_list = []
            if matched_rules_str and matched_rules_str.strip():
                try:
                    matched_rules_list = json.loads(matched_rules_str)
                except (json.JSONDecodeError, TypeError):
                    matched_rules_list = []

            detection_result = DetectionResult(
                classification=row["classification"],
                risk_score=row["risk_score"],
                matched_rules=matched_rules_list,
                ml_confidence=row["ml_confidence"],
                explanation=row["explanation"],
            )
            return SecurityEvent(
                id=row["event_id"],
                execve_event=execve_event,
                detection_result=detection_result,
                detected_at=row["detected_at"],
                remediation_action=row["remediation_action"],
                remediation_status=row["remediation_status"],
            )
        except Exception as e:
            import logging

            logging.getLogger(__name__).exception(
                f"Error reconstructing event from database row: {e}"
            )
            return None

    def append(self, event: SecurityEvent) -> None:
        """
        Add an event to persistent storage and cache.

        Args:
            event: SecurityEvent to store
        """
        with self._lock:
            # Insert into database
            row_data = self._event_to_row(event)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO security_events 
                    (id, event_id, agent_id, session_id, timestamp, detected_at, pid, ppid, uid, gid, command, argv_str, comm,
                     classification, risk_score, ml_confidence, matched_rules, explanation,
                     remediation_action, remediation_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        row_data["id"],
                        row_data["event_id"],
                        row_data["agent_id"],
                        row_data["session_id"],
                        row_data["timestamp"],
                        row_data["detected_at"],
                        row_data["pid"],
                        row_data["ppid"],
                        row_data["uid"],
                        row_data["gid"],
                        row_data["command"],
                        row_data["argv_str"],
                        row_data["comm"],
                        row_data["classification"],
                        row_data["risk_score"],
                        row_data["ml_confidence"],
                        row_data["matched_rules"],
                        row_data["explanation"],
                        row_data["remediation_action"],
                        row_data["remediation_status"],
                    ),
                )
                conn.commit()

            # Add to in-memory cache (maintain LRU)
            cache_key = event.id
            self._cache[cache_key] = event

            # Evict oldest from cache if exceeds max_events
            while len(self._cache) > self.max_events:
                self._cache.popitem(last=False)

    def get_recent(
        self,
        n: int = 100,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """
        Get the N most recent events from database.

        Args:
            n: Number of recent events to retrieve

        Returns:
            List of SecurityEvent objects in reverse chronological order (newest to oldest)
        """
        if n <= 0:
            return []

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if session_id is not None:
                    if agent_id is None:
                        cursor = conn.execute(
                            f"SELECT {self._SELECT_COLS} FROM security_events WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
                            (session_id, n),
                        )
                    else:
                        cursor = conn.execute(
                            f"SELECT {self._SELECT_COLS} FROM security_events WHERE session_id = ? AND agent_id = ? ORDER BY timestamp DESC LIMIT ?",
                            (session_id, agent_id, n),
                        )
                else:
                    if agent_id is None:
                        cursor = conn.execute(
                            f"SELECT {self._SELECT_COLS} FROM security_events ORDER BY timestamp DESC LIMIT ?",
                            (n,),
                        )
                    else:
                        cursor = conn.execute(
                            f"SELECT {self._SELECT_COLS} FROM security_events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
                            (agent_id, n),
                        )
                rows = cursor.fetchall()
            events = [self._row_to_event(row) for row in rows]
            # Return newest-first (DESC from query)
            return [e for e in events if e is not None]

    def get_event(
        self, event_id: str, session_id: Optional[str] = None
    ) -> Optional[SecurityEvent]:
        """Get a single event by its event_id."""
        with self._lock:
            # Check cache first
            if event_id in self._cache:
                return self._cache[event_id]

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    f"SELECT {self._SELECT_COLS} FROM security_events WHERE event_id = ?",
                    (event_id,),
                )
                row = cursor.fetchone()

            if row:
                event = self._row_to_event(row)
                if event:
                    self._cache[event_id] = event
                return event
            return None

    def update_event_explanation(
        self, event_id: str, explanation: str, session_id: Optional[str] = None
    ) -> bool:
        """Update the explanation for a specific event."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                if session_id is not None:
                    cursor = conn.execute(
                        "UPDATE security_events SET explanation = ? WHERE event_id = ? AND session_id = ?",
                        (explanation, event_id, session_id),
                    )
                else:
                    cursor = conn.execute(
                        "UPDATE security_events SET explanation = ? WHERE event_id = ?",
                        (explanation, event_id),
                    )
                conn.commit()
                success = cursor.rowcount > 0

            if success and event_id in self._cache:
                self._cache[event_id].detection_result.explanation = explanation

            return success

    def get_all(
        self, agent_id: Optional[str] = None, session_id: Optional[str] = None
    ) -> List[SecurityEvent]:
        """
        Get all events from database.

        Returns:
            List of all SecurityEvent objects (oldest to newest)
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if session_id is not None:
                    if agent_id is None:
                        cursor = conn.execute(
                            f"SELECT {self._SELECT_COLS} FROM security_events WHERE session_id = ? ORDER BY timestamp ASC",
                            (session_id,),
                        )
                    else:
                        cursor = conn.execute(
                            f"SELECT {self._SELECT_COLS} FROM security_events WHERE session_id = ? AND agent_id = ? ORDER BY timestamp ASC",
                            (session_id, agent_id),
                        )
                else:
                    if agent_id is None:
                        cursor = conn.execute(
                            f"SELECT {self._SELECT_COLS} FROM security_events ORDER BY timestamp ASC"
                        )
                    else:
                        cursor = conn.execute(
                            f"SELECT {self._SELECT_COLS} FROM security_events WHERE agent_id = ? ORDER BY timestamp ASC",
                            (agent_id,),
                        )
                rows = cursor.fetchall()
            events = [self._row_to_event(row) for row in rows]
            return [e for e in events if e is not None]

    def clear(self, session_id: Optional[str] = None) -> None:
        """Clear events from database and cache. If `session_id` is provided, only clear that session."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                if session_id is None:
                    conn.execute("DELETE FROM security_events")
                else:
                    conn.execute(
                        "DELETE FROM security_events WHERE session_id = ?",
                        (session_id,),
                    )
                conn.commit()
            # Clear cache entries for matching session
            if session_id is None:
                self._cache.clear()
            else:
                keys_to_delete = [
                    k
                    for k, v in list(self._cache.items())
                    if getattr(v.execve_event, "session_id", None) == session_id
                ]
                for k in keys_to_delete:
                    self._cache.pop(k, None)

    def size(
        self, session_id: Optional[str] = None, agent_id: Optional[str] = None
    ) -> int:
        """Get the total number of events in persistent storage. Optionally filter by `session_id` and `agent_id`."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                if session_id is not None:
                    if agent_id is None:
                        cursor = conn.execute(
                            "SELECT COUNT(*) FROM security_events WHERE session_id = ?",
                            (session_id,),
                        )
                    else:
                        cursor = conn.execute(
                            "SELECT COUNT(*) FROM security_events WHERE session_id = ? AND agent_id = ?",
                            (session_id, agent_id),
                        )
                else:
                    if agent_id is None:
                        cursor = conn.execute("SELECT COUNT(*) FROM security_events")
                    else:
                        cursor = conn.execute(
                            "SELECT COUNT(*) FROM security_events WHERE agent_id = ?",
                            (agent_id,),
                        )
                count = cursor.fetchone()[0]
            return count

    def count_by_classification(
        self,
        classification: str,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> int:
        """Get the count of events of a specific classification using COUNT(*)."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                if session_id is not None:
                    if agent_id is None:
                        cursor = conn.execute(
                            "SELECT COUNT(*) FROM security_events WHERE classification = ? AND session_id = ?",
                            (classification, session_id),
                        )
                    else:
                        cursor = conn.execute(
                            "SELECT COUNT(*) FROM security_events WHERE classification = ? AND session_id = ? AND agent_id = ?",
                            (classification, session_id, agent_id),
                        )
                else:
                    if agent_id is None:
                        cursor = conn.execute(
                            "SELECT COUNT(*) FROM security_events WHERE classification = ?",
                            (classification,),
                        )
                    else:
                        cursor = conn.execute(
                            "SELECT COUNT(*) FROM security_events WHERE classification = ? AND agent_id = ?",
                            (classification, agent_id),
                        )
                return cursor.fetchone()[0]

    def get_by_classification(
        self,
        classification: str,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """
        Get all events of a specific classification from database.

        Args:
            classification: One of "safe", "suspicious", "malicious"

        Returns:
            List of matching SecurityEvent objects
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if session_id is not None:
                    if agent_id is None:
                        cursor = conn.execute(
                            f"""
                            SELECT {self._SELECT_COLS} FROM security_events 
                            WHERE classification = ? AND session_id = ?
                            ORDER BY timestamp ASC
                        """,
                            (classification, session_id),
                        )
                    else:
                        cursor = conn.execute(
                            f"""
                            SELECT {self._SELECT_COLS} FROM security_events 
                            WHERE classification = ? AND session_id = ? AND agent_id = ?
                            ORDER BY timestamp ASC
                        """,
                            (classification, session_id, agent_id),
                        )
                else:
                    if agent_id is None:
                        cursor = conn.execute(
                            f"""
                            SELECT {self._SELECT_COLS} FROM security_events 
                            WHERE classification = ?
                            ORDER BY timestamp ASC
                        """,
                            (classification,),
                        )
                    else:
                        cursor = conn.execute(
                            f"""
                            SELECT {self._SELECT_COLS} FROM security_events 
                            WHERE classification = ? AND agent_id = ?
                            ORDER BY timestamp ASC
                        """,
                            (classification, agent_id),
                        )
                rows = cursor.fetchall()

            events = [self._row_to_event(row) for row in rows]
            return [e for e in events if e is not None]

    def get_malicious_count(
        self, agent_id: Optional[str] = None, session_id: Optional[str] = None
    ) -> int:
        """Get count of malicious events."""
        return self.count_by_classification(
            "malicious", agent_id=agent_id, session_id=session_id
        )

    def get_suspicious_count(
        self, agent_id: Optional[str] = None, session_id: Optional[str] = None
    ) -> int:
        """Get count of suspicious events."""
        return self.count_by_classification(
            "suspicious", agent_id=agent_id, session_id=session_id
        )

    def get_safe_count(
        self, agent_id: Optional[str] = None, session_id: Optional[str] = None
    ) -> int:
        """Get count of safe events."""
        return self.count_by_classification(
            "safe", agent_id=agent_id, session_id=session_id
        )


# Global event store instance
_event_store = None


def get_event_store(max_events: int = None):
    """
    Factory: Get or create the global event store.

    If `DATABASE_URL` is provided via settings, attempt to instantiate a
    Postgres-backed store (scaffold). Otherwise fall back to the bundled
    SQLiteEventStore.
    """
    global _event_store
    if _event_store is None:
        settings = get_settings()
        # If session mode is active, use the in-memory SessionEventStore
        if getattr(settings, "session_mode", False):
            try:
                from backend.events.session_event_store import SessionEventStore

                _event_store = SessionEventStore(ttl_seconds=settings.session_ttl)
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "Failed to initialize SessionEventStore; falling back to SQLiteEventStore"
                )
                _event_store = SQLiteEventStore(
                    max_events=max_events, db_path=settings.db_path
                )
        elif getattr(settings, "database_url", None):
            # Lazy import of PostgresEventStore to avoid adding DB deps for local dev
            try:
                from backend.events.postgres_event_store import PostgresEventStore

                _event_store = PostgresEventStore(
                    max_events=max_events, database_url=settings.database_url
                )
            except Exception:
                # If Postgres store cannot be created, fallback to SQLite and log
                import logging

                logging.getLogger(__name__).exception(
                    "Failed to initialize PostgresEventStore; falling back to SQLiteEventStore"
                )
                _event_store = SQLiteEventStore(
                    max_events=max_events, db_path=settings.db_path
                )
        else:
            _event_store = SQLiteEventStore(
                max_events=max_events, db_path=settings.db_path
            )
    return _event_store


# Alias for backward compatibility
EventStore = SQLiteEventStore
