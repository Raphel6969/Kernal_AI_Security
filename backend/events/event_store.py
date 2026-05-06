"""
SQLite-backed event store for security events with in-memory LRU cache for recent events.
Provides persistent storage with same API as in-memory implementation.
"""

import sqlite3
import json
import threading
import uuid
from typing import List, Optional, OrderedDict
from collections import OrderedDict as ODict
from backend.events.models import SecurityEvent, DetectionResult, ExecveEvent


class EventStore:
    """
    Thread-safe persistent event storage using SQLite with in-memory LRU cache.
    Recent events are cached in memory for fast access; all events persisted to disk.
    """

    def __init__(self, max_events: int = 1000, db_path: str = "events.db"):
        """
        Initialize event store with SQLite backend.
        
        Args:
            max_events: Maximum number of events to keep in memory cache
            db_path: Path to SQLite database file
        """
        self.max_events = max_events
        self.db_path = db_path
        self._lock = threading.Lock()
        self._cache: ODict = ODict()  # In-memory LRU cache
        
        # Initialize database
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize SQLite database and create tables if needed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
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
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON security_events(timestamp DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_classification 
                ON security_events(classification)
            """)
            conn.commit()
    
    def _event_to_row(self, event: SecurityEvent) -> dict:
        """Convert SecurityEvent to database row dict."""
        return {
            'id': str(uuid.uuid4()),
            'event_id': event.id,
            'timestamp': event.execve_event.timestamp,
            'detected_at': event.detected_at,
            'pid': event.execve_event.pid,
            'ppid': event.execve_event.ppid,
            'uid': event.execve_event.uid,
            'gid': event.execve_event.gid,
            'command': event.execve_event.command,
            'argv_str': event.execve_event.argv_str,
            'comm': event.execve_event.comm,
            'classification': event.detection_result.classification,
            'risk_score': event.detection_result.risk_score,
            'ml_confidence': event.detection_result.ml_confidence,
            'matched_rules': json.dumps(event.detection_result.matched_rules),
            'explanation': event.detection_result.explanation,
        }
    
    def _row_to_event(self, row: tuple) -> Optional[SecurityEvent]:
        """Reconstruct SecurityEvent from database row."""
        try:
            # row format: (id, event_id, timestamp, detected_at, pid, ppid, uid, gid, command, argv_str, comm, classification, risk_score, ml_confidence, matched_rules, explanation, created_at)
            _, event_id, timestamp, detected_at, pid, ppid, uid, gid, command, argv_str, comm, classification, risk_score, ml_confidence, matched_rules, explanation, _ = row
            
            # Reconstruct ExecveEvent
            execve_event = ExecveEvent(
                pid=pid,
                ppid=ppid,
                uid=uid,
                gid=gid,
                command=command,
                argv_str=argv_str,
                timestamp=timestamp,
                comm=comm
            )
            
            # Parse matched_rules
            matched_rules_list = json.loads(matched_rules) if matched_rules else []
            
            # Reconstruct DetectionResult
            detection_result = DetectionResult(
                classification=classification,
                risk_score=risk_score,
                matched_rules=matched_rules_list,
                ml_confidence=ml_confidence,
                explanation=explanation
            )
            
            # Reconstruct SecurityEvent
            event = SecurityEvent(
                id=event_id,
                execve_event=execve_event,
                detection_result=detection_result,
                detected_at=detected_at
            )
            return event
        except Exception as e:
            print(f"Error reconstructing event from database row: {e}")
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
                conn.execute("""
                    INSERT INTO security_events 
                    (id, event_id, timestamp, detected_at, pid, ppid, uid, gid, command, argv_str, comm, classification, risk_score, ml_confidence, matched_rules, explanation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (row_data['id'], row_data['event_id'], row_data['timestamp'], row_data['detected_at'], 
                      row_data['pid'], row_data['ppid'], row_data['uid'], row_data['gid'],
                      row_data['command'], row_data['argv_str'], row_data['comm'],
                      row_data['classification'], row_data['risk_score'], row_data['ml_confidence'],
                      row_data['matched_rules'], row_data['explanation']))
                conn.commit()
            
            # Add to in-memory cache (maintain LRU)
            cache_key = event.id
            self._cache[cache_key] = event
            
            # Evict oldest from cache if exceeds max_events
            while len(self._cache) > self.max_events:
                self._cache.popitem(last=False)

    def get_recent(self, n: int = 100) -> List[SecurityEvent]:
        """
        Get the N most recent events from database.
        
        Args:
            n: Number of recent events to retrieve
            
        Returns:
            List of SecurityEvent objects (oldest to newest)
        """
        if n <= 0:
            return []
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                # Get total count
                cursor = conn.execute("SELECT COUNT(*) FROM security_events")
                total = cursor.fetchone()[0]
                
                # Calculate offset to get last n rows
                offset = max(0, total - n)
                
                # Get rows in ascending order (oldest to newest)
                cursor = conn.execute("""
                    SELECT * FROM security_events 
                    ORDER BY timestamp ASC 
                    LIMIT ? OFFSET ?
                """, (n, offset))
                rows = cursor.fetchall()
            
            events = [self._row_to_event(row) for row in rows]
            return [e for e in events if e is not None]

    def get_all(self) -> List[SecurityEvent]:
        """
        Get all events from database.
        
        Returns:
            List of all SecurityEvent objects (oldest to newest)
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT * FROM security_events 
                    ORDER BY timestamp ASC
                """)
                rows = cursor.fetchall()
            
            events = [self._row_to_event(row) for row in rows]
            return [e for e in events if e is not None]

    def clear(self) -> None:
        """Clear all events from database and cache."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM security_events")
                conn.commit()
            self._cache.clear()

    def size(self) -> int:
        """Get the total number of events in persistent storage."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM security_events")
                count = cursor.fetchone()[0]
            return count

    def get_by_classification(self, classification: str) -> List[SecurityEvent]:
        """
        Get all events of a specific classification from database.
        
        Args:
            classification: One of "safe", "suspicious", "malicious"
            
        Returns:
            List of matching SecurityEvent objects
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT * FROM security_events 
                    WHERE classification = ?
                    ORDER BY timestamp ASC
                """, (classification,))
                rows = cursor.fetchall()
            
            events = [self._row_to_event(row) for row in rows]
            return [e for e in events if e is not None]

    
    def get_malicious_count(self) -> int:
        """Get count of malicious events."""
        return len(self.get_by_classification("malicious"))

    def get_suspicious_count(self) -> int:
        """Get count of suspicious events."""
        return len(self.get_by_classification("suspicious"))

    def get_safe_count(self) -> int:
        """Get count of safe events."""
        return len(self.get_by_classification("safe"))


# Global event store instance
_event_store = None


def get_event_store(max_events: int = 1000) -> EventStore:
    """
    Get or create the global event store.
    
    Args:
        max_events: Max events to keep in cache (only used on first call)
        
    Returns:
        The global EventStore instance
    """
    global _event_store
    if _event_store is None:
        _event_store = EventStore(max_events=max_events)
    return _event_store
