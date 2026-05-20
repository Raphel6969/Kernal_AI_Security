"""
In-memory session-scoped event store.

Stores events per `session_id` in memory only and evicts sessions after
`ttl_seconds` of inactivity. Designed for demo/demo-session usage where
events must not be persisted.
"""
import threading
import time
from collections import OrderedDict
from typing import Dict, List, Optional

from backend.events.models import SecurityEvent


class SessionEventStore:
    """Simple thread-safe session event store with TTL-based cleanup."""

    def __init__(self, ttl_seconds: int = 3600):
        self._sessions: Dict[str, OrderedDict] = {}
        self._last_access: Dict[str, float] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

        # Background cleaner
        self._stop = False
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleaner.start()

    def _cleanup_loop(self):
        while not self._stop:
            now = time.time()
            with self._lock:
                to_delete = [sid for sid, ts in self._last_access.items() if now - ts > self._ttl]
                for sid in to_delete:
                    self._sessions.pop(sid, None)
                    self._last_access.pop(sid, None)
            time.sleep(max(1, min(60, self._ttl // 10)))

    def append(self, event: SecurityEvent) -> None:
        sid = getattr(event.execve_event, "session_id", None)
        if not sid:
            return
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None:
                sess = OrderedDict()
                self._sessions[sid] = sess
            sess[event.id] = event
            self._last_access[sid] = time.time()

    def get_recent(self, n: int = 100, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> List[SecurityEvent]:
        if not session_id:
            return []
        with self._lock:
            sess = self._sessions.get(session_id, OrderedDict())
            self._last_access[session_id] = time.time()
            events = list(sess.values())
        # Return newest-first
        events = list(reversed(events))
        if agent_id:
            events = [e for e in events if e.execve_event.agent_id == agent_id]
        return events[:n]

    def get_all(self, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> List[SecurityEvent]:
        if not session_id:
            return []
        with self._lock:
            sess = self._sessions.get(session_id, OrderedDict())
            self._last_access[session_id] = time.time()
            events = list(sess.values())
        if agent_id:
            events = [e for e in events if e.execve_event.agent_id == agent_id]
        return events

    def clear(self, session_id: Optional[str] = None) -> None:
        with self._lock:
            if session_id:
                self._sessions.pop(session_id, None)
                self._last_access.pop(session_id, None)
            else:
                self._sessions.clear()
                self._last_access.clear()

    def size(self, session_id: Optional[str] = None) -> int:
        with self._lock:
            if session_id:
                return len(self._sessions.get(session_id, {}))
            return sum(len(s) for s in self._sessions.values())

    def get_by_classification(self, classification: str, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> List[SecurityEvent]:
        events = self.get_all(agent_id=agent_id, session_id=session_id)
        return [e for e in events if e.detection_result.classification == classification]

    def get_malicious_count(self, session_id: Optional[str] = None) -> int:
        return len(self.get_by_classification("malicious", session_id=session_id))

    def get_suspicious_count(self, session_id: Optional[str] = None) -> int:
        return len(self.get_by_classification("suspicious", session_id=session_id))

    def get_safe_count(self, session_id: Optional[str] = None) -> int:
        return len(self.get_by_classification("safe", session_id=session_id))

    def stop(self):
        self._stop = True
        try:
            self._cleaner.join(timeout=1)
        except Exception:
            pass
