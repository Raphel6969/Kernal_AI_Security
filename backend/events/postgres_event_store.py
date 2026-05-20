"""
Postgres-backed EventStore scaffold.

This module provides a PostgresEventStore implementation using SQLAlchemy Core.
It is intentionally light-weight and only used when `DATABASE_URL` is set in
configuration. To enable, install the dependencies:

    pip install sqlalchemy psycopg2-binary

This implementation mirrors the SQLiteEventStore API used by the rest of the
codebase. It aims to be a minimal drop-in replacement; further optimization
and pagination should be added as needed.
"""

import logging
from typing import List, Optional
import uuid
import json
import threading

from backend.events.models import SecurityEvent, DetectionResult, ExecveEvent
from backend.config import get_settings

try:
    from sqlalchemy import (
        create_engine, MetaData, Table, Column, String, Integer, Float, Text, select, text
    )
    from sqlalchemy.exc import SQLAlchemyError
except Exception as e:
    raise RuntimeError("PostgresEventStore requires 'sqlalchemy' and a DB driver (psycopg2-binary). Install them to enable Postgres support.") from e

logger = logging.getLogger(__name__)


class PostgresEventStore:
    """Postgres-backed event store using SQLAlchemy Core."""

    def __init__(self, max_events: int = None, database_url: str = None):
        settings = get_settings()
        self.max_events = max_events if max_events is not None else settings.event_cache_size
        self.database_url = database_url or settings.database_url
        self._lock = threading.Lock()
        self._cache = {}  # simple in-memory cache (not LRU)

        # Create engine and ensure table exists
        self.engine = create_engine(self.database_url, future=True)
        self.metadata = MetaData()
        self.security_events = Table(
            'security_events', self.metadata,
            Column('id', String, primary_key=True),
            Column('event_id', String, nullable=False),
            Column('agent_id', String),
            Column('timestamp', Float, nullable=False),
            Column('detected_at', Float, nullable=False),
            Column('pid', Integer),
            Column('ppid', Integer),
            Column('uid', Integer),
            Column('gid', Integer),
            Column('command', Text),
            Column('argv_str', Text),
            Column('comm', String),
            Column('classification', String),
            Column('risk_score', Float),
            Column('ml_confidence', Float),
            Column('matched_rules', Text),
            Column('explanation', Text),
            Column('remediation_action', Text),
            Column('remediation_status', Text),
        )

        try:
            self.metadata.create_all(self.engine)
        except SQLAlchemyError as e:
            logger.exception(f"Failed to create Postgres tables: {e}")
            raise

    def _event_to_row(self, event: SecurityEvent) -> dict:
        return {
            'id': str(uuid.uuid4()),
            'event_id': event.id,
            'agent_id': event.execve_event.agent_id,
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
            'remediation_action': event.remediation_action,
            'remediation_status': event.remediation_status,
        }

    def append(self, event: SecurityEvent) -> None:
        row = self._event_to_row(event)
        with self._lock:
            with self.engine.begin() as conn:
                conn.execute(self.security_events.insert().values(**row))
            # add to simple cache
            self._cache[event.id] = event
            # naive eviction
            if len(self._cache) > self.max_events:
                # remove oldest inserted key
                oldest = next(iter(self._cache))
                self._cache.pop(oldest, None)

    def _row_to_event(self, row) -> Optional[SecurityEvent]:
        try:
            execve_event = ExecveEvent(
                agent_id=row['agent_id'],
                pid=row['pid'] or 0,
                ppid=row['ppid'] or 0,
                uid=row['uid'] or 0,
                gid=row['gid'] or 0,
                command=row['command'] or '',
                argv_str=row['argv_str'] or '',
                timestamp=row['timestamp'],
                comm=row['comm'] or '',
            )
            matched_rules_str = row.get('matched_rules') or ''
            matched_rules_list = []
            if matched_rules_str and matched_rules_str.strip():
                try:
                    matched_rules_list = json.loads(matched_rules_str)
                except Exception:
                    matched_rules_list = []
            detection_result = DetectionResult(
                classification=row['classification'],
                risk_score=row['risk_score'],
                matched_rules=matched_rules_list,
                ml_confidence=row['ml_confidence'],
                explanation=row['explanation'],
            )
            return SecurityEvent(
                id=row['event_id'],
                execve_event=execve_event,
                detection_result=detection_result,
                detected_at=row['detected_at'],
                remediation_action=row.get('remediation_action'),
                remediation_status=row.get('remediation_status'),
            )
        except Exception:
            logger.exception("Error reconstructing event from Postgres row")
            return None

    def get_recent(self, n: int = 100, agent_id: Optional[str] = None) -> List[SecurityEvent]:
        if n <= 0:
            return []
        with self._lock:
            stmt = select(self.security_events).order_by(text('timestamp DESC')).limit(n)
            if agent_id:
                stmt = select(self.security_events).where(self.security_events.c.agent_id == agent_id).order_by(text('timestamp DESC')).limit(n)
            with self.engine.connect() as conn:
                rows = [dict(r) for r in conn.execute(stmt).fetchall()]
        events = [self._row_to_event(r) for r in rows]
        return [e for e in events if e is not None]

    def get_all(self, agent_id: Optional[str] = None) -> List[SecurityEvent]:
        with self._lock:
            stmt = select(self.security_events).order_by(text('timestamp ASC'))
            if agent_id:
                stmt = select(self.security_events).where(self.security_events.c.agent_id == agent_id).order_by(text('timestamp ASC'))
            with self.engine.connect() as conn:
                rows = [dict(r) for r in conn.execute(stmt).fetchall()]
        events = [self._row_to_event(r) for r in rows]
        return [e for e in events if e is not None]

    def clear(self) -> None:
        with self._lock:
            with self.engine.begin() as conn:
                conn.execute(self.security_events.delete())
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            with self.engine.connect() as conn:
                result = conn.execute(select([text('COUNT(*)')]).select_from(self.security_events)).scalar()
            return int(result or 0)

    def get_by_classification(self, classification: str, agent_id: Optional[str] = None) -> List[SecurityEvent]:
        with self._lock:
            stmt = select(self.security_events).where(self.security_events.c.classification == classification).order_by(text('timestamp ASC'))
            if agent_id:
                stmt = stmt.where(self.security_events.c.agent_id == agent_id)
            with self.engine.connect() as conn:
                rows = [dict(r) for r in conn.execute(stmt).fetchall()]
        events = [self._row_to_event(r) for r in rows]
        return [e for e in events if e is not None]

    def get_malicious_count(self) -> int:
        return len(self.get_by_classification("malicious"))

    def get_suspicious_count(self) -> int:
        return len(self.get_by_classification("suspicious"))

    def get_safe_count(self) -> int:
        return len(self.get_by_classification("safe"))
