"""
Tests for SQLite-backed EventStore with in-memory caching.
Validates persistence, API contract, and thread safety.
"""

import pytest
import os
import tempfile
import threading
import uuid
from backend.events.event_store import EventStore
from backend.events.models import SecurityEvent, DetectionResult, ExecveEvent


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
        db_path = f.name
    yield db_path
    # Try to close all connections and clean up
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
    except (PermissionError, OSError):
        pass  # Let OS clean up


@pytest.fixture
def event_store(temp_db):
    """Create an event store with temporary database."""
    return EventStore(max_events=100, db_path=temp_db)


def create_event(pid=1000, command="/bin/cmd", classification="safe", timestamp=1234567890.0, agent_id=None):
    """Helper to create a SecurityEvent."""
    execve_event = ExecveEvent(
        agent_id=agent_id,
        pid=pid,
        ppid=1000,
        uid=1000,
        gid=1000,
        command=command,
        argv_str=command,
        timestamp=timestamp,
        comm="cmd"
    )
    detection_result = DetectionResult(
        classification=classification,
        risk_score=50.0,
        matched_rules=[],
        ml_confidence=0.5
    )
    return SecurityEvent(
        id=str(uuid.uuid4()),
        execve_event=execve_event,
        detection_result=detection_result,
        detected_at=timestamp + 0.5
    )


class TestEventStorePersistence:
    """Test that events persist to SQLite database."""
    
    def test_append_persists_to_db(self, event_store):
        """Verify that append() saves to SQLite."""
        event = create_event()
        assert event_store.size() == 0
        event_store.append(event)
        assert event_store.size() == 1
        
        # Create new store instance pointing to same DB to verify persistence
        new_store = EventStore(db_path=event_store.db_path)
        assert new_store.size() == 1
    
    def test_multiple_appends(self, event_store):
        """Verify multiple appends are persisted."""
        for i in range(5):
            event = create_event(pid=1000 + i, command=f"/bin/cmd_{i}", timestamp=1234567890.0 + i)
            event_store.append(event)
        
        assert event_store.size() == 5
        
        # Verify persistence
        new_store = EventStore(db_path=event_store.db_path)
        assert new_store.size() == 5


class TestEventStoreAPI:
    """Test EventStore API contract."""
    
    def test_get_recent_returns_correct_order(self, event_store):
        """Verify get_recent() returns events in reverse chronological order (newest first)."""
        for i in range(10):
            event = create_event(pid=1000 + i, command=f"/bin/cmd_{i}", timestamp=1234567890.0 + i)
            event_store.append(event)
        
        recent = event_store.get_recent(5)
        assert len(recent) == 5
        # Should be newest to oldest (reverse chronological)
        assert recent[0].execve_event.pid == 1009  # Newest (highest timestamp)
        assert recent[-1].execve_event.pid == 1005  # Oldest of the 5
    
    def test_get_recent_respects_limit(self, event_store):
        """Verify get_recent() respects the limit parameter."""
        for i in range(20):
            event = create_event(pid=1000 + i, command=f"/bin/cmd_{i}", timestamp=1234567890.0 + i)
            event_store.append(event)
        
        assert len(event_store.get_recent(5)) == 5
        assert len(event_store.get_recent(100)) == 20
        assert len(event_store.get_recent(0)) == 0
    
    def test_get_all_returns_all_events(self, event_store):
        """Verify get_all() returns all events."""
        for i in range(10):
            event = create_event(pid=1000 + i, command=f"/bin/cmd_{i}", timestamp=1234567890.0 + i)
            event_store.append(event)
        
        all_events = event_store.get_all()
        assert len(all_events) == 10
    
    def test_clear_removes_all_events(self, event_store):
        """Verify clear() removes all events."""
        for i in range(5):
            event = create_event(pid=1000 + i, command=f"/bin/cmd_{i}", timestamp=1234567890.0 + i)
            event_store.append(event)
        
        assert event_store.size() == 5
        event_store.clear()
        assert event_store.size() == 0


class TestEventStoreClassification:
    """Test filtering by classification."""
    
    def test_get_by_classification(self, event_store):
        """Verify get_by_classification() filters correctly."""
        classifications = ["safe", "suspicious", "malicious", "safe", "malicious"]
        
        for i, classification in enumerate(classifications):
            event = create_event(pid=1000 + i, command=f"/bin/cmd_{i}", 
                               classification=classification, timestamp=1234567890.0 + i)
            event_store.append(event)
        
        safe_events = event_store.get_by_classification("safe")
        suspicious_events = event_store.get_by_classification("suspicious")
        malicious_events = event_store.get_by_classification("malicious")
        
        assert len(safe_events) == 2
        assert len(suspicious_events) == 1
        assert len(malicious_events) == 2
    
    def test_count_methods(self, event_store):
        """Verify count methods return correct values."""
        classifications = ["safe", "suspicious", "malicious", "safe"]
        
        for i, classification in enumerate(classifications):
            event = create_event(pid=1000 + i, command=f"/bin/cmd_{i}",
                               classification=classification, timestamp=1234567890.0 + i)
            event_store.append(event)
        
        assert event_store.get_safe_count() == 2
        assert event_store.get_suspicious_count() == 1
        assert event_store.get_malicious_count() == 1

    def test_agent_id_filters_recent_and_classification(self, event_store):
        """Verify tenant-specific queries only return matching agent events."""
        event_store.append(create_event(pid=1, command="/bin/a", agent_id="agent-a", timestamp=1.0))
        event_store.append(create_event(pid=2, command="/bin/b", agent_id="agent-b", timestamp=2.0, classification="malicious"))
        event_store.append(create_event(pid=3, command="/bin/c", agent_id="agent-a", timestamp=3.0, classification="suspicious"))

        recent_a = event_store.get_recent(10, agent_id="agent-a")
        assert len(recent_a) == 2
        assert all(event.execve_event.agent_id == "agent-a" for event in recent_a)

        malicious_a = event_store.get_by_classification("malicious", agent_id="agent-a")
        assert len(malicious_a) == 0

        malicious_b = event_store.get_by_classification("malicious", agent_id="agent-b")
        assert len(malicious_b) == 1
        assert malicious_b[0].execve_event.agent_id == "agent-b"


class TestEventStoreThreadSafety:
    """Test thread-safe concurrent access."""
    
    def test_concurrent_appends(self, event_store):
        """Verify concurrent appends are handled correctly."""
        num_threads = 5
        events_per_thread = 10
        
        def append_events(thread_id):
            for i in range(events_per_thread):
                event = create_event(pid=1000 + thread_id, 
                                   command=f"/bin/cmd_t{thread_id}_e{i}",
                                   timestamp=1234567890.0 + thread_id * 100 + i)
                event_store.append(event)
        
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=append_events, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Should have all events without data corruption
        assert event_store.size() == num_threads * events_per_thread
        all_events = event_store.get_all()
        assert len(all_events) == num_threads * events_per_thread


class TestEventStoreCache:
    """Test in-memory LRU cache behavior."""
    
    def test_cache_respects_max_events(self, temp_db):
        """Verify cache evicts oldest entries when max_events is exceeded."""
        store = EventStore(max_events=5, db_path=temp_db)
        
        for i in range(10):
            event = create_event(pid=1000 + i, command=f"/bin/cmd_{i}", timestamp=1234567890.0 + i)
            store.append(event)
        
        # Database should have all 10 events
        assert store.size() == 10
        
        # Cache should only have the last 5
        assert len(store._cache) <= 5


class TestEventStoreIntegration:
    """Integration tests with API endpoints."""
    
    def test_event_reconstruction(self, event_store):
        """Verify events can be reconstructed from database."""
        execve_event = ExecveEvent(
            pid=5678,
            ppid=1234,
            uid=1000,
            gid=1000,
            command="/bin/bash -i",
            argv_str="/bin/bash -i",
            timestamp=1234567890.5,
            comm="bash"
        )
        detection_result = DetectionResult(
            classification="malicious",
            risk_score=95.0,
            matched_rules=["xss_rule", "injection_rule"],
            ml_confidence=0.98
        )
        original_event = SecurityEvent(
            id=str(uuid.uuid4()),
            execve_event=execve_event,
            detection_result=detection_result,
            detected_at=1234567890.5
        )
        
        event_store.append(original_event)
        retrieved_event = event_store.get_recent(1)[0]
        
        assert retrieved_event.execve_event.pid == original_event.execve_event.pid
        assert retrieved_event.execve_event.ppid == original_event.execve_event.ppid
        assert retrieved_event.execve_event.uid == original_event.execve_event.uid
        assert retrieved_event.execve_event.gid == original_event.execve_event.gid
        assert retrieved_event.execve_event.command == original_event.execve_event.command
        assert retrieved_event.detection_result.classification == "malicious"
        assert retrieved_event.detection_result.risk_score == 95.0

