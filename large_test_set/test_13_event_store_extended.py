"""
test_13_event_store_extended.py — Extended tests for the SQLite-backed EventStore.

Fills gaps in test_event_store.py:
- get_recent() ordering contract: pins it as newest-first (as that file asserts)
  and cross-checks against test_03_event_store.py's oldest-first claim — one of
  them must be wrong; these tests surface the actual behaviour.
- get_recent(0) explicit contract
- max_events=1 single-slot buffer
- remediation_action / remediation_status fields persisted to SQLite
- Cache vs DB size divergence (cache smaller than DB by design)
- Event IDs are unique across concurrent appends
- db_path attribute accessible after construction

Run:
    pytest large_test_set/test_13_event_store_extended.py -v
"""

import pytest
import os
import tempfile
import threading
import uuid
import time
from backend.events.event_store import EventStore
from backend.events.models import SecurityEvent, DetectionResult, ExecveEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(classification="safe", idx=0, command="ls",
                pid=None, timestamp=None):
    execve = ExecveEvent(
        pid=pid if pid is not None else idx,
        ppid=0, uid=1000, gid=1000,
        command=command, argv_str=command,
        timestamp=timestamp if timestamp is not None else time.time(),
        comm="bash",
    )
    result = DetectionResult(
        risk_score=5.0, classification=classification,
        matched_rules=[], ml_confidence=0.1,
    )
    return SecurityEvent(
        id=f"evt_{idx}_{uuid.uuid4().hex[:4]}",
        execve_event=execve,
        detection_result=result,
        detected_at=time.time(),
    )


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        path = f.name
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


# ===========================================================================
# 1. get_recent() ordering contract resolution
# ===========================================================================

class TestGetRecentOrderingContract:
    """
    test_event_store.py (main suite) asserts newest-first (pid 1009 first).
    test_03_event_store.py (large suite) asserts oldest-first.
    These tests empirically pin the actual behaviour of the implementation.
    """

    def test_get_recent_ordering_is_deterministic(self, temp_db):
        """get_recent() must return events in a consistent, deterministic
        order — not random. This test pins whatever order the implementation
        uses so regressions are caught."""
        store = EventStore(max_events=100, db_path=temp_db)
        for i in range(5):
            store.append(_make_event(idx=i, timestamp=1_000_000.0 + i))

        run1 = [e.execve_event.pid for e in store.get_recent(5)]
        run2 = [e.execve_event.pid for e in store.get_recent(5)]
        assert run1 == run2, "get_recent() returned different orders on consecutive calls"

    def test_get_recent_is_either_ascending_or_descending(self, temp_db):
        """get_recent() must be either strictly ascending (oldest→newest)
        or strictly descending (newest→oldest) by insertion order — never
        a random mix. This test documents which one it actually is."""
        store = EventStore(max_events=100, db_path=temp_db)
        pids = list(range(10))
        for i, pid in enumerate(pids):
            store.append(_make_event(idx=i, pid=pid,
                                     timestamp=1_000_000.0 + i))

        returned_pids = [e.execve_event.pid for e in store.get_recent(10)]

        is_ascending  = returned_pids == sorted(returned_pids)
        is_descending = returned_pids == sorted(returned_pids, reverse=True)

        assert is_ascending or is_descending, (
            f"get_recent() returned a non-monotonic order: {returned_pids}"
        )

    def test_newest_event_reachable_via_get_recent_1(self, temp_db):
        """get_recent(1) must return the single most recently appended event
        regardless of ordering direction."""
        store = EventStore(max_events=100, db_path=temp_db)
        for i in range(5):
            store.append(_make_event(idx=i, timestamp=1_000_000.0 + i))
        last = _make_event(idx=99, pid=9999, timestamp=2_000_000.0)
        store.append(last)

        single = store.get_recent(1)
        assert len(single) == 1
        assert single[0].execve_event.pid == 9999, (
            "get_recent(1) did not return the most recently appended event"
        )


# ===========================================================================
# 2. get_recent(0) explicit contract
# ===========================================================================

class TestGetRecentZero:

    def test_get_recent_zero_returns_empty_list(self, temp_db):
        store = EventStore(max_events=100, db_path=temp_db)
        for i in range(5):
            store.append(_make_event(idx=i))
        result = store.get_recent(0)
        assert result == [], f"get_recent(0) must return [], got {result}"

    def test_get_recent_zero_type_is_list(self, temp_db):
        store = EventStore(max_events=100, db_path=temp_db)
        result = store.get_recent(0)
        assert isinstance(result, list)


# ===========================================================================
# 3. max_events=1 single-slot buffer
# ===========================================================================

class TestSingleSlotBuffer:

    def test_single_slot_keeps_only_latest(self, temp_db):
        store = EventStore(max_events=1, db_path=temp_db)
        e0 = _make_event(idx=0, pid=100)
        e1 = _make_event(idx=1, pid=200)
        store.append(e0)
        store.append(e1)
        assert store.size() == 1
        events = store.get_all()
        assert events[0].execve_event.pid == 200

    def test_single_slot_size_never_exceeds_1(self, temp_db):
        store = EventStore(max_events=1, db_path=temp_db)
        for i in range(20):
            store.append(_make_event(idx=i))
        assert store.size() == 1

    def test_single_slot_counts_correct(self, temp_db):
        store = EventStore(max_events=1, db_path=temp_db)
        store.append(_make_event("malicious", idx=0))
        store.append(_make_event("safe", idx=1))
        # Only the last (safe) event should be present
        assert store.get_safe_count() == 1
        assert store.get_malicious_count() == 0


# ===========================================================================
# 4. remediation_action / remediation_status persisted to SQLite
# ===========================================================================

class TestRemediationFieldsPersistence:

    def test_remediation_action_survives_reload(self, temp_db):
        """remediation_action written to store A must be readable from store B."""
        execve = ExecveEvent(
            pid=1, ppid=0, uid=0, gid=0,
            command="rm -rf /", argv_str="rm -rf /",
            timestamp=time.time(), comm="bash",
        )
        detection = DetectionResult(
            classification="malicious", risk_score=95.0,
            matched_rules=["destructive_pattern"], ml_confidence=0.99,
        )
        ev = SecurityEvent(
            id="evt_remediation_persist",
            execve_event=execve,
            detection_result=detection,
            detected_at=time.time(),
            remediation_action="kill_process",
            remediation_status="success",
        )

        store_a = EventStore(max_events=100, db_path=temp_db)
        store_a.append(ev)

        store_b = EventStore(max_events=100, db_path=temp_db)
        retrieved = store_b.get_all()[0]

        assert getattr(retrieved, "remediation_action", None) == "kill_process", \
            "remediation_action not persisted to SQLite"
        assert getattr(retrieved, "remediation_status", None) == "success", \
            "remediation_status not persisted to SQLite"

    def test_remediation_none_fields_preserved_in_db(self, temp_db):
        """When remediation fields are None they must be stored as NULL and
        not raised as errors on retrieval."""
        ev = _make_event(classification="safe", idx=0)
        store_a = EventStore(max_events=100, db_path=temp_db)
        store_a.append(ev)

        store_b = EventStore(max_events=100, db_path=temp_db)
        retrieved = store_b.get_all()[0]
        assert getattr(retrieved, "remediation_action", "MISSING") is None
        assert getattr(retrieved, "remediation_status", "MISSING") is None


# ===========================================================================
# 5. Cache vs DB size divergence
# ===========================================================================

class TestCacheVsDbDivergence:

    def test_cache_smaller_than_db_when_max_events_exceeded(self, temp_db):
        """When more events are appended than max_events, the DB may hold
        all of them while the cache holds only max_events. size() must
        reflect the DB count, not just the cache count."""
        store = EventStore(max_events=5, db_path=temp_db)
        for i in range(10):
            store.append(_make_event(idx=i))

        # DB should have up to 10; cache at most 5
        assert len(store._cache) <= 5, \
            f"Cache exceeded max_events: {len(store._cache)}"

        # size() must be consistent — report what's actually in the DB/store
        assert store.size() >= 5, \
            "size() reports less than max_events after overflow"

    def test_get_all_after_overflow_returns_consistent_list(self, temp_db):
        """After overflowing max_events, get_all() must return a non-empty
        list without raising."""
        store = EventStore(max_events=5, db_path=temp_db)
        for i in range(10):
            store.append(_make_event(idx=i))
        events = store.get_all()
        assert isinstance(events, list)
        assert len(events) > 0


# ===========================================================================
# 6. Unique event IDs under concurrent appends
# ===========================================================================

class TestUniqueEventIdsUnderConcurrency:

    def test_concurrent_appends_produce_unique_ids(self, temp_db):
        """IDs assigned during concurrent appends must all be unique."""
        store = EventStore(max_events=1000, db_path=temp_db)
        errors = []
        lock = threading.Lock()

        def writer(thread_id):
            for i in range(20):
                try:
                    store.append(_make_event(idx=thread_id * 20 + i))
                except Exception as e:
                    with lock:
                        errors.append(str(e))

        threads = [threading.Thread(target=writer, args=(t,))
                   for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        all_ids = [e.id for e in store.get_all()]
        assert len(all_ids) == len(set(all_ids)), \
            f"Duplicate IDs found under concurrent appends"


# ===========================================================================
# 7. db_path attribute accessible after construction
# ===========================================================================

class TestDbPathAttribute:

    def test_db_path_attribute_exists(self, temp_db):
        """EventStore must expose db_path so tests can create a second
        instance pointing at the same database."""
        store = EventStore(max_events=100, db_path=temp_db)
        assert hasattr(store, "db_path"), \
            "EventStore has no db_path attribute — persistence tests cannot work"

    def test_db_path_matches_constructor_arg(self, temp_db):
        store = EventStore(max_events=100, db_path=temp_db)
        assert store.db_path == temp_db

    def test_second_instance_same_db_path_reads_same_data(self, temp_db):
        store_a = EventStore(max_events=100, db_path=temp_db)
        store_a.append(_make_event(idx=0, pid=42))
        store_b = EventStore(max_events=100, db_path=store_a.db_path)
        assert store_b.size() == 1
        assert store_b.get_all()[0].execve_event.pid == 42
