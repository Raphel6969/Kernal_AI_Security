"""
test_03_event_store.py — Unit tests for backend/events/event_store.py

Tests circular buffer eviction, classification counts, get_recent edge cases,
clear(), thread-safety, SQLite persistence, and ordering contract.

Run:
    pytest large_test_set/test_03_event_store.py -v
"""

import pytest
import threading
import time
import tempfile
import os
from backend.events.event_store import EventStore
from backend.events.models import ExecveEvent, DetectionResult, SecurityEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(classification="safe", idx=0):
    execve = ExecveEvent(
        pid=idx, ppid=0, uid=1000, gid=1000,
        command="ls", argv_str="ls",
        timestamp=time.time(), comm="bash",
    )
    result = DetectionResult(
        risk_score=5.0, classification=classification,
        matched_rules=[], ml_confidence=0.1,
    )
    return SecurityEvent(
        id=f"evt_{idx}",
        execve_event=execve,
        detection_result=result,
        detected_at=time.time(),
    )


@pytest.fixture
def temp_db():
    """Temporary SQLite file, cleaned up after each test."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        path = f.name
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


# ===========================================================================
# 1. Basic Append and Size
# ===========================================================================

def test_empty_store_has_size_zero():
    store = EventStore(max_events=100)
    assert store.size() == 0

def test_append_increases_size():
    store = EventStore(max_events=100)
    store.append(_make_event())
    assert store.size() == 1

def test_append_multiple_increases_size():
    store = EventStore(max_events=100)
    for i in range(10):
        store.append(_make_event(idx=i))
    assert store.size() == 10


# ===========================================================================
# 2. Circular Buffer (max_events cap)
# ===========================================================================

def test_circular_buffer_caps_at_max_events():
    store = EventStore(max_events=3)
    for i in range(5):
        store.append(_make_event(idx=i))
    assert store.size() == 3

def test_circular_buffer_evicts_oldest():
    store = EventStore(max_events=3)
    for i in range(5):
        store.append(_make_event(idx=i))
    ids = [e.id for e in store.get_all()]
    assert "evt_0" not in ids   # evicted
    assert "evt_1" not in ids   # evicted
    assert "evt_4" in ids       # newest kept

def test_circular_buffer_keeps_newest():
    store = EventStore(max_events=3)
    for i in range(5):
        store.append(_make_event(idx=i))
    ids = [e.id for e in store.get_all()]
    assert set(ids) == {"evt_2", "evt_3", "evt_4"}


# ===========================================================================
# 3. get_recent
# ===========================================================================

def test_get_recent_returns_correct_count():
    store = EventStore(max_events=100)
    for i in range(20):
        store.append(_make_event(idx=i))
    assert len(store.get_recent(5)) == 5

def test_get_recent_zero_returns_empty():
    store = EventStore(max_events=100)
    store.append(_make_event())
    assert store.get_recent(0) == []

def test_get_recent_more_than_stored():
    store = EventStore(max_events=100)
    store.append(_make_event())
    assert len(store.get_recent(1000)) == 1

def test_get_recent_returns_newest_last():
    """Events returned oldest→newest (ascending order)."""
    store = EventStore(max_events=100)
    for i in range(5):
        store.append(_make_event(idx=i))
    events = store.get_recent(5)
    ids = [e.id for e in events]
    assert ids == ["evt_0", "evt_1", "evt_2", "evt_3", "evt_4"]

def test_get_recent_negative_returns_empty():
    store = EventStore(max_events=100)
    store.append(_make_event())
    assert store.get_recent(-1) == []


# ===========================================================================
# 4. get_all
# ===========================================================================

def test_get_all_returns_all_events():
    store = EventStore(max_events=100)
    for i in range(7):
        store.append(_make_event(idx=i))
    assert len(store.get_all()) == 7

def test_get_all_empty_store():
    store = EventStore(max_events=100)
    assert store.get_all() == []


# ===========================================================================
# 5. Classification Counts
# ===========================================================================

def test_get_safe_count():
    store = EventStore(max_events=100)
    store.append(_make_event("safe"))
    store.append(_make_event("safe"))
    store.append(_make_event("malicious"))
    assert store.get_safe_count() == 2

def test_get_malicious_count():
    store = EventStore(max_events=100)
    store.append(_make_event("malicious"))
    store.append(_make_event("safe"))
    assert store.get_malicious_count() == 1

def test_get_suspicious_count():
    store = EventStore(max_events=100)
    store.append(_make_event("suspicious"))
    store.append(_make_event("suspicious"))
    store.append(_make_event("safe"))
    assert store.get_suspicious_count() == 2

def test_counts_sum_to_total():
    """safe + suspicious + malicious must equal size()."""
    store = EventStore(max_events=100)
    store.append(_make_event("safe"))
    store.append(_make_event("safe"))
    store.append(_make_event("suspicious"))
    store.append(_make_event("malicious"))
    store.append(_make_event("malicious"))
    total = store.size()
    counted = (
        store.get_safe_count() +
        store.get_suspicious_count() +
        store.get_malicious_count()
    )
    assert counted == total

def test_counts_zero_on_empty_store():
    store = EventStore(max_events=100)
    assert store.get_safe_count() == 0
    assert store.get_suspicious_count() == 0
    assert store.get_malicious_count() == 0


# ===========================================================================
# 6. get_by_classification
# ===========================================================================

def test_get_by_classification_safe():
    store = EventStore(max_events=100)
    store.append(_make_event("safe", idx=1))
    store.append(_make_event("malicious", idx=2))
    safe_events = store.get_by_classification("safe")
    assert len(safe_events) == 1
    assert safe_events[0].id == "evt_1"

def test_get_by_classification_unknown_returns_empty():
    store = EventStore(max_events=100)
    store.append(_make_event("safe"))
    result = store.get_by_classification("unknown_class")
    assert result == []


# ===========================================================================
# 7. Clear
# ===========================================================================

def test_clear_empties_store():
    store = EventStore(max_events=100)
    for i in range(5):
        store.append(_make_event(idx=i))
    store.clear()
    assert store.size() == 0

def test_clear_resets_counts():
    store = EventStore(max_events=100)
    store.append(_make_event("malicious"))
    store.clear()
    assert store.get_malicious_count() == 0

def test_append_after_clear():
    store = EventStore(max_events=100)
    store.append(_make_event(idx=0))
    store.clear()
    store.append(_make_event(idx=1))
    assert store.size() == 1
    assert store.get_all()[0].id == "evt_1"


# ===========================================================================
# 8. Thread Safety
# ===========================================================================

def test_concurrent_appends_no_data_corruption():
    """5 threads writing 100 events each → exactly 500 events, no errors."""
    store = EventStore(max_events=1000)
    errors = []

    def writer(thread_id):
        try:
            for i in range(100):
                store.append(_make_event(idx=thread_id * 100 + i))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Thread errors: {errors}"
    assert store.size() == 500

def test_concurrent_reads_and_writes():
    """Simultaneous reads and writes must not raise RuntimeError."""
    store = EventStore(max_events=200)
    errors = []

    def writer():
        try:
            for i in range(50):
                store.append(_make_event(idx=i))
                time.sleep(0.001)
        except Exception as e:
            errors.append(("write", e))

    def reader():
        try:
            for _ in range(50):
                store.get_recent(10)
                store.size()
                time.sleep(0.001)
        except Exception as e:
            errors.append(("read", e))

    threads = (
        [threading.Thread(target=writer) for _ in range(2)] +
        [threading.Thread(target=reader) for _ in range(2)]
    )
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrency errors: {errors}"

def test_max_events_respected_under_concurrent_load():
    """Even with 200 concurrent appends, size must not exceed max_events."""
    store = EventStore(max_events=50)
    barrier = threading.Barrier(10)

    def writer(thread_id):
        barrier.wait()  # all threads start simultaneously
        for i in range(20):
            store.append(_make_event(idx=thread_id * 20 + i))

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert store.size() <= 50


# ===========================================================================
# 9. Edge Cases Extended
# ===========================================================================

class TestEventStoreEdgeCasesExtended:

    def test_max_events_one_keeps_only_last(self):
        """A single-slot buffer must always hold only the most recent event."""
        store = EventStore(max_events=1)
        store.append(_make_event(idx=0))
        store.append(_make_event(idx=1))
        assert store.size() == 1
        assert store.get_all()[0].id == "evt_1"

    def test_get_all_returns_oldest_to_newest(self):
        """get_all() must preserve insertion order (oldest → newest)."""
        store = EventStore(max_events=100)
        for i in range(5):
            store.append(_make_event(idx=i))
        ids = [e.id for e in store.get_all()]
        assert ids == ["evt_0", "evt_1", "evt_2", "evt_3", "evt_4"]

    def test_get_recent_ordering_after_buffer_wrap(self):
        """After the circular buffer wraps, ordering must stay oldest→newest."""
        store = EventStore(max_events=3)
        for i in range(6):
            store.append(_make_event(idx=i))
        ids = [e.id for e in store.get_recent(3)]
        assert ids == ["evt_3", "evt_4", "evt_5"]

    def test_get_by_classification_after_buffer_eviction(self):
        """Counts must reflect only events still inside the buffer."""
        store = EventStore(max_events=3)
        store.append(_make_event("malicious", idx=0))
        store.append(_make_event("malicious", idx=1))
        store.append(_make_event("safe", idx=2))
        store.append(_make_event("safe", idx=3))
        store.append(_make_event("safe", idx=4))
        # evt_0 and evt_1 (malicious) are evicted; only 3 safe remain
        assert store.get_malicious_count() == 0
        assert store.get_safe_count() == 3

    def test_get_by_classification_on_empty_store(self):
        store = EventStore(max_events=100)
        assert store.get_by_classification("safe") == []
        assert store.get_by_classification("malicious") == []
        assert store.get_by_classification("suspicious") == []

    def test_concurrent_clear_and_append_no_crash(self):
        """clear() racing with append() must not corrupt state or raise."""
        store = EventStore(max_events=200)
        errors = []

        def appender():
            try:
                for i in range(100):
                    store.append(_make_event(idx=i))
            except Exception as e:
                errors.append(("append", e))

        def clearer():
            try:
                for _ in range(5):
                    store.clear()
                    time.sleep(0.005)
            except Exception as e:
                errors.append(("clear", e))

        threads = [
            threading.Thread(target=appender),
            threading.Thread(target=clearer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors during concurrent clear/append: {errors}"
        assert store.size() <= 200


# ===========================================================================
# 10. SQLite Persistence  [NEW]
# test_03 previously only exercised in-memory behavior. These tests verify
# the SQLite layer: events survive a new EventStore instance on the same
# db_path, and field values are faithfully reconstructed from the database.
# ===========================================================================

class TestSQLitePersistence:

    def test_event_survives_new_store_instance(self, temp_db):
        """An event appended to store A must be readable from store B
        pointing at the same db_path."""
        store_a = EventStore(max_events=100, db_path=temp_db)
        store_a.append(_make_event(classification="malicious", idx=42))

        store_b = EventStore(max_events=100, db_path=temp_db)
        assert store_b.size() == 1

    def test_classification_persisted_correctly(self, temp_db):
        store_a = EventStore(max_events=100, db_path=temp_db)
        store_a.append(_make_event(classification="malicious", idx=1))

        store_b = EventStore(max_events=100, db_path=temp_db)
        event = store_b.get_all()[0]
        assert event.detection_result.classification == "malicious"

    def test_pid_persisted_correctly(self, temp_db):
        store_a = EventStore(max_events=100, db_path=temp_db)
        store_a.append(_make_event(idx=7777))

        store_b = EventStore(max_events=100, db_path=temp_db)
        event = store_b.get_all()[0]
        assert event.execve_event.pid == 7777

    def test_multiple_events_all_persisted(self, temp_db):
        store_a = EventStore(max_events=100, db_path=temp_db)
        for i in range(5):
            store_a.append(_make_event(idx=i))

        store_b = EventStore(max_events=100, db_path=temp_db)
        assert store_b.size() == 5

    def test_clear_also_clears_database(self, temp_db):
        """clear() must remove rows from SQLite, not just the in-memory cache."""
        store_a = EventStore(max_events=100, db_path=temp_db)
        for i in range(3):
            store_a.append(_make_event(idx=i))
        store_a.clear()

        store_b = EventStore(max_events=100, db_path=temp_db)
        assert store_b.size() == 0, \
            "clear() did not remove events from the SQLite database"

    def test_counts_correct_after_reload(self, temp_db):
        """Classification counts must be correct on a freshly loaded store."""
        store_a = EventStore(max_events=100, db_path=temp_db)
        store_a.append(_make_event("safe", idx=0))
        store_a.append(_make_event("malicious", idx=1))
        store_a.append(_make_event("suspicious", idx=2))

        store_b = EventStore(max_events=100, db_path=temp_db)
        assert store_b.get_safe_count() == 1
        assert store_b.get_malicious_count() == 1
        assert store_b.get_suspicious_count() == 1


# ===========================================================================
# 11. size() vs get_all() / get_recent() Consistency Invariant  [NEW]
# Documents and enforces that size() == len(get_all()) == len(get_recent(size()))
# at all times — critical for the WebSocket history replay limit.
# ===========================================================================

class TestSizeConsistencyInvariant:

    def test_size_equals_len_get_all(self):
        store = EventStore(max_events=100)
        for i in range(15):
            store.append(_make_event(idx=i))
        assert store.size() == len(store.get_all())

    def test_size_equals_len_get_recent_of_size(self):
        store = EventStore(max_events=100)
        for i in range(15):
            store.append(_make_event(idx=i))
        s = store.size()
        assert len(store.get_recent(s)) == s

    def test_size_consistent_after_buffer_wrap(self):
        """After the circular buffer evicts entries, size() must still
        equal len(get_all())."""
        store = EventStore(max_events=5)
        for i in range(10):
            store.append(_make_event(idx=i))
        assert store.size() == len(store.get_all())
        assert store.size() == 5

    def test_size_and_get_all_agree_under_concurrent_writes(self):
        """Under concurrent writes, size() must never exceed max_events and
        must agree with the length of get_all()."""
        store = EventStore(max_events=50)
        errors = []
        lock = threading.Lock()

        def writer(t_id):
            for i in range(20):
                try:
                    store.append(_make_event(idx=t_id * 20 + i))
                except Exception as e:
                    with lock:
                        errors.append(str(e))

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors during concurrent writes: {errors}"
        assert store.size() <= 50
        # size() and get_all() must agree after all writes settle
        assert store.size() == len(store.get_all())


# ===========================================================================
# 12. get_recent() Ordering Contract Verification  [NEW]
# Explicitly pins that get_recent() returns events in ascending (oldest→newest)
# order, consistent with how the WebSocket sends history to new clients.
# ===========================================================================

class TestGetRecentOrderingContract:

    def test_get_recent_is_ascending_order(self):
        """get_recent(n) must return events oldest-first (ascending by insertion)."""
        store = EventStore(max_events=100)
        for i in range(10):
            store.append(_make_event(idx=i))
        events = store.get_recent(10)
        ids = [e.id for e in events]
        assert ids == [f"evt_{i}" for i in range(10)], \
            f"get_recent() not ascending: {ids}"

    def test_get_recent_subset_is_newest_n_ascending(self):
        """get_recent(3) when 10 events exist must return the 3 newest
        in ascending order (evt_7, evt_8, evt_9 — not reversed)."""
        store = EventStore(max_events=100)
        for i in range(10):
            store.append(_make_event(idx=i))
        events = store.get_recent(3)
        ids = [e.id for e in events]
        assert ids == ["evt_7", "evt_8", "evt_9"], \
            f"get_recent(3) returned wrong slice or wrong order: {ids}"

    def test_get_recent_consistent_with_get_all_ordering(self):
        """The last n elements of get_all() must match get_recent(n)."""
        store = EventStore(max_events=100)
        for i in range(8):
            store.append(_make_event(idx=i))
        n = 4
        all_events   = store.get_all()
        recent_events = store.get_recent(n)
        assert [e.id for e in all_events[-n:]] == [e.id for e in recent_events], \
            "get_recent(n) is inconsistent with get_all()[-n:]"