"""
test_03_event_store.py — Unit tests for backend/events/event_store.py

Tests circular buffer eviction, classification counts, get_recent edge cases,
clear(), and thread-safety under concurrent writes.

Run:
    pytest large_test_set/test_03_event_store.py -v
"""

import pytest
import threading
import time
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
    # Anything <= 0 should return empty list without crashing
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
