#!/usr/bin/env python3
"""Integration test helper: local EventStore append/read test.

This is the same test as the root helper but placed under `tests/integration/`.
Run with pytest or directly with Python for quick checks.
"""
from __future__ import annotations

import logging
import sys
import time
import uuid
from datetime import datetime

sys.path.insert(0, "./")

LOG = logging.getLogger("test_local_store")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def build_test_event() -> object:
    from backend.events.models import ExecveEvent, DetectionResult, SecurityEvent

    execve = ExecveEvent(
        pid=12345,
        ppid=1,
        uid=1000,
        gid=1000,
        command="/bin/echo test_local_store",
        argv_str="/bin/echo test_local_store",
        timestamp=time.time(),
        comm="python",
        process_memory_mb=1.0,
        system_memory_percent=0.1,
        agent_id="local-test",
    )
    det = DetectionResult(
        risk_score=0.0,
        classification="safe",
        matched_rules=[],
        ml_confidence=0.0,
        explanation="local append test",
    )
    evt = SecurityEvent(
        id=f"evt_{uuid.uuid4().hex[:8]}",
        execve_event=execve,
        detection_result=det,
        detected_at=datetime.now().timestamp(),
    )
    return evt


def run_test() -> int:
    try:
        from backend.events.event_store import get_event_store
    except Exception as e:
        LOG.exception("Failed to import event_store: %s", e)
        return 2

    try:
        store = get_event_store()
        LOG.info("Store type: %s", type(store).__name__)
    except Exception as e:
        LOG.exception("Failed to get event store: %s", e)
        return 3

    try:
        before = store.size()
        LOG.info("Size before append: %s", before)
    except Exception:
        LOG.exception("Error reading size before append")

    evt = build_test_event()
    try:
        store.append(evt)
        LOG.info("Append succeeded (id=%s)", getattr(evt, "id", "-"))
    except Exception:
        LOG.exception("Append failed")
        return 4

    try:
        after = store.size()
        LOG.info("Size after append: %s", after)
    except Exception:
        LOG.exception("Error reading size after append")
        return 5

    print({
        "store": type(store).__name__,
        "size_before": before if "before" in locals() else None,
        "size_after": after,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(run_test())
