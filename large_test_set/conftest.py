"""
conftest.py — pytest configuration for large_test_set.

Resets all backend singletons before each test so state from one test
does not bleed into the next. Run from the project root:

    pytest large_test_set/ -v
"""

import sys
import os
import tempfile
import uuid
import shutil
from pathlib import Path
import pytest

# Make the project root importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Centralized test database directory
# ---------------------------------------------------------------------------

TEST_DB_DIR = Path(PROJECT_ROOT) / ".pytest-db"


@pytest.fixture(scope="session", autouse=True)
def setup_test_db_dir():
    """Create the shared test DB directory once per session and clean up
    everything inside it after all tests complete."""
    TEST_DB_DIR.mkdir(exist_ok=True)
    yield
    if TEST_DB_DIR.exists():
        shutil.rmtree(TEST_DB_DIR, ignore_errors=True)


# ---------------------------------------------------------------------------
# Per-test temporary SQLite database fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_db():
    """Provide a unique temporary SQLite database path for tests that need
    SQLite persistence without sharing state with other tests."""
    db_path = TEST_DB_DIR / f"test_{uuid.uuid4().hex[:12]}.db"
    yield str(db_path)
    try:
        db_path.unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Per-test isolated EventStore fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_event_store(temp_db, monkeypatch):
    """Provide an isolated EventStore backed by a fresh temp DB.
    Also patches the global _event_store singleton so any code that
    calls get_event_store() during the test gets this instance."""
    from backend.events.event_store import EventStore
    store = EventStore(max_events=100, db_path=temp_db)
    monkeypatch.setattr("backend.events.event_store._event_store", store)
    return store


# ---------------------------------------------------------------------------
# Per-test singleton reset  [ENHANCED]
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_singletons(monkeypatch):
    """
    Reset every module-level singleton before each test.

    This prevents state leaking between tests (e.g. event store counts,
    cached pipeline instances, ML scorer, active WebSocket connections,
    alert manager webhook registrations).

    Changes vs original:
    - active_websockets set in backend.app is now cleared to prevent
      stale WebSocket handles accumulating across tests.
    - backend.alerts.alert_manager._alert_manager is now reset so webhook
      registrations from one test never appear in the next.
    """
    import backend.detection.rule_engine as re_mod
    import backend.detection.ml_scorer as ml_mod
    import backend.detection.pipeline as pipe_mod
    import backend.events.event_store as es_mod
    import backend.kernel.execve_hook as hook_mod
    import backend.kernel.rce_monitor as rce_mod

    # ── pre-test reset ──────────────────────────────────────────────────────
    re_mod._rule_engine = None
    ml_mod._ml_scorer = None
    pipe_mod._detection_pipeline = None
    es_mod._event_store = None
    hook_mod._hook_manager = None
    rce_mod._rce_monitor = None

    # Clear active WebSocket connections so dead handles don't accumulate
    try:
        import backend.app as app_mod
        if hasattr(app_mod, "active_websockets"):
            app_mod.active_websockets.clear()
    except Exception:
        pass

    # Reset alert_manager singleton so registered webhooks don't persist
    try:
        import backend.alerts.alert_manager as am_mod
        if hasattr(am_mod, "_alert_manager"):
            am_mod._alert_manager = None
    except Exception:
        pass

    yield  # ── run the test ─────────────────────────────────────────────────

    # ── post-test teardown ──────────────────────────────────────────────────
    re_mod._rule_engine = None
    ml_mod._ml_scorer = None
    pipe_mod._detection_pipeline = None
    es_mod._event_store = None
    hook_mod._hook_manager = None
    rce_mod._rce_monitor = None

    try:
        import backend.app as app_mod
        if hasattr(app_mod, "active_websockets"):
            app_mod.active_websockets.clear()
    except Exception:
        pass

    try:
        import backend.alerts.alert_manager as am_mod
        if hasattr(am_mod, "_alert_manager"):
            am_mod._alert_manager = None
    except Exception:
        pass