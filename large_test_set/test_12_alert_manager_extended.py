"""
test_12_alert_manager_extended.py — Extended tests for AlertManager.

Fills gaps in the original test_alert_manager.py:
- Suspicious events dispatch behaviour (documented)
- Failed webhook HTTP response recorded as 'failed'
- Webhook timeout/connection error handled gracefully
- Multiple webhooks all notified for one malicious event
- Alert history limit and ordering
- Alert history persists across new AlertManager instances (same db)
- Webhook dispatch does not block / no double-dispatch

Run:
    pytest large_test_set/test_12_alert_manager_extended.py -v
"""

import pytest
import asyncio
import os
import uuid
import time
from unittest.mock import patch, MagicMock, call
import requests as requests_lib

from backend.alerts.alert_manager import AlertManager
from backend.events.models import SecurityEvent, ExecveEvent, DetectionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db():
    return f".pytest_alert_{uuid.uuid4().hex[:10]}.db"


def _execve(command="ls", pid=1):
    return ExecveEvent(
        pid=pid, ppid=0, uid=1000, gid=1000,
        command=command, argv_str=command,
        timestamp=time.time(), comm="bash",
    )


def _detection(cls="safe", score=10.0, rules=None):
    return DetectionResult(
        classification=cls,
        risk_score=score,
        matched_rules=rules or [],
        ml_confidence=0.5,
        explanation="test",
    )


def _event(cls="safe", command="ls", score=10.0, ev_id=None):
    return SecurityEvent(
        id=ev_id or f"evt_{uuid.uuid4().hex[:8]}",
        execve_event=_execve(command=command),
        detection_result=_detection(cls=cls, score=score),
        detected_at=time.time(),
    )


@pytest.fixture
def am(tmp_path):
    """AlertManager with a unique tmp db, cleaned up after each test."""
    db = str(tmp_path / f"alerts_{uuid.uuid4().hex[:8]}.db")
    mgr = AlertManager(db_path=db)
    yield mgr


# ===========================================================================
# 1. Suspicious event dispatch behaviour
# ===========================================================================

class TestSuspiciousDispatch:

    @pytest.mark.asyncio
    async def test_suspicious_event_dispatch_behaviour_documented(self, am):
        """Document whether suspicious events trigger webhooks.
        The original tests only covered safe (ignored) and malicious (fired).
        This test pins the actual behaviour without assuming either outcome."""
        am.add_webhook("http://example.com/hook")
        ev = _event(cls="suspicious", score=50.0)

        with patch("backend.alerts.alert_manager.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            await am.dispatch(ev)
            # Record observed behaviour — either called or not, both are valid
            # depending on the threshold config.  What must NOT happen is a crash.
            suspicious_triggers_webhook = mock_post.called

        # If suspicious events DO trigger, history must reflect it
        history = am.get_alert_history()
        if suspicious_triggers_webhook:
            assert len(history) == 1, \
                "Webhook fired for suspicious but no history entry recorded"
        else:
            assert len(history) == 0, \
                "No webhook fired for suspicious but history entry appeared"

    @pytest.mark.asyncio
    async def test_suspicious_dispatch_does_not_crash(self, am):
        """Regardless of policy, dispatching a suspicious event must not raise."""
        am.add_webhook("http://example.com/hook")
        ev = _event(cls="suspicious", score=45.0)
        with patch("backend.alerts.alert_manager.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            try:
                await am.dispatch(ev)
            except Exception as e:
                pytest.fail(f"dispatch() raised on suspicious event: {e}")


# ===========================================================================
# 2. Failed webhook HTTP response
# ===========================================================================

class TestFailedWebhookResponse:

    @pytest.mark.asyncio
    async def test_non_200_webhook_recorded_as_failed(self, am):
        """A webhook that returns 500 must be recorded in history with
        status 'failed', not 'success'."""
        am.add_webhook("http://example.com/hook")
        ev = _event(cls="malicious", score=90.0)

        with patch("backend.alerts.alert_manager.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=500)
            await am.dispatch(ev)

        history = am.get_alert_history()
        assert len(history) == 1
        assert history[0].status == "failed", \
            f"Expected 'failed' for 500 response, got {history[0].status!r}"

    @pytest.mark.asyncio
    async def test_404_webhook_recorded_as_failed(self, am):
        am.add_webhook("http://example.com/hook")
        ev = _event(cls="malicious", score=90.0)

        with patch("backend.alerts.alert_manager.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=404)
            await am.dispatch(ev)

        history = am.get_alert_history()
        assert history[0].status == "failed"

    @pytest.mark.asyncio
    async def test_success_and_failed_both_appear_in_history(self, am):
        """One successful dispatch + one failed dispatch must both appear in history."""
        am.add_webhook("http://example.com/hook_ok")
        am.add_webhook("http://example.com/hook_fail")
        ev = _event(cls="malicious", score=90.0)

        def side_effect(url, *args, **kwargs):
            m = MagicMock()
            m.status_code = 200 if "hook_ok" in url else 500
            return m

        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=side_effect):
            await am.dispatch(ev)

        history = am.get_alert_history()
        statuses = {h.status for h in history}
        assert "success" in statuses, "No success entry in history"
        assert "failed" in statuses, "No failed entry in history"


# ===========================================================================
# 3. Webhook connection error / timeout handling
# ===========================================================================

class TestWebhookConnectionError:

    @pytest.mark.asyncio
    async def test_connection_error_does_not_raise(self, am):
        """A webhook that raises ConnectionError must not crash dispatch()."""
        am.add_webhook("http://127.0.0.1:19999/unreachable")
        ev = _event(cls="malicious", score=90.0)

        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=requests_lib.exceptions.ConnectionError("refused")):
            try:
                await am.dispatch(ev)
            except Exception as e:
                pytest.fail(f"dispatch() raised on ConnectionError: {e}")

    @pytest.mark.asyncio
    async def test_connection_error_recorded_as_failed(self, am):
        """A connection error must be recorded in alert history as 'failed'."""
        am.add_webhook("http://127.0.0.1:19999/unreachable")
        ev = _event(cls="malicious", score=90.0)

        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=requests_lib.exceptions.ConnectionError("refused")):
            await am.dispatch(ev)

        history = am.get_alert_history()
        assert len(history) == 1
        assert history[0].status == "failed"

    @pytest.mark.asyncio
    async def test_timeout_does_not_raise(self, am):
        """A webhook that raises Timeout must not crash dispatch()."""
        am.add_webhook("http://example.com/slow")
        ev = _event(cls="malicious", score=90.0)

        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=requests_lib.exceptions.Timeout("timed out")):
            try:
                await am.dispatch(ev)
            except Exception as e:
                pytest.fail(f"dispatch() raised on Timeout: {e}")

    @pytest.mark.asyncio
    async def test_timeout_recorded_as_failed(self, am):
        am.add_webhook("http://example.com/slow")
        ev = _event(cls="malicious", score=90.0)
        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=requests_lib.exceptions.Timeout("timed out")):
            await am.dispatch(ev)
        assert am.get_alert_history()[0].status == "failed"


# ===========================================================================
# 4. Multiple webhooks — all notified for one event
# ===========================================================================

class TestMultipleWebhooks:

    @pytest.mark.asyncio
    async def test_all_webhooks_called_for_malicious_event(self, am):
        """All registered webhooks must each be called exactly once per
        malicious event dispatch."""
        urls = [f"http://example.com/hook-{i}" for i in range(3)]
        for url in urls:
            am.add_webhook(url)

        ev = _event(cls="malicious", score=95.0)
        called_urls = []

        def side_effect(url, *args, **kwargs):
            called_urls.append(url)
            return MagicMock(status_code=200)

        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=side_effect):
            await am.dispatch(ev)

        for url in urls:
            assert url in called_urls, f"Webhook {url!r} was not called"

    @pytest.mark.asyncio
    async def test_each_webhook_called_exactly_once(self, am):
        """No webhook must be called more than once per dispatch."""
        urls = [f"http://example.com/hook-{i}" for i in range(3)]
        for url in urls:
            am.add_webhook(url)

        ev = _event(cls="malicious", score=95.0)
        call_counts = {url: 0 for url in urls}

        def side_effect(url, *args, **kwargs):
            call_counts[url] = call_counts.get(url, 0) + 1
            return MagicMock(status_code=200)

        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=side_effect):
            await am.dispatch(ev)

        for url, count in call_counts.items():
            assert count == 1, f"Webhook {url!r} called {count} times (expected 1)"

    @pytest.mark.asyncio
    async def test_partial_failure_does_not_skip_remaining_webhooks(self, am):
        """If the first webhook fails, remaining webhooks must still be called."""
        am.add_webhook("http://example.com/hook-fail")
        am.add_webhook("http://example.com/hook-ok")
        ev = _event(cls="malicious", score=95.0)
        called = []

        def side_effect(url, *args, **kwargs):
            called.append(url)
            if "fail" in url:
                return MagicMock(status_code=500)
            return MagicMock(status_code=200)

        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=side_effect):
            await am.dispatch(ev)

        assert "http://example.com/hook-ok" in called, \
            "Second webhook skipped after first webhook failed"

    @pytest.mark.asyncio
    async def test_history_has_entry_per_webhook(self, am):
        """With 3 webhooks, dispatching one malicious event must create
        3 history entries (one per webhook)."""
        for i in range(3):
            am.add_webhook(f"http://example.com/hook-{i}")
        ev = _event(cls="malicious", score=95.0)

        with patch("backend.alerts.alert_manager.requests.post",
                   return_value=MagicMock(status_code=200)):
            await am.dispatch(ev)

        history = am.get_alert_history()
        assert len(history) == 3, \
            f"Expected 3 history entries (one per webhook), got {len(history)}"


# ===========================================================================
# 5. Alert history limit and ordering
# ===========================================================================

class TestAlertHistoryLimitAndOrdering:

    @pytest.mark.asyncio
    async def test_alert_history_most_recent_first(self, am):
        """get_alert_history() must return the most recent alert first."""
        am.add_webhook("http://example.com/hook")
        for i in range(3):
            ev = _event(cls="malicious", score=90.0 + i,
                        ev_id=f"evt_order_{i}")
            with patch("backend.alerts.alert_manager.requests.post",
                       return_value=MagicMock(status_code=200)):
                await am.dispatch(ev)

        history = am.get_alert_history()
        assert len(history) == 3
        # Most recent should be first
        assert history[0].event_id == "evt_order_2", \
            f"Expected newest first, got {history[0].event_id!r}"

    @pytest.mark.asyncio
    async def test_alert_history_respects_limit_param(self, am):
        """get_alert_history(limit=2) must return at most 2 entries."""
        am.add_webhook("http://example.com/hook")
        for i in range(5):
            ev = _event(cls="malicious", score=90.0, ev_id=f"evt_lim_{i}")
            with patch("backend.alerts.alert_manager.requests.post",
                       return_value=MagicMock(status_code=200)):
                await am.dispatch(ev)

        history = am.get_alert_history(limit=2)
        assert len(history) <= 2

    @pytest.mark.asyncio
    async def test_safe_events_never_appear_in_history(self, am):
        """Safe events must never produce alert history entries."""
        am.add_webhook("http://example.com/hook")
        for i in range(5):
            ev = _event(cls="safe", score=5.0)
            with patch("backend.alerts.alert_manager.requests.post",
                       return_value=MagicMock(status_code=200)):
                await am.dispatch(ev)

        assert am.get_alert_history() == [], \
            "Safe events produced alert history entries"


# ===========================================================================
# 6. Alert history persistence across instances
# ===========================================================================

class TestAlertHistoryPersistence:

    @pytest.mark.asyncio
    async def test_history_survives_new_instance_same_db(self, tmp_path):
        """Dispatch a malicious event, then create a new AlertManager
        pointing at the same db — the history must still be there."""
        db = str(tmp_path / "persist_test.db")

        am_a = AlertManager(db_path=db)
        am_a.add_webhook("http://example.com/hook")
        ev = _event(cls="malicious", score=90.0, ev_id="evt_persist_1")

        with patch("backend.alerts.alert_manager.requests.post",
                   return_value=MagicMock(status_code=200)):
            await am_a.dispatch(ev)

        am_b = AlertManager(db_path=db)
        history = am_b.get_alert_history()
        assert len(history) >= 1, \
            "Alert history not persisted to SQLite"
        assert history[0].event_id == "evt_persist_1"

    @pytest.mark.asyncio
    async def test_history_status_preserved_across_instances(self, tmp_path):
        """The 'failed' status must survive a new AlertManager instance."""
        db = str(tmp_path / "status_persist.db")
        am_a = AlertManager(db_path=db)
        am_a.add_webhook("http://example.com/hook")
        ev = _event(cls="malicious", score=90.0)

        with patch("backend.alerts.alert_manager.requests.post",
                   return_value=MagicMock(status_code=500)):
            await am_a.dispatch(ev)

        am_b = AlertManager(db_path=db)
        history = am_b.get_alert_history()
        assert history[0].status == "failed", \
            "Alert status not preserved across AlertManager instances"


# ===========================================================================
# 7. No double-dispatch / idempotency
# ===========================================================================

class TestNoDoubleDispatch:

    @pytest.mark.asyncio
    async def test_same_event_dispatched_twice_calls_webhook_twice(self, am):
        """Dispatching the same event object twice must call the webhook
        twice — dispatch() has no deduplication by design."""
        am.add_webhook("http://example.com/hook")
        ev = _event(cls="malicious", score=90.0, ev_id="evt_double")
        call_count = []

        def side_effect(url, *a, **kw):
            call_count.append(1)
            return MagicMock(status_code=200)

        with patch("backend.alerts.alert_manager.requests.post",
                   side_effect=side_effect):
            await am.dispatch(ev)
            await am.dispatch(ev)

        assert len(call_count) == 2, \
            f"Expected 2 calls for 2 dispatches, got {len(call_count)}"

    @pytest.mark.asyncio
    async def test_dispatch_with_no_webhooks_does_not_crash(self, am):
        """Dispatching when no webhooks are registered must be a no-op,
        not raise AttributeError or similar."""
        ev = _event(cls="malicious", score=90.0)
        try:
            await am.dispatch(ev)
        except Exception as e:
            pytest.fail(f"dispatch() raised with no webhooks: {e}")
        assert am.get_alert_history() == []
