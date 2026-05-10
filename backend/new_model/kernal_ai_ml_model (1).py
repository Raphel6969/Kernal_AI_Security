"""
Kernal AI Security — ML Model (Replicated from repo architecture)
=================================================================
Mirrors the two-tier detection pipeline described in Raphel6969/Kernal_AI_Security:
  Tier A — Rule Engine       (60% weight): pattern matching, keyword scoring, entropy
  Tier B — ML Scorer         (40% weight): TF-IDF + Logistic Regression

Usage:
    python3 kernal_ai_ml_model.py --train-safe safe_commands.txt \
                                  --train-mal  malicious_commands.txt \
                                  --test       commands_to_test.txt \
                                  --output     results.json
"""

import re
import math
import json
import time
import argparse
from collections import defaultdict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np


# ─────────────────────────────────────────────────────────────────────────────
# TIER A — RULE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS = {
    "reverse_shell":  [
        r"/dev/tcp/",
        r"bash\s*-i",
        r"nc\s+-e\s*/bin",
        r"ncat\s+.*-e",
    ],
    "pipe_to_shell":  [r"\|\s*bash", r"\|\s*sh\b", r"\|\s*zsh"],
    "obfuscated_b64": [r"base64\s+-d", r"base64\s+--decode", r"\{echo,"],
    "destructive":    [
        r"rm\s+-rf\s+/\s+--no-preserve",
        r"dd\s+if=/dev/zero",
        r"mkfs\.",
    ],
    "priv_esc":       [r"chmod\s+4[0-9]{3}\s+/bin/", r"NOPASSWD:ALL"],
    "data_exfil":     [
        r"cat\s+/etc/shadow",
        r"find.*id_rsa.*xargs\s+cat",
        r"\|\s*nc\s+\d+\.\d+\.\d+\.\d+",
    ],
    "fork_bomb":      [r":\(\)\s*\{", r":\|\:&"],
    "log_wipe":       [r"shred.*\s+/var/log", r"truncate\s+-s\s+0\s+/var/log/"],
    "download_exec":  [r"wget.*-O\s+/tmp.*&&.*chmod.*&&", r"curl.*\|\s*bash"],
    "ssh_inject":     [r"authorized_keys"],
    "web_shell":      [r"php.*system\(\$", r"php.*passthru\(\$"],
}

KEYWORD_SCORES = {
    "eval": 15, "exec": 10, "base64": 20, "nc ": 15,
    "/tmp/": 5,  "pty.spawn": 30, "socket.connect": 25, "os.dup2": 25,
}


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def rule_engine_score(command: str):
    """
    Tier A: pattern matching + keyword scoring + entropy.
    Returns (score 0-100, list of matched rule names).
    """
    score, matched = 0, []
    cmd_lower = command.lower()

    for rule_name, patterns in PATTERNS.items():
        for pat in patterns:
            if re.search(pat, command, re.IGNORECASE):
                score += 40
                matched.append(rule_name)
                break

    for kw, pts in KEYWORD_SCORES.items():
        if kw in cmd_lower:
            score += pts

    ent = shannon_entropy(command)
    if ent > 4.5:
        score += 20
    elif ent > 3.8:
        score += 10

    return min(score, 100), list(set(matched))


# ─────────────────────────────────────────────────────────────────────────────
# TIER B — ML SCORER  (TF-IDF + Logistic Regression)
# ─────────────────────────────────────────────────────────────────────────────

def build_ml_pipeline() -> Pipeline:
    """
    Replicates the repo's ML scorer:
      - TF-IDF vectoriser (word-level, bigrams, 5000 features, sublinear TF)
      - Logistic Regression classifier
    """
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="word",
            token_pattern=r"[^\s]+",   # tokenise on whitespace
            ngram_range=(1, 2),
            max_features=5000,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            C=1.0,
            solver="lbfgs",
        )),
    ])


def train_model(safe_path: str, malicious_path: str) -> Pipeline:
    """Load labelled data and fit the ML pipeline."""
    def load(path, label):
        with open(path) as f:
            return [(l.strip(), label) for l in f if l.strip()]

    data = load(malicious_path, "malicious") + load(safe_path, "safe")
    X = [d[0] for d in data]
    y = [d[1] for d in data]

    pipeline = build_ml_pipeline()
    pipeline.fit(X, y)
    print(f"✅ Model trained on {len(X)} samples  |  classes: {list(pipeline.classes_)}")
    return pipeline


# ─────────────────────────────────────────────────────────────────────────────
# COMBINED ANALYSER  (Tier A 60% + Tier B 40%)
# ─────────────────────────────────────────────────────────────────────────────

# Thresholds (mirrors repo architecture)
THRESHOLD_MALICIOUS  = 60   # combined score ≥ 60  → malicious
THRESHOLD_SUSPICIOUS = 25   # combined score ≥ 25  → suspicious
                             # else                 → safe

WEIGHT_RULES = 0.6
WEIGHT_ML    = 0.4


def analyze_command(command: str, ml_pipeline: Pipeline) -> dict:
    """
    Run a single command through both tiers and return a result dict.
    """
    # Tier A
    rule_score, matched_rules = rule_engine_score(command)

    # Tier B
    classes   = list(ml_pipeline.classes_)
    probs     = ml_pipeline.predict_proba([command])[0]
    prob_dict = dict(zip(classes, probs))
    ml_mal    = prob_dict.get("malicious", 0.0)
    ml_safe   = prob_dict.get("safe", 1.0)
    ml_score  = ml_mal * 100

    # Combined weighted score
    combined = (rule_score * WEIGHT_RULES) + (ml_score * WEIGHT_ML)

    if combined >= THRESHOLD_MALICIOUS:
        classification = "malicious"
    elif combined >= THRESHOLD_SUSPICIOUS:
        classification = "suspicious"
    else:
        classification = "safe"

    return {
        "command":                  command,
        "classification":           classification,
        "risk_score":               round(combined, 2),
        "rule_score":               round(rule_score, 2),
        "ml_score":                 round(ml_score, 2),
        "ml_confidence_malicious":  round(ml_mal, 4),
        "ml_confidence_safe":       round(ml_safe, 4),
        "matched_rules":            matched_rules,
        "entropy":                  round(shannon_entropy(command), 4),
    }


def analyze_batch(commands: list, ml_pipeline: Pipeline) -> list:
    """Analyse a list of commands and return results."""
    return [analyze_command(cmd, ml_pipeline) for cmd in commands]


# ─────────────────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def print_report(results: list, true_label: str = None):
    """Print a summary report. If true_label given, show detection metrics."""
    total       = len(results)
    risk_scores = [r["risk_score"] for r in results]
    counts      = defaultdict(int)
    for r in results:
        counts[r["classification"]] += 1

    print(f"\n{'='*58}")
    print(f"  RESULTS  ({total} commands)")
    print(f"{'='*58}")
    for cls in ["malicious", "suspicious", "safe"]:
        pct = counts[cls] / total * 100
        print(f"  {cls:<12} : {counts[cls]:>6}  ({pct:.1f}%)")
    print(f"  {'─'*46}")
    print(f"  Avg risk score : {np.mean(risk_scores):.2f}")
    print(f"  Max risk score : {np.max(risk_scores):.2f}")
    print(f"  Min risk score : {np.min(risk_scores):.2f}")
    print(f"  Std deviation  : {np.std(risk_scores):.2f}")

    if true_label:
        correct = counts[true_label]
        print(f"  {'─'*46}")
        print(f"  Detection rate : {correct/total*100:.1f}%  ({correct}/{total} correctly → {true_label})")

    # Rule breakdown
    all_rules = []
    for r in results:
        all_rules.extend(r["matched_rules"])
    rule_counts = defaultdict(int)
    for rule in all_rules:
        rule_counts[rule] += 1
    if rule_counts:
        print(f"\n  Rule match breakdown:")
        for rule, cnt in sorted(rule_counts.items(), key=lambda x: -x[1]):
            print(f"    {rule:<22} {cnt:>5}  ({cnt/total*100:.1f}%)")

    # Distribution
    buckets = defaultdict(int)
    for s in risk_scores:
        b = int(s // 10) * 10
        buckets[b] += 1
    print(f"\n  Risk score distribution:")
    for b in sorted(buckets):
        bar = "█" * (buckets[b] // max(1, total // 200))
        print(f"    {b:>3}-{b+9:<3}  {buckets[b]:>5}  {bar}")
    print(f"{'='*58}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Kernal AI Security — ML Model")
    parser.add_argument("--train-safe",  required=True, help="Path to safe commands training file")
    parser.add_argument("--train-mal",   required=True, help="Path to malicious commands training file")
    parser.add_argument("--test",        required=True, help="Path to commands to test")
    parser.add_argument("--true-label",  default=None,  help="Ground truth label (safe/malicious/suspicious)")
    parser.add_argument("--output",      default="results.json", help="Output JSON path")
    args = parser.parse_args()

    # Train
    ml_pipeline = train_model(args.train_safe, args.train_mal)

    # Load test commands
    with open(args.test) as f:
        commands = [l.strip() for l in f if l.strip()]
    print(f"🔍 Loaded {len(commands)} commands from {args.test}")

    # Analyse
    t0 = time.time()
    results = analyze_batch(commands, ml_pipeline)
    elapsed = time.time() - t0
    print(f"🚀 Analysed {len(results)} commands in {elapsed:.2f}s  ({elapsed/len(results)*1000:.2f}ms/cmd)")

    # Report
    print_report(results, true_label=args.true_label)

    # Save
    summary_counts = defaultdict(int)
    for r in results:
        summary_counts[r["classification"]] += 1
    risk_scores = [r["risk_score"] for r in results]

    output = {
        "summary": {
            "total":            len(results),
            "malicious":        summary_counts["malicious"],
            "suspicious":       summary_counts["suspicious"],
            "safe":             summary_counts["safe"],
            "avg_risk_score":   round(float(np.mean(risk_scores)), 2),
            "max_risk_score":   round(float(np.max(risk_scores)), 2),
            "min_risk_score":   round(float(np.min(risk_scores)), 2),
            "std_risk_score":   round(float(np.std(risk_scores)), 2),
            "elapsed_seconds":  round(elapsed, 2),
            "ms_per_command":   round(elapsed / len(results) * 1000, 3),
        },
        "all_results": results,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n💾 Results saved → {args.output}")


if __name__ == "__main__":
    main()
