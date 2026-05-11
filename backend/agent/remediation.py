"""
Remediation Manager for Aegix.
Handles automatic process termination when malicious activity is detected.

NOTE: Auto-Remediation is only meaningful on Linux where the eBPF kernel hook
provides real PIDs of active processes. On Windows/macOS, the PID in events is
typically 0 (API-mode), so kill attempts are skipped gracefully.
"""

import os
import sys
import logging
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

# Global toggle - controlled via API endpoint
_remediation_enabled = False


def is_remediation_enabled() -> bool:
    return _remediation_enabled


def set_remediation_enabled(enabled: bool):
    global _remediation_enabled
    _remediation_enabled = enabled
    status = "ENABLED" if enabled else "DISABLED"
    logger.info(f"🛡️  Auto-Remediation {status}")
    print(f"🛡️  Auto-Remediation {status}")


def kill_process(pid: int) -> dict:
    """
    Attempt to terminate a process by PID.

    Returns a dict with:
        - action: "kill_process"
        - status: "success" | "already_dead" | "skipped_no_pid" |
                  "skipped_windows" | "permission_denied" | "failed" | "unavailable"
        - detail: human-readable message
    """
    result = {
        "action": "kill_process",
        "status": "failed",
        "detail": "",
    }

    # Nothing to kill if PID is 0 (API-mode events)
    if pid == 0:
        result["status"] = "skipped_no_pid"
        result["detail"] = "No real PID captured (API-mode event, not from kernel hook)"
        return result

    # Require psutil
    if not PSUTIL_AVAILABLE:
        result["status"] = "unavailable"
        result["detail"] = "psutil not installed. Run: pip install psutil"
        return result

    # On Windows, psutil can still kill processes but we surface a note
    is_linux = sys.platform.startswith("linux")

    try:
        process = psutil.Process(pid)

        # Check if it's actually running
        if not process.is_running():
            result["status"] = "already_dead"
            result["detail"] = f"Process {pid} was already terminated"
            return result

        proc_name = process.name()
        process.kill()  # SIGKILL on Linux/macOS, TerminateProcess on Windows

        # Confirm it's gone
        try:
            process.wait(timeout=2)
        except psutil.TimeoutExpired:
            pass

        if is_linux:
            result["status"] = "success"
            result["detail"] = f"Process '{proc_name}' (PID {pid}) killed via SIGKILL"
        else:
            result["status"] = "success"
            result["detail"] = f"Process '{proc_name}' (PID {pid}) terminated (non-Linux platform)"

        logger.warning(f"🛑 Remediation: {result['detail']}")
        print(f"🛑 {result['detail']}")

    except psutil.NoSuchProcess:
        result["status"] = "already_dead"
        result["detail"] = f"Process {pid} not found (already terminated)"

    except psutil.AccessDenied:
        result["status"] = "permission_denied"
        result["detail"] = f"Permission denied killing PID {pid}. Run backend as root/admin."
        logger.error(f"❌ {result['detail']}")

    except Exception as e:
        result["status"] = "failed"
        result["detail"] = f"Unexpected error killing PID {pid}: {e}"
        logger.error(f"❌ {result['detail']}")

    return result
