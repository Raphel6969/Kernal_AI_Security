"""
High-level interface for execve syscall monitoring.
"""

from typing import List
from backend.kernel.rce_monitor import get_rce_monitor, RCEMonitor


class ExecuteHookManager:
    """
    High-level interface for managing execve hooks.
    Wraps the RCEMonitor for easier use.
    """

    def __init__(self):
        """Initialize the hook manager."""
        self.monitor = get_rce_monitor()

    def start(self, event_callback=None):
        """
        Start monitoring execve syscalls.
        
        Args:
            event_callback: Optional callback for each event
        """
        self.monitor.start(event_callback)

    def stop(self):
        """Stop monitoring."""
        self.monitor.stop()

    def set_callback(self, callback):
        """
        Set the event callback.
        
        Args:
            callback: Function(event) to call on each event
        """
        self.monitor.set_event_callback(callback)


# Singleton instance
_hook_manager = None


def get_hook_manager() -> ExecuteHookManager:
    """Get or create the hook manager singleton."""
    global _hook_manager
    if _hook_manager is None:
        _hook_manager = ExecuteHookManager()
    return _hook_manager
