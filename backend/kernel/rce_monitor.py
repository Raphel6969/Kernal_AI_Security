"""
eBPF program interface and event monitoring.
Loads and manages the execve system call tracepoint hook.
"""

from typing import Callable, Optional
import threading
import time
from backend.events.models import ExecveEvent


class RCEMonitor:
    """
    Manages eBPF execve syscall monitoring.
    Loads the compiled eBPF program and polls the ring buffer for events.
    """

    def __init__(self, ebpf_program_path: str = None):
        """
        Initialize the RCE monitor.
        
        Args:
            ebpf_program_path: Path to compiled eBPF .o file
        """
        self.ebpf_program_path = ebpf_program_path
        self.bpf = None
        self.ring_buffer = None
        self.running = False
        self.thread = None
        self.event_callback: Optional[Callable] = None

    def start(self, event_callback: Callable = None) -> None:
        """
        Start monitoring execve syscalls.
        
        Args:
            event_callback: Optional async function to call on each event
                           Signature: async def callback(event: ExecveEvent)
        """
        if self.running:
            return
        
        print("🔧 Starting RCE Monitor...")
        
        # This is a stub for now - actual eBPF loading in Phase 2
        # For now, we'll create a mock monitoring setup
        self.event_callback = event_callback
        self.running = True
        
        # Start background thread for polling ring buffer
        self.thread = threading.Thread(target=self._poll_ring_buffer, daemon=True)
        self.thread.start()
        
        print("✅ RCE Monitor started")

    def stop(self) -> None:
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("✅ RCE Monitor stopped")

    def _poll_ring_buffer(self) -> None:
        """
        Poll ring buffer for events (runs in background thread).
        This will be connected to actual eBPF in Phase 2.
        """
        while self.running:
            try:
                # TODO: In Phase 2, replace with actual ring buffer polling
                # For now: mock implementation that does nothing
                time.sleep(0.1)
            except Exception as e:
                print(f"❌ Error polling ring buffer: {e}")
                time.sleep(1)

    def set_event_callback(self, callback: Callable) -> None:
        """
        Set or update the event callback.
        
        Args:
            callback: Function to call on each event
        """
        self.event_callback = callback


# Singleton instance
_rce_monitor = None


def get_rce_monitor(ebpf_path: str = None) -> RCEMonitor:
    """
    Get or create the RCE monitor singleton.
    
    Args:
        ebpf_path: Path to compiled eBPF program
        
    Returns:
        The global RCEMonitor instance
    """
    global _rce_monitor
    if _rce_monitor is None:
        _rce_monitor = RCEMonitor(ebpf_path)
    return _rce_monitor
