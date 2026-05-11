"""
eBPF program interface and event monitoring.
Loads and manages the execve system call tracepoint hook.
"""

from typing import Callable, Optional
import threading
import time
import os
import struct
import platform
from ctypes import c_uint, c_int
from backend.events.models import ExecveEvent
import logging

logger = logging.getLogger(__name__)

# Try to import BCC (only available on Linux)
try:
    from bcc import BPF, lib
    HAS_BCC = True
except ImportError:
    HAS_BCC = False


class RCEMonitor:
    """
    Manages eBPF execve syscall monitoring.
    Loads the compiled eBPF program and polls the ring buffer for events.
    
    Requires:
    - Linux kernel 5.4+ with CONFIG_HAVE_SYSCALL_TRACEPOINTS
    - BCC (eBPF Compiler Collection) installed
    - Root/CAP_BPF privileges
    """

    def __init__(self, ebpf_program_path: str = None):
        """
        Initialize the RCE monitor.
        
        Args:
            ebpf_program_path: Path to compiled eBPF .o file (optional)
                              If None, will compile from C source inline
        """
        if not HAS_BCC:
            logger.warning("BCC not available - eBPF monitoring will be disabled")
            logger.info("Install: pip install bcc (requires Linux + kernel headers)")
        
        self.ebpf_program_path = ebpf_program_path
        self.bpf = None
        self.ring_buffer = None
        self.running = False
        self.thread = None
        self.event_callback: Optional[Callable] = None
        self.system = platform.system()

    def start(self, event_callback: Callable = None) -> None:
        """
        Start monitoring execve syscalls.
        
        Args:
            event_callback: Optional async function to call on each event
                           Signature: async def callback(event: ExecveEvent)
        """
        if self.running:
            return
        
        logger.info("Starting RCE Monitor")
        
        # Check platform
        if self.system != "Linux":
            logger.warning(f"eBPF monitoring requires Linux (running on {self.system})")
            logger.info("API and Dashboard will still work without kernel monitoring")
            self.event_callback = event_callback
            return
        
        # Check BCC availability
        if not HAS_BCC:
            logger.error("BCC not installed - cannot load eBPF program")
            logger.info("Install: sudo apt install python3-bcc")
            return
        
        # Set callback
        self.event_callback = event_callback
        self.running = True
        
        # Load eBPF program
        try:
            self._load_ebpf_program()
            
            # Start background thread for polling ring buffer
            self.thread = threading.Thread(target=self._poll_ring_buffer, daemon=True)
            self.thread.start()
            
            logger.info("RCE Monitor started - monitoring execve syscalls")
        except Exception:
            logger.exception("Failed to start RCE Monitor")
            self.running = False
            self.bpf = None

    def stop(self) -> None:
        """Stop monitoring."""
        if not self.running:
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        
        if self.bpf:
            self.bpf.cleanup()
            self.bpf = None
        
        logger.info("RCE Monitor stopped")

    def _load_ebpf_program(self) -> None:
        """
        Load the eBPF program using BCC.
        Uses inline C source for maximum compatibility.
        """
        if not HAS_BCC:
            raise RuntimeError("BCC not available")
        
        # eBPF program source (same as kernel/execve_hook.c)
        ebpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Ring Buffer map for event streaming
BPF_RINGBUF_OUTPUT(events, 256);

// Event structure
struct execve_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u64 timestamp;
    char comm[16];
    char argv[4096];
};

// Hook into sys_enter_execve tracepoint
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    struct execve_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    u32 pid_tgid = bpf_get_current_pid_tgid();
    u32 uid_gid = bpf_get_current_uid_gid();
    
    event->pid = pid_tgid & 0xFFFFFFFF;
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    
    struct task_struct *parent_task = NULL;
    bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &task->real_parent);
    
    u32 ppid = 0;
    if (parent_task) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent_task->tgid);
    }
    event->ppid = ppid;
    
    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), &task->comm);
    event->timestamp = bpf_ktime_get_ns();
    
    const char *filename = args->filename;
    if (filename) {
        bpf_probe_read_user_str(&event->argv, sizeof(event->argv), filename);
    } else {
        bpf_probe_read_kernel_str(&event->argv, sizeof(event->argv), &task->comm);
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}
"""
        
        logger.info("Loading eBPF program...")
        try:
            self.bpf = BPF(text=ebpf_source)
            logger.info("eBPF program loaded")
        except Exception as e:
            raise RuntimeError(f"Failed to load eBPF program: {e}")
        
        # Get ring buffer reference
        try:
            self.ring_buffer = self.bpf["events"]
            logger.info("Ring buffer initialized")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize ring buffer: {e}")

    def _poll_ring_buffer(self) -> None:
        """
        Poll ring buffer for events (runs in background thread).
        Converts kernel events to ExecveEvent objects and calls callback.
        """
        if not self.bpf or not self.ring_buffer:
            return
        
        logger.info("Ring buffer polling started")
        
        def handle_ring_buffer_event(ctx, data, size):
            """Callback when eBPF ringbuf has data."""
            try:
                # Parse event from ring buffer
                if size < 4128:  # sizeof(execve_event)
                    return
                
                # Extract fields from binary data (must match struct layout)
                import struct
                
                # Unpack: pid, ppid, uid, gid, timestamp (u32, u32, u32, u32, u64)
                pid, ppid, uid, gid, timestamp = struct.unpack_from(
                    '<IIIIQ', data, 0
                )
                
                # Extract comm (16 bytes at offset 20)
                comm_bytes = data[20:36]
                comm = comm_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
                
                # Extract argv (4096 bytes at offset 36)
                argv_bytes = data[36:4132]
                argv = argv_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
                
                # Create ExecveEvent
                event = ExecveEvent(
                    pid=pid,
                    ppid=ppid,
                    uid=uid,
                    gid=gid,
                    command=argv or comm,  # Prefer argv, fallback to comm
                    argv_str=argv,
                    timestamp=timestamp / 1e9,  # Convert nanoseconds to seconds
                    comm=comm,
                )
                
                # Call the registered callback
                if self.event_callback:
                    try:
                        self.event_callback(event)
                    except Exception:
                        logger.exception("Callback error processing ring buffer event")
                        
            except Exception:
                if self.running:
                    logger.exception("Event parsing error")
        
        while self.running:
            try:
                # Poll ring buffer with callback
                self.ring_buffer.poll(handle_ring_buffer_event, timeout=100)
                
            except KeyboardInterrupt:
                break
            except Exception:
                if self.running:
                    logger.exception("Ring buffer error")
                import time
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
        ebpf_path: Path to compiled eBPF program (optional)
        
    Returns:
        The global RCEMonitor instance
    """
    global _rce_monitor
    if _rce_monitor is None:
        _rce_monitor = RCEMonitor(ebpf_path)
    return _rce_monitor
