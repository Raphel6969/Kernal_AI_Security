// eBPF program for execve syscall monitoring
// Compiled on-the-fly by BCC - no need for pre-compilation
// Works on WSL2, native Linux, and all kernel versions 5.4+
//
// DESIGN NOTE — Memory Profiling Layer:
//   Process RSS memory and system RAM% are intentionally NOT captured here.
//   Reasons:
//     1. eBPF VM prohibits floating-point arithmetic (bytes→MB conversion).
//     2. task_mem_info() requires CO-RE BTF support not available on all kernels.
//     3. Very short-lived processes (e.g. ls) exit before ring-buffer flush.
//   Memory is sampled by the Python agent/backend using psutil immediately after
//   this event surfaces from the ring buffer — the standard approach used by
//   Falco, Sysdig, and other production eBPF security tools.
//   See: backend/agent/main.py and backend/app.py (on_kernel_event)

BPF_RINGBUF_OUTPUT(events, 256);

struct execve_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u64 timestamp;
    char comm[16];
    char argv[4096];
};

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
    
    const char **argv = args->argv;
    const char *filename = args->filename;
    
    if (filename) {
        bpf_probe_read_user_str(&event->argv, sizeof(event->argv), filename);
    } else if (argv) {
        const char *arg0 = NULL;
        bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
        if (arg0) {
            bpf_probe_read_user_str(&event->argv, sizeof(event->argv), arg0);
        }
    }
    
    if (event->argv[0] == 0) {
        bpf_probe_read_kernel_str(&event->argv, sizeof(event->argv), &task->comm);
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}
