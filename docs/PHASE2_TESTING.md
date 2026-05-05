# Phase 2: Kernel Guard Testing Guide

Testing Phase 2 requires validating both the eBPF kernel program and the Python/BCC loader integration.

## Quick Test Matrix

| Test | Platform | Prerequisites | What It Tests |
|------|----------|---|---|
| **Build Verification** | Linux | clang, llvm, kernel headers | eBPF program compiles correctly |
| **BCC Loader Test** | Linux (root) | BCC installed + compiled .o file | RCEMonitor loads and polls events |
| **API Fallback Test** | Windows/Mac/Linux | Python environment only | System degrades gracefully without eBPF |
| **Full Integration** | Linux (root) | Everything | End-to-end: kernel → userspace → detection → API |

---

## Test 1: Build Verification (Linux)

Verify the eBPF program compiles without errors.

### Prerequisites
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev linux-headers-$(uname -r)
```

### Run Build Test
```bash
cd kernel
make check      # Verify tools installed
make clean      # Clean previous builds
make all        # Compile execve_hook.c → .output/execve_hook.o
```

### Expected Output
```
eBPF Build System
=================
Targets:
  all     - Compile execve_hook.c to execve_hook.o
  ...
✓ clang: clang version 14.0.0 ...
✓ llc: LLVM version 14.0.0 ...
✓ Kernel: 5.15.0-56-generic
✓ BCC installed
...
[100%] Linking CXX object execve_hook.o
Built target execve_hook.o
```

### Verification
```bash
ls -lah kernel/.output/execve_hook.o
# Should show a file >100KB (containing the compiled eBPF bytecode)

file kernel/.output/execve_hook.o
# Should output: "ELF 64-bit LSB relocatable"
```

---

## Test 2: RCEMonitor Unit Test (Linux)

Test the Python/BCC loader without running the full backend.

### Setup
```bash
# Install BCC Python bindings
sudo apt-get install -y python3-bcc

# Or install via pip
pip install bcc
```

### Run Test
```bash
cd /path/to/kernal_ai_bouncer
python3 -c "
from backend.kernel.rce_monitor import get_rce_monitor

# Get monitor singleton
monitor = get_rce_monitor()

# Try to start (will print status)
monitor.start()

import time
time.sleep(2)

# Stop
monitor.stop()
print('✅ Test completed')
"
```

### Expected Output (as root)
```
🔧 Starting RCE Monitor...
  Loading eBPF program...
  ✓ eBPF program loaded
  ✓ Ring buffer initialized
  📡 Ring buffer polling started
✅ RCE Monitor started - monitoring execve syscalls
```

### Expected Output (without root)
```
🔧 Starting RCE Monitor...
❌ Failed to start RCE Monitor: [Errno 1] Operation not permitted
```

### Expected Output (without BCC installed)
```
⚠️  BCC not available - eBPF monitoring will be disabled
   Install: pip install bcc (requires Linux + kernel headers)
❌ BCC not installed - cannot load eBPF program
```

---

## Test 3: System Call Capture Test (Linux, root required)

Verify the eBPF hook actually captures execve events.

### Setup
```bash
cd /path/to/kernal_ai_bouncer
pip install -r backend/requirements.txt
```

### Create Test Script
```bash
cat > /tmp/test_ebpf_events.py << 'EOF'
import sys
sys.path.insert(0, '/path/to/kernal_ai_bouncer')

from backend.kernel.rce_monitor import get_rce_monitor
import time

captured_events = []

def event_callback(event):
    print(f"📡 Captured event: PID={event.pid}, cmd={event.command}")
    captured_events.append(event)

monitor = get_rce_monitor()
monitor.start(event_callback=event_callback)

print("✅ eBPF hook active. Running test commands in 2 seconds...")
time.sleep(2)

# In another terminal, run:
#   for i in {1..5}; do echo "test"; ls /tmp; done

print("Waiting for events (30 seconds)...")
time.sleep(30)

monitor.stop()
print(f"\n✅ Captured {len(captured_events)} events")
EOF

# Run as root
sudo python3 /tmp/test_ebpf_events.py
```

### In Another Terminal (while test is running)
```bash
# Generate some exec events
for i in {1..5}; do
  echo "=== Command $i ==="
  ls /tmp
  whoami
  date
  sleep 0.5
done
```

### Expected Behavior
First terminal should log captured events:
```
✅ eBPF hook active. Running test commands in 2 seconds...
📡 Captured event: PID=12345, cmd=ls
📡 Captured event: PID=12346, cmd=whoami
📡 Captured event: PID=12347, cmd=date
...
✅ Captured 15 events
```

---

## Test 4: API Fallback Test (Windows/Mac/Linux without eBPF)

Verify the system works without kernel monitoring.

### Setup
```bash
cd /path/to/kernal_ai_bouncer
pip install -r backend/requirements.txt
python backend/models/train_model.py  # Train ML model
```

### Start Backend
```bash
uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

### Expected Output
```
INFO:     Started server process [12345]
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

**Note**: On non-Linux, you'll see:
```
⚠️  eBPF monitoring requires Linux (running on Windows)
   API and Dashboard will still work without kernel monitoring
```

### Test API Endpoint
```bash
# Safe command
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"ls -la"}'

# Response should be:
{
  "command": "ls -la",
  "classification": "safe",
  "risk_score": 5.2,
  "matched_rules": [],
  "ml_confidence": 0.15,
  "explanation": "Normal command with low suspicious indicators."
}
```

---

## Test 5: Full Integration Test (Linux, root)

End-to-end test with backend, detection pipeline, and WebSocket streaming.

### Setup
```bash
cd /path/to/kernal_ai_bouncer
bash scripts/setup_kernel.sh      # Install eBPF + BCC
bash scripts/setup_backend.sh     # Install Python deps
python backend/models/train_model.py
```

### Start Backend (as root)
```bash
sudo -E /path/to/venv/bin/uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload-dir backend
```

You should see:
```
🔧 Starting RCE Monitor...
  Loading eBPF program...
  ✓ eBPF program loaded
  ✓ Ring buffer initialized
  📡 Ring buffer polling started
✅ RCE Monitor started - monitoring execve syscalls
```

### Test API (another terminal)
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"ls"}'
```

### Test Real-Time Monitoring
```bash
# In terminal 2: Make API calls
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"bash -c whoami"}'

# In terminal 3: Run actual commands (will be captured by eBPF)
bash -c 'whoami'
bash -c 'cat /etc/hostname'
curl https://example.com
```

### Get Recent Events
```bash
curl http://localhost:8000/events?limit=10 | python3 -m json.tool
```

Expected response includes both API-analyzed and kernel-captured events:
```json
{
  "events": [
    {
      "id": "evt_xyz123",
      "command": "bash -c whoami",
      "pid": 5678,
      "risk_score": 45.2,
      "classification": "suspicious",
      "timestamp": 1699500000.123
    },
    ...
  ],
  "total": 5
}
```

---

## Test 6: Demo Script (Linux or Windows)

Run the existing demo suite:

### On Linux (with eBPF)
```bash
bash scripts/demo.sh      # API-based demo
bash scripts/test_attacks.sh  # Detection accuracy test
```

### On Windows (without eBPF)
```powershell
.\scripts\demo.ps1
```

---

## Troubleshooting Phase 2

### Issue: `clang not found`
```bash
sudo apt-get install -y clang llvm
```

### Issue: `from bcc import BPF` fails
```bash
# Ubuntu/Debian
sudo apt-get install -y python3-bcc

# Or via pip
pip install bcc
# (requires kernel headers installed)
```

### Issue: eBPF program fails to load with "Operation not permitted"
```bash
# Must run as root
sudo python3 script.py

# Or grant CAP_BPF
sudo setcap cap_bpf=+ep $(which python3)
```

### Issue: Ring buffer poll times out
- This is normal if no processes are executing
- Try running some commands: `ls`, `pwd`, `whoami`
- The backend should capture them in real-time

### Issue: Kernel version < 5.4
```bash
uname -r
# eBPF tracepoint hooks require 5.4+
# Older kernels will fail to load the program
```

---

## Checklist for Phase 2 Completion

- [ ] eBPF program compiles: `make all` succeeds
- [ ] Build tools verified: `make check` passes
- [ ] BCC loader initializes without errors
- [ ] API works on Windows/Mac (fallback mode)
- [ ] API works on Linux without eBPF
- [ ] API works on Linux with eBPF (root)
- [ ] Kernel events are captured in real-time
- [ ] WebSocket `/ws` endpoint receives events
- [ ] Detection pipeline scores kernel events correctly
- [ ] `/events` endpoint returns both API and kernel events

---

## Current Status

The real-time kernel-to-dashboard path is implemented in this workspace. The remaining validation focus is Linux-specific kernel capture, stress testing, and optional persistence/alerting work.
