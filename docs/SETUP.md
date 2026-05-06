# AI Bouncer + Kernel Guard - Setup Guide

## Prerequisites

- **OS**: Ubuntu 20.04+, Debian 11+, or equivalent Linux distribution
- **Kernel**: 5.4 or newer (check with `uname -r`)
- **Python**: 3.8 or newer
- **Node.js**: 16 or newer
- **Sudo/Root**: Required for eBPF operations
- **Internet**: For downloading dependencies

### Platform Behavior

- **Linux**: full agent + backend + kernel monitoring
- **Windows**: agent + backend + dashboard in API-only mode
- **macOS**: agent + backend + dashboard in API-only mode

## Step 1: Verify System Requirements

```bash
# Check Linux kernel version (need 5.4+)
uname -r

# Check Python version (need 3.8+)
python3 --version

# Check Node.js version (need 16+)
node --version
npm --version
```

## Step 2: Backend Setup

### Install System Dependencies

```bash
# Update package lists
sudo apt-get update

# Install build tools
sudo apt-get install -y \
    build-essential \
    python3-dev \
    python3-pip \
    python3-venv
```

### Run Backend Setup Script

```bash
cd kernal_ai_bouncer
bash scripts/setup_backend.sh
```

This will:
- Create a Python virtual environment
- Install FastAPI, scikit-learn, pandas, and other dependencies
- Create the `venv/` folder

For the always-on agent phase, you can start the agent wrapper directly after setup:

```bash
bash scripts/run_agent.sh
```

Verify installation:
```bash
source venv/bin/activate
python3 -c "import fastapi; import sklearn; print('✓ Backend deps OK')"
```

### Train the ML Model

```bash
source venv/bin/activate
python backend/models/train_model.py
```

This will:
- Load 100 labeled commands (50 safe + 50 malicious) from `data/`
- Train a Logistic Regression classifier
- Save the model to `backend/models/trained_model.pkl`
- Print accuracy and classification metrics

Expected accuracy: 85-95%

## Step 2.5: Agent Runtime

Before connecting the full event pipeline, verify the agent runtime starts and reports the correct mode:

```bash
python -c "from backend.agent.runtime import format_startup_message; print(format_startup_message())"
```

Expected behavior:
- Linux reports `kernel`
- Windows and macOS report `api-only`
- Unsupported platforms report `unsupported`

## Step 3: Kernel Monitoring Setup

### Install eBPF Dependencies

```bash
# Install BCC and kernel headers
bash scripts/setup_kernel.sh
```

This will:
- Install clang, llvm, libelf-dev
- Install linux-headers for your kernel
- Install BCC (eBPF toolkit) and Python bindings

If you're on macOS, this step is not applicable today. Use API-only mode and the dashboard until a Mac-native collector is added.

Verify installation:
```bash
clang --version
python3 -c "from bcc import BPF; print('✓ BCC installed')"
```

### Build eBPF Program

**Phase 2: Kernel Guard** - Compile the eBPF program:
```bash
cd kernel
make check    # Verify all build tools are installed
make clean    # Clean previous builds
make all      # Compile execve_hook.c → .output/execve_hook.o
```

This compiles the tracepoint hook using clang/llvm. The `.output/execve_hook.o` binary is automatically loaded by BCC when the backend starts.

On WSL2, `make all` now prints a skip message instead of failing. That is expected: the backend uses BCC inline compilation and continues in API-only mode if kernel loading is unavailable.

**Verify compilation**:
```bash
ls -lah kernel/.output/execve_hook.o
```

**Run the full setup**:
The `scripts/setup_kernel.sh` now automatically:
1. Installs all eBPF dependencies (clang, llvm, BCC)
2. Installs kernel headers
3. Compiles the eBPF program

## Step 4: Frontend Setup

### Install Node.js (if not already installed)

```bash
# Using apt (Ubuntu/Debian)
sudo apt-get install -y nodejs npm

# Or from Node.js official repo
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Run Frontend Setup Script

```bash
bash scripts/setup_frontend.sh
```

This will:
- Install npm dependencies (React, Vite, TypeScript)
- Create node_modules folder

Verify installation:
```bash
cd frontend && npm list | head -10
```

## Step 5: Running the System

### Terminal 1: Start Agent + Backend API

```bash
cd kernal_ai_bouncer
source venv/bin/activate
python -c "from backend.agent.runtime import format_startup_message; print(format_startup_message())"
python backend/app.py
```

Expected output:
```
🚀 Starting AI Bouncer backend server...
   API: http://localhost:8000
   Docs: http://localhost:8000/docs
   WebSocket: ws://localhost:8000/ws
...
Uvicorn running on http://0.0.0.0:8000
```

### Terminal 2: Start Frontend Dev Server

```bash
cd kernal_ai_bouncer/frontend
npm run dev
```

Expected output:
```
  ➜  Local:   http://localhost:5173/
  ➜  Press h to show help
```

### Terminal 3: Run Demo

```bash
cd kernal_ai_bouncer
bash scripts/demo.sh
```

This will:
- Send 8 test commands to the API
- Show detection results for each
- Mix of safe, suspicious, and malicious commands

### Terminal 4 (Optional): Test Suite

```bash
bash scripts/test_attacks.sh
```

Runs comprehensive test suite on RCE detection patterns.

## Step 6: Access the Dashboard

Open your browser to:
```
http://localhost:5173
```

You should see:
- Real-time event feed
- Risk score visualization
- Event statistics (safe/suspicious/malicious)

Run demo commands in Terminal 3 and watch them appear in the dashboard!

## Troubleshooting

### Backend won't start

**Error: `ModuleNotFoundError: No module named 'fastapi'`**
```bash
# Ensure venv is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r backend/requirements.txt
```

**Error: `Permission denied` on eBPF**
```bash
# eBPF typically requires root
sudo python backend/app.py

# Or verify capabilities:
sudo getcap /usr/bin/python3
```

### ML model not found

**Error: `Model not found at backend/models/trained_model.pkl`**
```bash
# Train the model
python backend/models/train_model.py
```

### Frontend won't connect to backend

**Dashboard shows "Backend Offline"**

1. Check backend is running on port 8000:
   ```bash
   lsof -i :8000
   ```

2. Check CORS is enabled in `backend/app.py`

3. Try API directly:
   ```bash
   curl http://localhost:8000/
   ```

### WebSocket connection fails

**Console shows "WebSocket closed"**

1. Check backend is running and accessible
2. Reconnects now use exponential backoff with jitter, so allow a few seconds between retries
3. Check browser console for errors

### Kernel monitoring not capturing events

This is expected on Windows and WSL2. Kernel capture requires Linux with eBPF support, while API and dashboard functionality continue to work.

## Next Steps

1. **Persistence**: Add SQLite storage and log rotation
2. **Alerting**: Add Slack, email, or SIEM integrations
3. **Cross-platform kernels**: Explore ETW and DTrace backends
4. **Packaging**: Add production deployment and release automation

## Support

For issues:
1. Check `/docs` endpoint for API reference
2. Enable debug logging: `export LOG_LEVEL=DEBUG`
3. Check `backend/app.py` for configuration options

---

**Happy defending! 🛡️**
