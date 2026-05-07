<!-- ARCH Linux setup and testing guide for kernal_ai_bouncer -->
# Arch Linux — Setup, eBPF & Always-on Agent

This file describes how to setup the kernal_ai_bouncer project on Arch Linux, build/load the kernel hook/eBPF components, create an "always-on" agent (systemd), and run tests and attack simulations so you don't need to manually POST to the service during robustness testing.

> Assumes repository root contains the project (this repo). Paths referenced are workspace-relative.

## 1 — Prerequisites

- Update system and install base development tools and runtime dependencies:

```bash
sudo pacman -Syu --needed git base-devel python python-virtualenv python-pip nodejs npm clang llvm libelf elfutils openssl pkgconf
```

- Install kernel headers matching your running kernel (required for building kernel helpers / eBPF):

```bash
sudo pacman -S --needed linux-headers
```

- Install BPF tooling (bpftool) and optional helper libs. On Arch, `bpftool` is available in `bpftool` package or within `linux-tools` depending on mirror; if not available, install from AUR:

```bash
sudo pacman -S --needed bpftool
# if bpftool isn't in your repos, use an AUR helper to install 'bpftool'
```

- Additional useful packages: `jq`, `python-pytest` for running tests.

## 2 — Clone & Python environment

1. Clone (if not already cloned):

```bash
git clone <repo-url> kernal_ai_bouncer
cd kernal_ai_bouncer
```

2. Create and activate a virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
```

3. (Optional) If you prefer conda, create a conda env and install Python packages accordingly.

## 3 — Configuration

All settings are centralized in `backend/config.py` and can be configured via environment variables or a `.env` file.

**Configuration options:**

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Edit `.env` with your settings (common overrides):

```ini
# Kernel monitor ownership (backend|agent|disabled)
KERNEL_MONITOR_OWNER=backend

# API Server
API_HOST=0.0.0.0
API_PORT=8000
API_LOG_LEVEL=info

# Frontend CORS
FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# Event storage
DB_PATH=data/events.db
EVENT_CACHE_SIZE=1000

# Agent forwarding
BACKEND_URL=http://localhost:8000
AGENT_EVENT_TIMEOUT=5
```

All settings have defaults, so `.env` is optional. You can also override individual values via environment variables:

```bash
export KERNEL_MONITOR_OWNER=agent
export API_PORT=9000
python backend/app.py
```

## 4 — Backend & frontend quick start

- Backend (API/agent):

```bash
cd backend
# run the API/agent for manual testing
python app.py
```

- Frontend: install and run dev server (optional for UI tests):

```bash
cd frontend
npm install
npm run dev
```

## 5 — Build and load the kernel hook / eBPF helper

This project includes kernel components in `kernel/` (see [kernel/execve_hook.c](kernel/execve_hook.c) and `kernel/Makefile`). On Arch you have two common approaches:

- Use the provided Makefile to build (requires `clang`, `llvm`, `bpftool` and kernel headers).
- If it's a kernel module (insmod), follow the repo-specific Makefile instructions.

Example build & load (repo-root):

```bash
cd kernel
make clean
make
# If Makefile builds an object you can load, the Makefile may produce a loader or .o for bpftool
# You may need sudo to load: e.g. sudo ./load_execve_hook.sh or sudo ./install.sh
```

If the project uses eBPF user-space loader, run that loader as root to attach probes. If it uses a kernel module, use `sudo insmod`/`sudo modprobe` as documented in the Makefile.

Verify loaded BPF programs with `bpftool`:

```bash
sudo bpftool prog show
sudo bpftool map show
```

## 6 — Systemd: Always-on agent and eBPF loader

Create two units: one for the Python agent (backend) and one optional service to load the eBPF hook at boot.

- Example `agent` unit: create `/etc/systemd/system/kernal-ai-bouncer.service` with content below (edit paths):

```ini
[Unit]
Description=Kernal AI Bouncer Agent
After=network.target

[Service]
Type=simple
User=%u
WorkingDirectory=/home/<youruser>/kernal_ai_bouncer/backend
ExecStart=/home/<youruser>/kernal_ai_bouncer/.venv/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- Example `ebpf` loader unit (if you have a loader script or Makefile target):

```ini
[Unit]
Description=Load execve eBPF hook
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -lc 'cd /home/<youruser>/kernal_ai_bouncer/kernel && sudo make load'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kernal-ai-bouncer.service
sudo systemctl enable --now kernal-ai-bouncer-ebpf.service  # if used

# Check status
sudo systemctl status kernal-ai-bouncer.service
journalctl -u kernal-ai-bouncer.service -f
```

Notes:
- Use absolute paths for the Python interpreter in the `ExecStart` line (point to the venv python).
- Running the eBPF loader may require root; consider using a small privileged helper or set the unit to run as `root` for the loader only.

### Kernel monitor ownership

To avoid duplicate capture/processing, only one process should attach the eBPF hook on a host. This project supports a single-owner policy controlled by the `KERNEL_MONITOR_OWNER` environment variable. Valid values:

- `backend` (default): backend (`backend/app.py`) will attach the eBPF monitor. Run the agent in `api-only` mode or as a forwarder that does not start its own monitor.
- `agent`: the always-on agent process will attach and own the eBPF monitor and forward events to the backend API.
- `disabled`: no process will attach kernel hooks; system operates API-only.

Set the variable in your systemd unit or environment before starting services. Example for `backend` unit environment:

```ini
[Service]
Environment=KERNEL_MONITOR_OWNER=backend
```

Recommendation: choose one owner per host (usually `backend`) and keep the other service(s) in `api-only` mode to prevent duplicate alerts and remediation.

## 7 — Testing & robustness (no manual POSTs)

This repo already contains useful scripts and tests. Use them to automate attack simulation and verify detection/remediation without manually sending HTTP requests.

- Run the unit / integration tests (Python):

```bash
source .venv/bin/activate
pytest -q
```

- Attack simulation scripts (examples in `scripts/`):

```bash
# simulate attacks using provided script
./scripts/test_attacks.sh

# run the agent in background (for local testing)
./scripts/run_agent.sh

# simulate traffic and exercises
python scripts/simulate_traffic.py

# test websocket broadcast (if implemented)
python scripts/test_ws_broadcast.py
```

- Make tests reproducible by running the agent as a systemd service (see section 5) so it restarts automatically when destroyed.

Automated robustness checklist:

- Start both systemd units (agent + ebpf loader).
- Run `scripts/simulate_traffic.py` to generate normal and malicious activity.
- Run `scripts/test_attacks.sh` and monitor `journalctl -u kernal-ai-bouncer.service` and `data/logs/` for alerts.
- Observe that the agent remediations run (see `backend/agent/remediation.py`) and that alerts are persisted (see `events/event_store.py` and [alerts/alert_manager.py](alerts/alert_manager.py)).

## 8 — eBPF-specific testing tips

- Confirm BPF program is attached to the expected hook (kprobe/tracepoint):

```bash
sudo bpftool prog show
sudo bpftool net list   # if network-related
```

- Run a targeted syscall invocation to exercise `execve` hooks (example):

```bash
# run a sample binary that would trigger execve
/bin/ls
# or run one of your simulated malicious commands
```

- Tail kernel logs and agent logs concurrently:

```bash
sudo journalctl -k -f &
journalctl -u kernal-ai-bouncer.service -f
```

## 9 — Debugging tips

- If the eBPF program won't load, ensure `clang`, `llvm`, `bpftool` and `linux-headers` are installed and match your kernel.
- Use `dmesg` and `sudo journalctl -k` to find verifier or loader errors.
- Run the Python process manually (with `python -m pdb`) to debug agent code paths invoked by simulated traffic.

## 10 — Quick checklist for a test run

1. Build kernel hooks: `cd kernel && make`
2. Activate venv & install requirements: `source .venv/bin/activate && pip install -r backend/requirements.txt`
3. Enable+start services: `sudo systemctl enable --now kernal-ai-bouncer.service` (and ebpf loader if used)
4. Run simulations: `./scripts/test_attacks.sh` and `python scripts/simulate_traffic.py`
5. Inspect logs: `journalctl -u kernal-ai-bouncer.service -f` and `sudo bpftool prog show`

## 11 — Where to look in the repo

- Agent runtime and bridge: [backend/agent/main.py](backend/agent/main.py) and [backend/agent/bridge.py](backend/agent/bridge.py)
- Remediation logic: [backend/agent/remediation.py](backend/agent/remediation.py)
- Kernel/hook sources: [kernel/execve_hook.c](kernel/execve_hook.c) and [kernel/Makefile](kernel/Makefile)
- Simulation & test scripts: [scripts/](scripts/)

---

If you want, I can:

- add the example `systemd` unit files into `deploy/` in this repo, or
- make a small `make` target to `install-service` that registers the systemd unit and enables it.

Tell me which you'd prefer and I'll add it.
