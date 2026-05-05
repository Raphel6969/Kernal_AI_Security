# Quick Start

## Windows and WSL2

Use the API and dashboard path when kernel capture is unavailable:

```powershell
pip install -r backend/requirements.txt
python backend/models/train_model.py
uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Then start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Expected behavior:
- API requests classify commands in real time.
- The dashboard connects to `/ws` and shows live events.
- eBPF kernel capture stays disabled on Windows and WSL2.

## Linux With Kernel Capture

```bash
bash scripts/setup_kernel.sh
cd kernel && make check && make all
sudo -E /path/to/venv/bin/uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Then run commands such as:

```bash
whoami
ls /tmp
curl https://example.com
```

Expected behavior:
- Kernel execve events flow into the detection pipeline.
- Security events are stored and broadcast to the dashboard.
- WebSocket clients receive the live stream immediately.

## Where To Go Next

- [Phase 2 Testing](PHASE2_TESTING.md)
- [Architecture](ARCHITECTURE.md)
- [API Reference](API.md)