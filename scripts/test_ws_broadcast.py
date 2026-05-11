r"""Simple local test to verify WebSocket broadcast from the backend.

Usage (from project root, with dependencies installed):

python -m venv .venv
.venv/Scripts/Activate.ps1   # Windows PowerShell (use forward slashes to avoid \ escapes)
pip install -r backend/requirements.txt
python scripts/test_ws_broadcast.py

This script uses FastAPI's TestClient to run the app in-process
and connect a WebSocket client to `/ws`, then POST `/analyze` and
print any messages received on the socket.
"""

import sys
import json
import os

# Add project root to sys.path so backend package is importable
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from backend import app as backend_app_module
    from backend.events.event_store import get_event_store
    from fastapi.testclient import TestClient
except Exception as e:
    print("Missing dependency or import error:", e)
    print("Ensure your venv is activated and you've installed backend requirements:")
    print("  conda activate aegix")
    print("  pip install -r backend/requirements.txt")
    sys.exit(1)


def main():
    # Reset in-memory store to avoid prior events
    backend_app_module.event_store = get_event_store(max_events=1000)
    backend_app_module.active_websockets = set()

    # Create TestClient - use positional arg for app
    app = backend_app_module.app
    client = TestClient(app)

    print("Connecting WebSocket to /ws...")
    with client.websocket_connect("/ws") as ws:
        print("Connected. Posting /analyze...")
        resp = client.post("/analyze", json={"command": "echo test-broadcast"})
        print("POST status:", resp.status_code)
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        print("POST body:", json.dumps(body) if isinstance(body, dict) else body)

        # Attempt to read a broadcasted message
        try:
            msg = ws.receive_json(timeout=3)
            print("Received WebSocket message:")
            print(json.dumps(msg, indent=2)[:2000])
        except Exception as e:
            print("No WebSocket message received:", e)


if __name__ == "__main__":
    main()
