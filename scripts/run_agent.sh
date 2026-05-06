#!/bin/bash
set -e

echo "Starting AI Bouncer agent..."
python3 - <<'PY'
from backend.agent.runtime import format_startup_message
print(format_startup_message())
PY

echo "Starting backend server on port 8000..."
python3 -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
