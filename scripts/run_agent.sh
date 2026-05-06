#!/bin/bash
set -e

echo "Starting AI Bouncer agent in background..."
python3 -m backend.agent.main &
AGENT_PID=$!

echo "Starting backend server on port 8000..."
python3 -m uvicorn backend.app:app --host 0.0.0.0 --port 8000

# Cleanup agent when backend stops
kill $AGENT_PID
