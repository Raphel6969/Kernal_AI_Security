#!/bin/bash
set -e

# Single-owner kernel monitoring: only one process should attach eBPF
# KERNEL_MONITOR_OWNER defaults to 'backend' (recommended)
# Set to 'agent' to have the agent own the monitor instead
# Set to 'disabled' to disable kernel monitoring entirely

KERNEL_MONITOR_OWNER=${KERNEL_MONITOR_OWNER:-backend}
export KERNEL_MONITOR_OWNER

echo "🚀 Starting AI Bouncer with KERNEL_MONITOR_OWNER=$KERNEL_MONITOR_OWNER"
echo ""

if [ "$KERNEL_MONITOR_OWNER" = "backend" ]; then
    echo "✓ Backend will own kernel monitoring"
    echo "✓ Agent will idle (no duplicate monitoring)"
elif [ "$KERNEL_MONITOR_OWNER" = "agent" ]; then
    echo "✓ Agent will own kernel monitoring"
    echo "✓ Backend will operate in API-only mode"
else
    echo "✓ Kernel monitoring is disabled"
fi

echo ""
echo "Starting AI Bouncer agent in background..."
python3 -m backend.agent.main &
AGENT_PID=$!

echo "Starting backend server on port 8000..."
python3 -m uvicorn backend.app:app --host 0.0.0.0 --port 8000

# Cleanup agent when backend stops
kill $AGENT_PID 2>/dev/null || true
