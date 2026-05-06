param(
    [switch]$ApiOnly
)

$ErrorActionPreference = "Stop"

Write-Host "Starting AI Bouncer agent..."

if ($ApiOnly) {
    Write-Host "API-only mode requested."
}

python -c "from backend.agent.runtime import format_startup_message; print(format_startup_message())"

Write-Host "Starting backend server on port 8000..."
python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
