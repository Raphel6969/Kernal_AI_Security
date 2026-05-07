param(
    [switch]$ApiOnly
)

$ErrorActionPreference = "Stop"

Write-Host "Starting AI Bouncer agent in background..."

if ($ApiOnly) {
    Write-Host "API-only mode requested."
}

Start-Process -NoNewWindow -FilePath "python" -ArgumentList "-m backend.agent.main" -PassThru | Set-Variable -Name AgentProcess

Write-Host "Starting backend server on port 8000..."
try {
    python -m uvicorn backend.app:app --host 0.0.0.0 --port 8000
} finally {
    if ($AgentProcess) {
        Write-Host "Stopping background agent..."
        Stop-Process -Id $AgentProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
