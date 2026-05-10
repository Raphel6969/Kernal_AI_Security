"""
Main FastAPI application for AI Bouncer backend.
Handles command analysis via API and WebSocket event streaming.
"""

import os
import sys

# Ensure project root is on sys.path so running `python app.py` from
# the `backend/` folder can still import the `backend` package.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, WebSocket, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from typing import List, Set
import asyncio
import uuid
from datetime import datetime

from backend.config import get_settings
from backend.detection.pipeline import get_detection_pipeline
from backend.events.event_store import get_event_store
from backend.events.models import ExecveEvent, SecurityEvent
from backend.kernel.execve_hook import get_hook_manager
from backend.alerts.alert_manager import get_alert_manager
from backend.alerts.models import WebhookCreate, WebhookResponse, AlertHistoryResponse
from backend.agent.remediation import kill_process, is_remediation_enabled, set_remediation_enabled

# ==============================================================================
# Models
# ==============================================================================

class CommandAnalysisRequest(BaseModel):
    """Request to analyze a command."""
    command: str


class AgentEventRequest(BaseModel):
    """Event forwarded by the always-on agent."""
    command: str
    pid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    argv_str: str | None = None
    comm: str = "agent"
    timestamp: float | None = None


class CommandAnalysisResponse(BaseModel):
    """Response from command analysis."""
    command: str
    classification: str
    risk_score: float
    matched_rules: List[str]
    ml_confidence: float
    explanation: str


# ==============================================================================
# FastAPI App Setup
# ==============================================================================

# ==============================================================================
# FastAPI App Setup
# ==============================================================================

settings = get_settings()

app = FastAPI(
    title="AI Bouncer + Kernel Guard",
    description="Real-time RCE Prevention System",
    version="0.1.0",
)

# Rate Limiter setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware for frontend (restrict origins via config)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.parsed_frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# Global State
# ==============================================================================

pipeline = get_detection_pipeline()
event_store = get_event_store(max_events=settings.event_cache_size)
hook_manager = get_hook_manager()
alert_manager = get_alert_manager()
active_websockets: Set[WebSocket] = set()
active_websockets_lock = asyncio.Lock()
main_event_loop = None


def _build_execve_event(
    command: str,
    *,
    pid: int = 0,
    ppid: int = 0,
    uid: int = 0,
    gid: int = 0,
    argv_str: str | None = None,
    comm: str = "api",
    timestamp: float | None = None,
) -> ExecveEvent:
    """Build a normalized execve event for both API and agent inputs."""
    return ExecveEvent(
        pid=pid,
        ppid=ppid,
        uid=uid,
        gid=gid,
        command=command,
        argv_str=argv_str or command,
        timestamp=timestamp or datetime.now().timestamp(),
        comm=comm,
    )


def _build_response(security_event: SecurityEvent) -> CommandAnalysisResponse:
    """Convert a security event into the API response model."""
    result = security_event.detection_result
    return CommandAnalysisResponse(
        command=security_event.execve_event.command,
        classification=result.classification,
        risk_score=result.risk_score,
        matched_rules=result.matched_rules,
        ml_confidence=result.ml_confidence,
        explanation=result.explanation or "",
    )


async def ingest_security_event(
    execve_event: ExecveEvent,
    *,
    source: str = "api",
) -> SecurityEvent:
    """Run detection, store the event, and broadcast it to the dashboard."""
    detection_result = pipeline.detect(execve_event.command)
    security_event = SecurityEvent(
        id=f"evt_{uuid.uuid4().hex[:8]}",
        execve_event=execve_event,
        detection_result=detection_result,
        detected_at=datetime.now().timestamp(),
    )

    # Auto-Remediation: kill the process if malicious and toggle is ON
    if detection_result.classification == "malicious":
        if is_remediation_enabled():
            rem_result = kill_process(execve_event.pid)
            security_event.remediation_action = rem_result["action"]
            security_event.remediation_status = rem_result["status"]
        else:
            print(f"⚠️  Malicious event detected (PID {execve_event.pid}) but Auto-Remediation is DISABLED. Skipping kill.")

    event_store.append(security_event)
    asyncio.create_task(alert_manager.dispatch(security_event))

    emoji = "🟢" if security_event.detection_result.classification == "safe" else \
            "🟡" if security_event.detection_result.classification == "suspicious" else "🔴"
    rem_info = f" | 🛑 {security_event.remediation_status}" if security_event.remediation_status else ""
    print(
        f"{emoji} {source.upper()} event: {execve_event.command[:50]} "
        f"(PID {execve_event.pid}) -> {security_event.detection_result.classification.upper()}{rem_info}"
    )

    await broadcast_event(security_event)
    return security_event

# ==============================================================================
# Startup & Shutdown
# ==============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize backend systems on startup."""
    global main_event_loop

    main_event_loop = asyncio.get_running_loop()
    
    # Define kernel event callback
    def on_kernel_event(execve_event):
        """Handle kernel events from eBPF."""
        try:
            # Run detection pipeline
            if main_event_loop:
                asyncio.run_coroutine_threadsafe(
                    ingest_security_event(execve_event, source="kernel"),
                    main_event_loop,
                )
        except Exception as e:
            print(f"⚠️  Kernel event processing error: {e}")
    
    # Kernel monitor ownership policy
    owner = settings.validate_owner()
    kernel_active = False

    print("==================================================")
    print("🚀 Starting AI Bouncer backend...")
    print(f"   Platform:      {sys.platform}")
    print(f"   Owner Mode:    {owner}")
    print(f"   API URL:       http://{settings.api_host}:{settings.api_port}")
    print(f"   WebSocket URL: ws://{settings.api_host}:{settings.api_port}/ws")

    if owner == "backend":
        # Start kernel monitoring with callback
        try:
            hook_manager.start(event_callback=on_kernel_event)
            kernel_active = getattr(hook_manager.monitor, "running", False)
            print("✅ Kernel Guard initialized (owned by backend)")
        except Exception as e:
            print(f"⚠️  Kernel Guard initialization failed: {e}")
            print("   System will operate in API-only mode")
    elif owner == "agent":
        print("ℹ️  Kernel monitor ownership set to 'agent' — backend will not attach eBPF hooks")
    else:
        print("ℹ️  Kernel monitoring disabled by configuration (KERNEL_MONITOR_OWNER=disabled)")
    
    print(f"   Kernel Active: {'YES' if kernel_active else 'NO'}")
    print("==================================================")
    print("✅ Backend ready!")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    print("🛑 Shutting down...")
    hook_manager.stop()
    print("✅ Shutdown complete")


# ==============================================================================
# API Endpoints
# ==============================================================================

@app.get("/healthz")
async def healthz():
    """Fast health ping."""
    return {"status": "ok"}

@app.get("/readyz")
async def readyz():
    """Readiness probe for deploy environments."""
    try:
        # Validate core dependencies are initialized and DB is reachable.
        _ = pipeline is not None
        _ = alert_manager is not None
        _ = event_store.size()
        return {"status": "ready"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Not ready: {e}")

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "online",
        "name": "AI Bouncer + Kernel Guard",
        "version": "0.1.0",
        "events_stored": event_store.size(),
    }


@app.post("/analyze", response_model=CommandAnalysisResponse)
@limiter.limit("30/minute")
async def analyze_command(request: Request, body: CommandAnalysisRequest):
    """
    Analyze a command for threat level.
    
    Args:
        request: CommandAnalysisRequest with command string
        
    Returns:
        CommandAnalysisResponse with detection results
    """
    if not body.command or not body.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")
    
    execve_event = _build_execve_event(body.command)
    security_event = await ingest_security_event(execve_event, source="api")
    return _build_response(security_event)


@app.post("/agent/events", response_model=CommandAnalysisResponse)
@limiter.limit("60/minute")
async def ingest_agent_event(request: Request, body: AgentEventRequest):
    """Ingest an event forwarded by the always-on agent."""
    if not body.command or not body.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    execve_event = _build_execve_event(
        body.command,
        pid=body.pid,
        ppid=body.ppid,
        uid=body.uid,
        gid=body.gid,
        argv_str=body.argv_str,
        comm=body.comm,
        timestamp=body.timestamp,
    )
    security_event = await ingest_security_event(execve_event, source="agent")
    return _build_response(security_event)


@app.get("/events")
@limiter.limit("20/minute")
async def get_events(request: Request, limit: int = Query(default=100, ge=1, le=1000)):
    """
    Get recent security events.
    
    Args:
        limit: Maximum number of events to return
        
    Returns:
        List of recent SecurityEvent objects as dicts
    """
    events = event_store.get_recent(limit)
    return [e.dict() for e in events]


@app.get("/stats")
async def get_stats():
    """Get statistics about detected events."""
    return {
        "total_events": event_store.size(),
        "safe": event_store.get_safe_count(),
        "suspicious": event_store.get_suspicious_count(),
        "malicious": event_store.get_malicious_count(),
    }


@app.get("/webhooks", response_model=List[WebhookResponse])
async def list_webhooks():
    """List all registered webhooks."""
    return alert_manager.get_webhooks()


@app.post("/webhooks", response_model=WebhookResponse)
async def create_webhook(request: WebhookCreate):
    """Register a new webhook URL."""
    if not request.url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL")
    return alert_manager.add_webhook(
        request.url,
        trigger_safe=request.trigger_safe,
        trigger_suspicious=request.trigger_suspicious,
        trigger_malicious=request.trigger_malicious
    )


@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    """Remove a webhook."""
    alert_manager.remove_webhook(webhook_id)
    return {"status": "success"}


@app.get("/alerts/history", response_model=List[AlertHistoryResponse])
async def list_alert_history(limit: int = Query(default=50, ge=1, le=1000)):
    """Get history of triggered alerts."""
    return alert_manager.get_alert_history(limit)


# ==============================================================================
# Remediation Settings
# ==============================================================================

@app.get("/settings/remediation")
async def get_remediation_settings():
    """Get current auto-remediation toggle state."""
    return {"enabled": is_remediation_enabled()}


@app.post("/settings/remediation")
async def update_remediation_settings(body: dict):
    """Enable or disable auto-remediation."""
    enabled = body.get("enabled", False)
    set_remediation_enabled(bool(enabled))
    return {"enabled": is_remediation_enabled()}


@app.get("/settings/thresholds")
async def get_threshold_settings():
    """Get current classification thresholds."""
    return {
        "suspicious_threshold": pipeline.suspicious_threshold,
        "malicious_threshold": pipeline.malicious_threshold
    }


@app.post("/settings/thresholds")
async def update_threshold_settings(body: dict):
    """Update classification thresholds."""
    suspicious = float(body.get("suspicious_threshold", 30.0))
    malicious = float(body.get("malicious_threshold", 70.0))
    pipeline.update_thresholds(suspicious, malicious)
    return {
        "suspicious_threshold": pipeline.suspicious_threshold,
        "malicious_threshold": pipeline.malicious_threshold
    }


# ==============================================================================
# WebSocket
# ==============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time event streaming.
    Broadcasts security events to all connected clients.
    """
    await websocket.accept()
    async with active_websockets_lock:
        active_websockets.add(websocket)
        active_count = len(active_websockets)
    
    try:
        print(f"📡 WebSocket client connected ({active_count} active)")
        
        # Send recent events to new client
        recent_events = event_store.get_recent(100)
        for event in recent_events:
            try:
                await websocket.send_json(event.dict())
            except Exception as e:
                print(f"⚠️  Failed to send recent event: {e}")
        
        # Keep connection alive
        while True:
            # Client can send ping to stay alive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    
    except Exception as e:
        print(f"❌ WebSocket error: {e}")
    
    finally:
        async with active_websockets_lock:
            active_websockets.discard(websocket)
            active_count = len(active_websockets)
        print(f"📡 WebSocket client disconnected ({active_count} active)")


async def broadcast_event(event: SecurityEvent):
    """
    Broadcast a security event to all connected WebSocket clients.
    
    Args:
        event: SecurityEvent to broadcast
    """
    dead_connections = set()

    # Snapshot avoids set-size-change errors during iteration.
    async with active_websockets_lock:
        websockets_snapshot = list(active_websockets)

    for websocket in websockets_snapshot:
        try:
            await websocket.send_json(event.dict())
        except Exception as e:
            print(f"⚠️  Failed to send event to client: {e}")
            dead_connections.add(websocket)
    
    # Cleanup dead connections
    if dead_connections:
        async with active_websockets_lock:
            for ws in dead_connections:
                active_websockets.discard(ws)


# ==============================================================================
# Event Processing Callback
# ==============================================================================

async def process_execve_event(execve_event: ExecveEvent):
    """
    Process an execve event from the kernel.
    
    Args:
        execve_event: ExecveEvent object with kernel data
    """
    # Detection runs inside ingest_security_event.
    await ingest_security_event(execve_event, source="kernel")


# ==============================================================================
# Main Entry Point
# ==============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting AI Bouncer backend server...")
    print(f"   API: http://{settings.api_host}:{settings.api_port}")
    print(f"   Docs: http://{settings.api_host}:{settings.api_port}/docs")
    print(f"   WebSocket: ws://{settings.api_host}:{settings.api_port}/ws")
    
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.api_log_level,
    )
