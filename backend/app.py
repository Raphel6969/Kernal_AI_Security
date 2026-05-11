"""
Main FastAPI application for Aegix backend.
Handles command analysis via API and WebSocket event streaming.
"""

import os
import sys
import logging

# Ensure project root is on sys.path so running `python app.py` from
# the `backend/` folder can still import the `backend` package.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, WebSocket, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from typing import Dict, List, Optional
import asyncio
import uuid
import psutil
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
    agent_id: str | None = None
    command: str
    pid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    argv_str: str | None = None
    comm: str = "agent"
    timestamp: float | None = None
    process_memory_mb: float = 0.0
    system_memory_percent: float = 0.0


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
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Aegix Security",
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
active_websockets: Dict[WebSocket, Optional[str]] = {}
active_websockets_lock = asyncio.Lock()
main_event_loop = None


def _build_execve_event(
    command: str,
    *,
    agent_id: str | None = None,
    pid: int = 0,
    ppid: int = 0,
    uid: int = 0,
    gid: int = 0,
    argv_str: str | None = None,
    comm: str = "api",
    timestamp: float | None = None,
    process_memory_mb: float = 0.0,
    system_memory_percent: float = 0.0,
) -> ExecveEvent:
    """Build a normalized execve event for both API and agent inputs."""
    return ExecveEvent(
        agent_id=agent_id,
        pid=pid,
        ppid=ppid,
        uid=uid,
        gid=gid,
        command=command,
        argv_str=argv_str or command,
        timestamp=timestamp or datetime.now().timestamp(),
        comm=comm,
        process_memory_mb=process_memory_mb,
        system_memory_percent=system_memory_percent,
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
    detection_result = pipeline.detect(
        execve_event.command,
        process_memory_mb=execve_event.process_memory_mb,
        system_memory_percent=execve_event.system_memory_percent
    )
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
            logger.warning(f"Malicious event detected (PID {execve_event.pid}) but Auto-Remediation is DISABLED. Skipping kill.")

    event_store.append(security_event)
    asyncio.create_task(alert_manager.dispatch(security_event))

    emoji = "🟢" if security_event.detection_result.classification == "safe" else \
        "🟡" if security_event.detection_result.classification == "suspicious" else "🔴"
    rem_info = f" | remediation={security_event.remediation_status}" if security_event.remediation_status else ""
    logger.info(
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
            # Capture memory footprint immediately
            try:
                proc = psutil.Process(execve_event.pid)
                execve_event.process_memory_mb = proc.memory_info().rss / (1024 * 1024)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                execve_event.process_memory_mb = 0.0
            
            execve_event.system_memory_percent = psutil.virtual_memory().percent

            # Run detection pipeline
            if main_event_loop:
                asyncio.run_coroutine_threadsafe(
                    ingest_security_event(execve_event, source="kernel"),
                    main_event_loop,
                )
        except Exception as e:
            logger.exception("Kernel event processing error")
    
    # Kernel monitor ownership policy
    owner = settings.validate_owner()
    kernel_active = False

    logger.info("==================================================")
    logger.info("Starting Aegix backend")
    logger.info(f"Platform: {sys.platform}")
    logger.info(f"Owner Mode: {owner}")
    logger.info(f"API URL: http://{settings.api_host}:{settings.api_port}")
    logger.info(f"WebSocket URL: ws://{settings.api_host}:{settings.api_port}/ws")

    if owner == "backend":
        # Start kernel monitoring with callback
        try:
            hook_manager.start(event_callback=on_kernel_event)
            kernel_active = getattr(hook_manager.monitor, "running", False)
            logger.info("Aegix security module initialized (owned by backend)")
            store_type = type(event_store).__name__ if event_store is not None else "<none>"
            logger.info(f"Startup: DB path={settings.db_path} | EventStore={store_type}")
        except Exception as e:
            logger.exception("Aegix security module initialization failed; operating in API-only mode")
    elif owner == "agent":
        logger.info("Kernel monitor ownership set to 'agent' — backend will not attach eBPF hooks")
    else:
        logger.info("Kernel monitoring disabled by configuration (KERNEL_MONITOR_OWNER=disabled)")
    
    logger.info(f"Kernel Active: {'YES' if kernel_active else 'NO'}")
    logger.info("Backend ready")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down...")
    hook_manager.stop()
    logger.info("Shutdown complete")


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
async def ingest_agent_event(request: Request, event: AgentEventRequest):
    """Ingest an event forwarded by the always-on agent."""
    if not event.command or not event.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    execve_event = _build_execve_event(
        event.command,
        agent_id=event.agent_id,
        pid=event.pid,
        ppid=event.ppid,
        uid=event.uid,
        gid=event.gid,
        argv_str=event.argv_str,
        comm=event.comm,
        timestamp=event.timestamp,
        process_memory_mb=event.process_memory_mb,
        system_memory_percent=event.system_memory_percent,
    )
    security_event = await ingest_security_event(execve_event, source="agent")
    return _build_response(security_event)


@app.get("/events")
@limiter.limit("20/minute")
async def get_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    agent_id: str | None = Query(default=None),
):
    """
    Get recent security events.
    
    Args:
        limit: Maximum number of events to return
        
    Returns:
        List of recent SecurityEvent objects as dicts
    """
    events = event_store.get_recent(limit, agent_id=agent_id)
    return [e.dict() for e in events]


@app.delete("/events")
async def clear_events():
    """Delete all stored security events and clear the in-memory cache."""
    deleted_events = event_store.size()
    event_store.clear()
    return {"status": "ok", "deleted_events": deleted_events}


@app.get("/stats")
async def get_stats(agent_id: str | None = Query(default=None)):
    """Get statistics about detected events."""
    return {
        "total_events": len(event_store.get_all(agent_id=agent_id)),
        "safe": len(event_store.get_by_classification("safe", agent_id=agent_id)),
        "suspicious": len(event_store.get_by_classification("suspicious", agent_id=agent_id)),
        "malicious": len(event_store.get_by_classification("malicious", agent_id=agent_id)),
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
async def websocket_endpoint(websocket: WebSocket, agent_id: str | None = Query(default=None)):
    """
    WebSocket endpoint for real-time event streaming.
    Broadcasts security events to connected clients filtered by agent_id when provided.
    """
    await websocket.accept()
    async with active_websockets_lock:
        active_websockets[websocket] = agent_id
        active_count = len(active_websockets)

    try:
        logger.info(f"WebSocket client connected ({active_count} active)")

        # Send recent events to new client
        recent_events = event_store.get_recent(100, agent_id=agent_id)
        for event in recent_events:
            try:
                await websocket.send_json(event.dict())
            except Exception:
                logger.exception("Failed to send recent event to new websocket client")

        # Keep connection alive
        while True:
            # Client can send ping to stay alive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")

    except Exception:
        logger.exception("WebSocket error")

    finally:
        async with active_websockets_lock:
            active_websockets.pop(websocket, None)
            active_count = len(active_websockets)
        logger.info(f"WebSocket client disconnected ({active_count} active)")


async def broadcast_event(event: SecurityEvent):
    """
    Broadcast a security event to all connected WebSocket clients.
    
    Args:
        event: SecurityEvent to broadcast
    """
    dead_connections = set()

    # Snapshot avoids set-size-change errors during iteration.
    async with active_websockets_lock:
        websockets_snapshot = list(active_websockets.items())

    for websocket, websocket_agent_id in websockets_snapshot:
        if websocket_agent_id is not None and websocket_agent_id != event.execve_event.agent_id:
            continue
        if websocket_agent_id is None and event.execve_event.agent_id is not None:
            continue
        try:
            await websocket.send_json(event.dict())
        except Exception:
            logger.exception("Failed to send event to client")
            dead_connections.add(websocket)
    
    # Cleanup dead connections
    if dead_connections:
        async with active_websockets_lock:
            for ws in dead_connections:
                active_websockets.pop(ws, None)


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
# Static Files (Frontend)
# ==============================================================================

# Serve React frontend build as static files.
# Mount at the very end so API routes take precedence.
frontend_dist = os.path.join(PROJECT_ROOT, "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
else:
    logger.warning(f"Frontend dist directory not found at {frontend_dist}. Frontend assets will not be served.")


# ==============================================================================
# Main Entry Point
# ==============================================================================

if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting Aegix backend server")
    logger.info(f"API: http://{settings.api_host}:{settings.api_port}")
    logger.info(f"Docs: http://{settings.api_host}:{settings.api_port}/docs")
    logger.info(f"WebSocket: ws://{settings.api_host}:{settings.api_port}/ws")
    
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.api_log_level,
    )
