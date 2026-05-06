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

from fastapi import FastAPI, WebSocket, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Set
import asyncio
import uuid
from datetime import datetime

from backend.detection.pipeline import get_detection_pipeline
from backend.events.event_store import get_event_store
from backend.events.models import ExecveEvent, SecurityEvent
from backend.kernel.execve_hook import get_hook_manager

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

app = FastAPI(
    title="AI Bouncer + Kernel Guard",
    description="Real-time RCE Prevention System",
    version="0.1.0",
)

# CORS middleware for frontend (restrict origins via env in production)
frontend_origins_env = os.getenv(
    "FRONTEND_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
)
allowed_origins = [origin.strip() for origin in frontend_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# Global State
# ==============================================================================

pipeline = get_detection_pipeline()
event_store = get_event_store(max_events=1000)
hook_manager = get_hook_manager()
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

    event_store.append(security_event)

    emoji = "🟢" if security_event.detection_result.classification == "safe" else \
            "🟡" if security_event.detection_result.classification == "suspicious" else "🔴"
    print(
        f"{emoji} {source.upper()} event: {execve_event.command[:50]} "
        f"(PID {execve_event.pid}) -> {security_event.detection_result.classification.upper()}"
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

    print("🚀 Starting AI Bouncer backend...")
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
    
    # Start kernel monitoring with callback
    try:
        hook_manager.start(event_callback=on_kernel_event)
        print("✅ Kernel Guard initialized")
    except Exception as e:
        print(f"⚠️  Kernel Guard initialization failed: {e}")
        print("   System will operate in API-only mode")
    
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
async def analyze_command(request: CommandAnalysisRequest):
    """
    Analyze a command for threat level.
    
    Args:
        request: CommandAnalysisRequest with command string
        
    Returns:
        CommandAnalysisResponse with detection results
    """
    if not request.command or not request.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")
    
    execve_event = _build_execve_event(request.command)
    security_event = await ingest_security_event(execve_event, source="api")
    return _build_response(security_event)


@app.post("/agent/events", response_model=CommandAnalysisResponse)
async def ingest_agent_event(request: AgentEventRequest):
    """Ingest an event forwarded by the always-on agent."""
    if not request.command or not request.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    execve_event = _build_execve_event(
        request.command,
        pid=request.pid,
        ppid=request.ppid,
        uid=request.uid,
        gid=request.gid,
        argv_str=request.argv_str,
        comm=request.comm,
        timestamp=request.timestamp,
    )
    security_event = await ingest_security_event(execve_event, source="agent")
    return _build_response(security_event)


@app.get("/events")
async def get_events(limit: int = Query(default=100, ge=1, le=1000)):
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
    # Run detection pipeline
    detection_result = pipeline.detect(execve_event.command)
    
    await ingest_security_event(execve_event, source="kernel")


# Set the kernel monitor callback
def _setup_kernel_callback():
    """Setup the kernel monitor to call our async handler."""
    def sync_callback(event):
        # Called from monitor thread; schedule work safely on the main event loop.
        try:
            command = str(event)
            if main_event_loop and main_event_loop.is_running():
                main_event_loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(process_execve_event(command))
                )
            else:
                print("⚠️ Main event loop not ready; dropping kernel event")
        except Exception as e:
            print(f"❌ Error processing kernel event: {e}")
    
    hook_manager.set_callback(sync_callback)


# Call this after app creation
_setup_kernel_callback()


# ==============================================================================
# Main Entry Point
# ==============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting AI Bouncer backend server...")
    print("   API: http://localhost:8000")
    print("   Docs: http://localhost:8000/docs")
    print("   WebSocket: ws://localhost:8000/ws")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
