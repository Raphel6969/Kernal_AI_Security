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

from fastapi import FastAPI, WebSocket, HTTPException
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

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (restrict in production)
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

# ==============================================================================
# Startup & Shutdown
# ==============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize backend systems on startup."""
    print("🚀 Starting AI Bouncer backend...")
    
    # Start kernel monitoring
    try:
        hook_manager.start()
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
    
    # Run detection pipeline
    result = pipeline.detect(request.command)

    # Build a minimal ExecveEvent for UI purposes (kernel fields unknown here)
    execve_event = ExecveEvent(
        pid=0,
        ppid=0,
        uid=0,
        gid=0,
        command=request.command,
        argv_str=request.command,
        timestamp=datetime.now().timestamp(),
        comm="api",
    )

    # Create SecurityEvent and store/broadcast it
    security_event = SecurityEvent(
        id=f"evt_{uuid.uuid4().hex[:8]}",
        execve_event=execve_event,
        detection_result=result,
        detected_at=datetime.now().timestamp(),
    )

    # Store event in memory
    event_store.append(security_event)

    # Broadcast asynchronously to WebSocket clients
    try:
        asyncio.create_task(broadcast_event(security_event))
    except Exception as e:
        print(f"⚠️ Failed to schedule broadcast: {e}")

    return CommandAnalysisResponse(
        command=request.command,
        classification=result.classification,
        risk_score=result.risk_score,
        matched_rules=result.matched_rules,
        ml_confidence=result.ml_confidence,
        explanation=result.explanation,
    )


@app.get("/events")
async def get_events(limit: int = 100):
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
    active_websockets.add(websocket)
    
    try:
        print(f"📡 WebSocket client connected ({len(active_websockets)} active)")
        
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
        active_websockets.discard(websocket)
        print(f"📡 WebSocket client disconnected ({len(active_websockets)} active)")


async def broadcast_event(event: SecurityEvent):
    """
    Broadcast a security event to all connected WebSocket clients.
    
    Args:
        event: SecurityEvent to broadcast
    """
    dead_connections = set()
    
    for websocket in active_websockets:
        try:
            await websocket.send_json(event.dict())
        except Exception as e:
            print(f"⚠️  Failed to send event to client: {e}")
            dead_connections.add(websocket)
    
    # Cleanup dead connections
    for ws in dead_connections:
        active_websockets.discard(ws)


# ==============================================================================
# Event Processing Callback
# ==============================================================================

async def process_execve_event(command: str):
    """
    Process an execve event from the kernel.
    
    Args:
        command: The command that was executed
    """
    # Create ExecveEvent
    execve_event = ExecveEvent(
        pid=0,  # Will be filled by eBPF in Phase 2
        ppid=0,
        uid=0,
        gid=0,
        command=command,
        argv_str=command,
        timestamp=datetime.now().timestamp(),
        comm="",
    )
    
    # Run detection
    detection_result = pipeline.detect(command)
    
    # Create SecurityEvent
    security_event = SecurityEvent(
        id=f"evt_{uuid.uuid4().hex[:8]}",
        execve_event=execve_event,
        detection_result=detection_result,
        detected_at=datetime.now().timestamp(),
    )
    
    # Store event
    event_store.append(security_event)
    
    # Broadcast to WebSocket clients
    await broadcast_event(security_event)


# Set the kernel monitor callback
def _setup_kernel_callback():
    """Setup the kernel monitor to call our async handler."""
    def sync_callback(event):
        # This will be called from the kernel monitor thread
        # We need to run the async function in the event loop
        try:
            asyncio.create_task(process_execve_event(str(event)))
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
