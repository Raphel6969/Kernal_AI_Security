"""
Client bridge used by the always-on agent to forward endpoint events to the backend.
"""

from dataclasses import dataclass
import json
import os
from typing import Any, Optional
from urllib import error, request


@dataclass(frozen=True)
class AgentEventPayload:
    command: str
    pid: int = 0
    ppid: int = 0
    uid: int = 0
    gid: int = 0
    argv_str: Optional[str] = None
    comm: str = "agent"
    timestamp: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "gid": self.gid,
            "argv_str": self.argv_str or self.command,
            "comm": self.comm,
            "timestamp": self.timestamp,
        }


class BackendAgentClient:
    """Small HTTP client used by the agent to forward events."""

    def __init__(self, backend_url: str | None = None, timeout_seconds: float = 5.0):
        self.backend_url = (backend_url or os.getenv("AI_BOUNCER_BACKEND_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.timeout_seconds = timeout_seconds

    def submit_event(self, payload: AgentEventPayload) -> bool:
        data = json.dumps(payload.to_dict()).encode("utf-8")
        ingest_url = f"{self.backend_url}/agent/events"
        payload_request = request.Request(
            ingest_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(payload_request, timeout=self.timeout_seconds) as response:
                return 200 <= getattr(response, "status", 200) < 300
        except error.URLError as exc:
            print(f"⚠️  Failed to forward event to backend: {exc}")
            return False


def get_backend_agent_client() -> BackendAgentClient:
    return BackendAgentClient()
