"""
Event models and data structures for the security system.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional
import json


@dataclass
class ExecveEvent:
    """Event captured by eBPF execve hook."""
    pid: int
    ppid: int
    uid: int
    gid: int
    command: str
    argv_str: str
    timestamp: float
    comm: str  # Process name from kernel


@dataclass
class DetectionResult:
    """Result from the detection pipeline."""
    risk_score: float  # 0-100
    classification: str  # "safe", "suspicious", or "malicious"
    matched_rules: List[str]
    ml_confidence: float  # 0-1 probability from ML model
    explanation: Optional[str] = None


@dataclass
class SecurityEvent:
    """Combined event: eBPF capture + detection result."""
    id: str  # Unique event ID
    execve_event: ExecveEvent
    detection_result: DetectionResult
    detected_at: float  # When detection ran (Unix timestamp)

    def dict(self):
        """Convert to dict for JSON serialization."""
        return {
            "id": self.id,
            "pid": self.execve_event.pid,
            "ppid": self.execve_event.ppid,
            "uid": self.execve_event.uid,
            "gid": self.execve_event.gid,
            "command": self.execve_event.command,
            "argv_str": self.execve_event.argv_str,
            "timestamp": self.execve_event.timestamp,
            "comm": self.execve_event.comm,
            "risk_score": self.detection_result.risk_score,
            "classification": self.detection_result.classification,
            "matched_rules": self.detection_result.matched_rules,
            "ml_confidence": self.detection_result.ml_confidence,
            "explanation": self.detection_result.explanation,
            "detected_at": self.detected_at,
        }

    def json(self):
        """Convert to JSON string."""
        return json.dumps(self.dict())
