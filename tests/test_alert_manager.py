import pytest
import asyncio
from unittest.mock import patch, MagicMock
import os
import sqlite3

from backend.alerts.alert_manager import AlertManager
from backend.events.models import SecurityEvent, ExecveEvent, DetectionResult

import uuid

@pytest.fixture
def alert_manager():
    # Use unique db file for each test
    db_path = f"test_events_{uuid.uuid4().hex}.db"
    manager = AlertManager(db_path=db_path)
    yield manager
    if os.path.exists(db_path):
        import time
        time.sleep(0.1)
        try:
            os.remove(db_path)
        except Exception:
            pass

@pytest.mark.asyncio
async def test_alert_manager_dispatch_malicious(alert_manager):
    """Test that malicious events trigger the webhook."""
    webhook = alert_manager.add_webhook("http://example.com/webhook")
    
    execve_event = ExecveEvent(pid=1, ppid=2, uid=3, gid=4, command="rm -rf /", argv_str="rm -rf /", timestamp=123.4, comm="rm")
    detection_result = DetectionResult(classification="malicious", risk_score=95.0, matched_rules=["destructive"], ml_confidence=0.9, explanation="")
    event = SecurityEvent(id="evt_test", execve_event=execve_event, detection_result=detection_result, detected_at=123.5)
    
    with patch('backend.alerts.alert_manager.requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        await alert_manager.dispatch(event)
        
        assert mock_post.called
        assert mock_post.call_args[0][0] == "http://example.com/webhook"
        
        history = alert_manager.get_alert_history()
        assert len(history) == 1
        assert history[0].status == "success"

@pytest.mark.asyncio
async def test_alert_manager_dispatch_safe_ignored(alert_manager):
    """Test that safe events do not trigger webhooks."""
    alert_manager.add_webhook("http://example.com/webhook")
    
    execve_event = ExecveEvent(pid=1, ppid=2, uid=3, gid=4, command="ls", argv_str="ls", timestamp=123.4, comm="ls")
    detection_result = DetectionResult(classification="safe", risk_score=10.0, matched_rules=[], ml_confidence=0.1, explanation="")
    event = SecurityEvent(id="evt_test2", execve_event=execve_event, detection_result=detection_result, detected_at=123.5)
    
    with patch('backend.alerts.alert_manager.requests.post') as mock_post:
        await alert_manager.dispatch(event)
        assert not mock_post.called
        
        history = alert_manager.get_alert_history()
        assert len(history) == 0
