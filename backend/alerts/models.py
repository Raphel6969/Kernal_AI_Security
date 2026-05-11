from pydantic import BaseModel
from typing import Optional

class WebhookCreate(BaseModel):
    url: str
    trigger_safe: bool = False
    trigger_suspicious: bool = False
    trigger_malicious: bool = True

class WebhookResponse(BaseModel):
    id: str
    url: str
    is_active: bool
    created_at: float
    trigger_safe: bool
    trigger_suspicious: bool
    trigger_malicious: bool

class AlertHistoryResponse(BaseModel):
    id: str
    event_id: str
    url: str
    status: str
    timestamp: float
