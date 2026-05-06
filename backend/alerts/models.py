from pydantic import BaseModel
from typing import Optional

class WebhookCreate(BaseModel):
    url: str

class WebhookResponse(BaseModel):
    id: str
    url: str
    is_active: bool
    created_at: float

class AlertHistoryResponse(BaseModel):
    id: str
    event_id: str
    url: str
    status: str
    timestamp: float
