from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Dict, Any


class NotificationResponse(BaseModel):
    id: str
    category: str
    title: str
    message: str
    timestamp: float
    read: bool
    session_id: Optional[str] = None


class ActivityNotificationRequest(BaseModel):
    type: str
    detail: Optional[str] = None


class EmailReportRequest(BaseModel):
    to_email: str
    provider: str = "gmail"
    department: Optional[str] = None
    include_json_attachment: bool = True
    session_token: Optional[str] = None


class EmailReportResponse(BaseModel):
    status: str
    message: str
    recipients: List[str]


class DepartmentEmailsResponse(BaseModel):
    departments: Dict[str, str]
