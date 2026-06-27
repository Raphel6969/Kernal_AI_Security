"""Gmail SMTP report delivery with JSON log attachment."""

import json
import logging
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from backend.config import get_settings

logger = logging.getLogger(__name__)


def get_department_map() -> Dict[str, str]:
    """Parse DEPARTMENT_EMAILS JSON from settings."""
    settings = get_settings()
    raw = getattr(settings, "department_emails", "") or ""
    if not raw.strip():
        return {
            "SOC Operations": "soc@yourcompany.com",
            "Security Engineering": "security@yourcompany.com",
            "Incident Response": "ir@yourcompany.com",
        }
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except json.JSONDecodeError:
        logger.warning("Invalid DEPARTMENT_EMAILS JSON; using defaults")
    return {}


def build_report_summary(stats: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
    total = stats.get("total_events", len(events))
    safe = stats.get("safe", 0)
    suspicious = stats.get("suspicious", 0)
    malicious = stats.get("malicious", 0)
    avg_risk = 0.0
    if events:
        avg_risk = sum(float(e.get("risk_score", 0)) for e in events) / len(events)

    lines = [
        "AEGIX Security — Session Report",
        "================================",
        "",
        f"Total events analyzed: {total}",
        f"  Safe:        {safe}",
        f"  Suspicious:  {suspicious}",
        f"  Malicious:   {malicious}",
        f"Average risk score: {avg_risk:.1f} / 100",
        "",
    ]

    if malicious > 0:
        lines.append("Top malicious commands:")
        shown = 0
        for ev in events:
            if ev.get("classification") == "malicious" and shown < 5:
                cmd = str(ev.get("command", ""))[:120]
                lines.append(f"  • [{ev.get('risk_score', 0):.0f}] {cmd}")
                shown += 1
        lines.append("")

    lines.append("Full event payload is attached as JSON (aegix_events.json).")
    lines.append("")
    lines.append("— Aegix Kernel Guard")
    return "\n".join(lines)


def send_gmail_report(
    *,
    to_emails: List[str],
    subject: str,
    body_text: str,
    json_payload: Any,
    cc_emails: Optional[List[str]] = None,
) -> None:
    settings = get_settings()
    gmail_user = getattr(settings, "gmail_user", "") or ""
    gmail_password = getattr(settings, "gmail_app_password", "") or ""
    from_email = getattr(settings, "gmail_from_email", "") or gmail_user

    if not gmail_user or not gmail_password:
        raise ValueError(
            "Gmail is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD in .env "
            "(use a Google App Password for SMTP)."
        )

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = ", ".join(to_emails)
    if cc_emails:
        msg["Cc"] = ", ".join(cc_emails)
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain", "utf-8"))

    attachment = MIMEApplication(
        json.dumps(json_payload, indent=2, default=str).encode("utf-8"),
        Name="aegix_events.json",
    )
    attachment["Content-Disposition"] = 'attachment; filename="aegix_events.json"'
    msg.attach(attachment)

    smtp_host = getattr(settings, "gmail_smtp_host", "smtp.gmail.com")
    smtp_port = int(getattr(settings, "gmail_smtp_port", 587))

    recipients = list(to_emails)
    if cc_emails:
        recipients.extend(cc_emails)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(gmail_user, gmail_password)
        server.sendmail(from_email, recipients, msg.as_string())

    logger.info("Report email sent to %s", to_emails)
