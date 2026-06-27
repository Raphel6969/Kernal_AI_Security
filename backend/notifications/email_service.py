"""Gmail SMTP report delivery with JSON/CSV logs and HTML presentation."""

import csv
import io
import json
import logging
import smtplib
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from backend.config import get_settings

logger = logging.getLogger(__name__)


def get_department_map() -> Dict[str, str]:
    """Retrieve departments map dynamically from NotificationStore SQLite table."""
    try:
        from backend.notifications.notification_store import get_notification_store
        return get_notification_store().list_departments()
    except Exception as exc:
        logger.error("Failed to load departments from DB: %s", exc)
        return {
            "SOC Operations": "soc@yourcompany.com",
            "Security Engineering": "security@yourcompany.com",
            "Incident Response": "ir@yourcompany.com",
        }


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

    lines.append("Report attachment is enclosed.")
    lines.append("")
    lines.append("— Aegix Kernel Guard")
    return "\n".join(lines)


def build_csv_attachment(events: List[Dict[str, Any]]) -> str:
    """Convert events list to a CSV formatted string."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow([
        "ID", "Time", "PID", "PPID", "UID", "Command", "Severity", "Risk Score", "Matched Rules", "ML Confidence"
    ])
    
    for ev in events:
        detected_at = ev.get("detected_at", 0)
        time_str = ""
        if detected_at:
            time_str = datetime.fromtimestamp(detected_at).strftime("%Y-%m-%d %H:%M:%S")
            
        rules = ", ".join(ev.get("matched_rules", [])) if isinstance(ev.get("matched_rules"), list) else str(ev.get("matched_rules", ""))
        ml_conf = ev.get("ml_confidence", 0.0)
        ml_conf_str = f"{ml_conf * 100:.1f}%" if ml_conf else "0.0%"
            
        writer.writerow([
            ev.get("id", ""),
            time_str,
            ev.get("pid", ""),
            ev.get("ppid", ""),
            ev.get("uid", ""),
            ev.get("command", ""),
            ev.get("classification", "safe"),
            ev.get("risk_score", 0.0),
            rules,
            ml_conf_str
        ])
    
    return output.getvalue()


def build_html_email_summary(stats: Dict[str, Any], events: List[Dict[str, Any]]) -> str:
    """Returns a beautifully styled HTML report summary matching the Aegix cybersec theme."""
    total = stats.get("total_events", len(events))
    safe = stats.get("safe", 0)
    suspicious = stats.get("suspicious", 0)
    malicious = stats.get("malicious", 0)
    avg_risk = 0.0
    if events:
        avg_risk = sum(float(e.get("risk_score", 0)) for e in events) / len(events)
        
    malicious_rows = []
    for ev in events:
        if ev.get("classification") == "malicious":
            cmd = str(ev.get("command", ""))[:120]
            score = ev.get("risk_score", 0) or 0.0
            malicious_rows.append(
                f'<tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.05);">'
                f'<td style="padding: 12px 8px; font-family: monospace; color: #ff4d4d; font-weight: bold; font-size: 13px; width: 60px;">[{score:.0f}]</td>'
                f'<td style="padding: 12px 8px; font-family: monospace; color: #e2e8f0; font-size: 12px; word-break: break-all; line-height: 1.4;">'
                f'<code style="background-color: #080c14; border: 1px solid rgba(255, 255, 255, 0.05); padding: 4px 6px; border-radius: 4px; display: block; white-space: pre-wrap;">{cmd}</code>'
                f'</td>'
                f'</tr>'
            )
            if len(malicious_rows) >= 5:
                break
                
    malicious_section = ""
    if malicious_rows:
        malicious_section = f"""
        <h3 style="color: #ff4d4d; margin-top: 28px; font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 8px; font-family: 'Outfit', sans-serif;">Top Malicious Commands</h3>
        <table style="width: 100%; border-collapse: collapse; margin-top: 8px; border: 1px solid rgba(255,255,255,0.05); border-radius: 6px; overflow: hidden; background-color: rgba(0,0,0,0.15);">
          {"".join(malicious_rows)}
        </table>
        """

    # Determine risk pill color
    pill_color = "#ff4d4d" if avg_risk >= 70 else "#ffaa00" if avg_risk >= 30 else "#00ff9d"
    pill_text = "HIGH RISK" if avg_risk >= 70 else "ELEVATED" if avg_risk >= 30 else "SECURE"
    glow_shadow = "rgba(255, 77, 77, 0.2)" if avg_risk >= 70 else "rgba(255, 170, 0, 0.15)" if avg_risk >= 30 else "rgba(0, 255, 157, 0.15)"

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AEGIX Security Report</title>
</head>
<body style="margin: 0; padding: 0; background-color: #080c14; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #94a3b8;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #080c14; padding: 40px 20px;">
    <tr>
      <td align="center">
        <!-- Main Card Wrapper -->
        <table width="600" border="0" cellspacing="0" cellpadding="0" style="background-color: #0d1426; border: 1px solid rgba(0, 210, 255, 0.15); border-radius: 12px; overflow: hidden; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5), 0 0 40px rgba(0, 210, 255, 0.05);">
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #0a0f1d, #0d1426); padding: 32px 24px; text-align: center; border-bottom: 1px solid rgba(0, 210, 255, 0.15);">
              <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 800; letter-spacing: 2px; font-family: 'Outfit', sans-serif; text-shadow: 0 0 15px rgba(0, 210, 255, 0.35);">AEGIX SECURITY SUMMARY</h1>
              <p style="margin: 6px 0 0 0; color: #00d2ff; font-size: 11px; text-transform: uppercase; letter-spacing: 2px; font-weight: 600;">Kernel Level RCE Interceptor</p>
            </td>
          </tr>
          <!-- Content Body -->
          <tr>
            <td style="padding: 32px 24px;">
              <h2 style="margin-top: 0; font-size: 16px; color: #ffffff; margin-bottom: 8px; letter-spacing: 0.5px;">Session Log Audit Report</h2>
              <p style="font-size: 13.5px; color: #94a3b8; line-height: 1.6; margin-top: 0; margin-bottom: 24px;">
                The Aegix daemon has completed event analysis for the active session. The security metrics and critical command warnings are summarized below.
              </p>
              
              <!-- Stats Cards Grid -->
              <table width="100%" border="0" cellspacing="8" cellpadding="0" style="margin-bottom: 24px;">
                <tr>
                  <td width="25%" align="center" style="background-color: #080c14; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 16px 12px;">
                    <span style="font-size: 9px; color: #64748b; display: block; text-transform: uppercase; font-weight: bold; letter-spacing: 0.5px;">Total</span>
                    <strong style="font-size: 24px; color: #ffffff; display: block; margin-top: 6px; font-family: 'Courier New', Courier, monospace;">{total}</strong>
                  </td>
                  <td width="25%" align="center" style="background-color: #080c14; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 16px 12px;">
                    <span style="font-size: 9px; color: #00ff9d; display: block; text-transform: uppercase; font-weight: bold; letter-spacing: 0.5px;">Safe</span>
                    <strong style="font-size: 24px; color: #00ff9d; display: block; margin-top: 6px; font-family: 'Courier New', Courier, monospace;">{safe}</strong>
                  </td>
                  <td width="25%" align="center" style="background-color: #080c14; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 16px 12px;">
                    <span style="font-size: 9px; color: #ffaa00; display: block; text-transform: uppercase; font-weight: bold; letter-spacing: 0.5px;">Suspicious</span>
                    <strong style="font-size: 24px; color: #ffaa00; display: block; margin-top: 6px; font-family: 'Courier New', Courier, monospace;">{suspicious}</strong>
                  </td>
                  <td width="25%" align="center" style="background-color: #080c14; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 16px 12px;">
                    <span style="font-size: 9px; color: #ff4d4d; display: block; text-transform: uppercase; font-weight: bold; letter-spacing: 0.5px;">Malicious</span>
                    <strong style="font-size: 24px; color: #ff4d4d; display: block; margin-top: 6px; font-family: 'Courier New', Courier, monospace;">{malicious}</strong>
                  </td>
                </tr>
              </table>

              <!-- Average Risk Summary Card (Glow Accent) -->
              <div style="background-color: rgba(0, 210, 255, 0.03); border: 1px solid rgba(0, 210, 255, 0.15); border-radius: 8px; padding: 18px; margin-bottom: 24px; box-shadow: inset 0 0 12px rgba(0, 210, 255, 0.02);">
                <table width="100%" border="0" cellspacing="0" cellpadding="0">
                  <tr>
                    <td>
                      <span style="font-size: 10px; color: #00d2ff; text-transform: uppercase; font-weight: 700; letter-spacing: 1px; display: block;">System Risk Rating</span>
                      <strong style="font-size: 22px; color: #ffffff; display: block; margin-top: 6px; font-family: 'Outfit', sans-serif;">{avg_risk:.1f} <span style="font-size: 13px; color: #64748b;">/ 100</span></strong>
                    </td>
                    <td align="right" valign="middle">
                      <span style="padding: 8px 16px; border-radius: 4px; font-size: 11px; font-weight: bold; background-color: {pill_color}; color: #080c14; display: inline-block; letter-spacing: 1px; box-shadow: 0 0 10px {glow_shadow};">
                        {pill_text}
                      </span>
                    </td>
                  </tr>
                </table>
              </div>

              {malicious_section}

              <p style="font-size: 11px; color: #475569; margin-top: 36px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 20px; text-align: center; margin-bottom: 0;">
                Generated by **Aegix System Engine** • Secure Kernel Monitoring
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
    return html


def send_gmail_report(
    *,
    to_emails: List[str],
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
    attachment_content: Optional[bytes] = None,
    attachment_filename: Optional[str] = None,
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

    msg = MIMEMultipart("mixed")
    msg["From"] = from_email
    msg["To"] = ", ".join(to_emails)
    if cc_emails:
        msg["Cc"] = ", ".join(cc_emails)
    msg["Subject"] = subject

    # Create body parts (Plain text fallback and HTML)
    msg_body = MIMEMultipart("alternative")
    msg_body.attach(MIMEText(body_text, "plain", "utf-8"))
    if body_html:
        msg_body.attach(MIMEText(body_html, "html", "utf-8"))
    msg.attach(msg_body)

    # Attach file if provided
    if attachment_content is not None and attachment_filename is not None:
        attachment = MIMEApplication(
            attachment_content,
            Name=attachment_filename,
        )
        attachment["Content-Disposition"] = f'attachment; filename="{attachment_filename}"'
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
