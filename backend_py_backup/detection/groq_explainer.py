"""
Tier C — Groq LLM explainer for detailed human-readable command analysis.
On-demand only; never blocks the detection pipeline.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import requests

from backend.config import get_settings

logger = logging.getLogger(__name__)

GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"

SYSTEM_PROMPT = """You are AEGIX Tier C, an expert Linux security analyst embedded in a kernel-level RCE prevention system.

When given a shell command and detection context, write a clear, authoritative briefing for a SOC analyst. Be specific and practical — no filler.

Structure your response with these exact section headers (use markdown bold for headers):

**What this command does**
Plain-language breakdown of each part of the command and its intended effect on the system.

**Attack objective**
What an adversary is trying to achieve (e.g. reverse shell, credential theft, persistence, lateral movement, data exfiltration). If benign, state that clearly.

**Threat pattern**
Name the attack technique, map to MITRE ATT&CK where applicable, and relate to any matched detection rules provided.

**Risk assessment**
Explain why the cascade verdict (safe / suspicious / malicious) and risk score make sense given the command behavior.

**Recommended action**
Concrete next steps: block, kill process, isolate host, investigate parent process, rotate credentials, etc.

Keep the tone professional and direct. Do not repeat the raw command more than once. Do not invent PID or host details not provided."""

_llm_cache: dict[str, str] = {}


def get_cached_llm_explanation(event_id: str) -> Optional[str]:
    return _llm_cache.get(event_id)


def _build_user_prompt(
    command: str,
    *,
    classification: str,
    risk_score: float,
    matched_rules: list[str],
    ml_confidence: float,
    pid: Optional[int] = None,
    ppid: Optional[int] = None,
    uid: Optional[int] = None,
    baseline_explanation: Optional[str] = None,
) -> str:
    rules = ", ".join(matched_rules) if matched_rules else "none"
    ctx = [
        f"Command: {command}",
        f"Verdict: {classification.upper()}",
        f"Risk score: {risk_score:.1f}/100",
        f"Matched rules: {rules}",
        f"ML confidence: {ml_confidence * 100:.1f}%",
    ]
    if pid is not None:
        ctx.append(f"PID: {pid}")
    if ppid is not None:
        ctx.append(f"PPID: {ppid}")
    if uid is not None:
        ctx.append(f"UID: {uid}")
    if baseline_explanation:
        ctx.append(f"Tier A/B summary: {baseline_explanation}")
    return "\n".join(ctx)


def _call_groq_sync(
    command: str,
    *,
    classification: str,
    risk_score: float,
    matched_rules: list[str],
    ml_confidence: float,
    pid: Optional[int] = None,
    ppid: Optional[int] = None,
    uid: Optional[int] = None,
    baseline_explanation: Optional[str] = None,
) -> str:
    settings = get_settings()
    api_key = settings.groq_api_key.strip()
    if not api_key:
        raise ValueError(
            "GROQ_API_KEY is not configured. Add it to your .env file to enable Tier C explanations."
        )

    user_content = _build_user_prompt(
        command,
        classification=classification,
        risk_score=risk_score,
        matched_rules=matched_rules,
        ml_confidence=ml_confidence,
        pid=pid,
        ppid=ppid,
        uid=uid,
        baseline_explanation=baseline_explanation,
    )

    payload: dict[str, Any] = {
        "model": settings.groq_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.3,
        "max_tokens": 1024,
    }

    response = requests.post(
        GROQ_CHAT_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=settings.groq_timeout_seconds,
    )

    if not response.ok:
        detail = response.text[:500]
        logger.error("Groq API error %s: %s", response.status_code, detail)
        raise RuntimeError(f"Groq API request failed ({response.status_code})")

    data = response.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("Groq API returned an empty response")

    content = choices[0].get("message", {}).get("content", "").strip()
    if not content:
        raise RuntimeError("Groq API returned empty explanation text")
    return content


async def generate_llm_explanation(
    command: str,
    *,
    classification: str,
    risk_score: float,
    matched_rules: list[str],
    ml_confidence: float,
    pid: Optional[int] = None,
    ppid: Optional[int] = None,
    uid: Optional[int] = None,
    baseline_explanation: Optional[str] = None,
    event_id: Optional[str] = None,
    force: bool = False,
) -> str:
    """Generate (or return cached) Groq explanation for a command."""
    if event_id and not force:
        cached = get_cached_llm_explanation(event_id)
        if cached:
            return cached

    explanation = await asyncio.to_thread(
        _call_groq_sync,
        command,
        classification=classification,
        risk_score=risk_score,
        matched_rules=matched_rules,
        ml_confidence=ml_confidence,
        pid=pid,
        ppid=ppid,
        uid=uid,
        baseline_explanation=baseline_explanation,
    )

    if event_id:
        _llm_cache[event_id] = explanation
    return explanation
