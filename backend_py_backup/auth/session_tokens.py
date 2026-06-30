"""Session token utilities: create and verify signed session tokens.

Token format: <session_id>.<signature>
signature = base64url(hmac_sha256(secret_key, session_id))

This avoids needing external dependencies.
"""
import hmac
import hashlib
import base64
from typing import Optional

from backend.config import get_settings


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def create_session_token(session_id: str) -> str:
    settings = get_settings()
    key = settings.secret_key.encode("utf-8")
    sig = hmac.new(key, session_id.encode("utf-8"), hashlib.sha256).digest()
    return f"{session_id}.{_b64u(sig)}"


def verify_session_token(token: str) -> Optional[str]:
    """Verify token and return session_id if valid, otherwise None."""
    settings = get_settings()
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        session_id, sig_b64 = parts
        expected = hmac.new(
            settings.secret_key.encode("utf-8"),
            session_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        try:
            sig = _b64u_decode(sig_b64)
        except Exception:
            return None
        if hmac.compare_digest(expected, sig):
            return session_id
        return None
    except Exception:
        return None
