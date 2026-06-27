"""
Centralized configuration for Aegix backend.
All environment variables and settings are defined here using pydantic.
"""

import os
import secrets
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
import logging

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables and .env file.

    Example .env file:
        KERNEL_MONITOR_OWNER=backend
        API_HOST=0.0.0.0
        API_PORT=8000
        DB_PATH=data/events.db
        EVENT_CACHE_SIZE=1000
        LOG_LEVEL=info
        FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
        GROQ_API_KEY=gsk_...
        GROQ_MODEL=llama-3.3-70b-versatile
    """

    # Kernel monitoring ownership policy
    # Options: 'backend' (default), 'agent', 'disabled'
    kernel_monitor_owner: str = "backend"

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_log_level: str = "info"

    # Frontend origins (CORS)
    frontend_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Event storage
    db_path: str = ""  # Will default to project_root/data/events.db if empty
    # Optional database URL (Postgres). If set, backend will use this instead of SQLite.
    database_url: str = ""
    event_cache_size: int = 1000
    # Session (ephemeral) mode for demos
    session_mode: bool = False
    session_ttl: int = 3600  # seconds
    # Secret used to sign session tokens (HMAC). If empty, a random value is generated at startup.
    secret_key: str = ""

    # Agent settings
    backend_url: str = "http://localhost:8000"
    agent_event_timeout: int = 5

    # Gmail SMTP (reports & department routing)
    gmail_user: str = ""
    gmail_app_password: str = ""
    gmail_from_email: str = ""
    gmail_smtp_host: str = "smtp.gmail.com"
    gmail_smtp_port: int = 587
    # JSON map: {"SOC Operations":"soc@company.com","Security Engineering":"security@company.com"}
    department_emails: str = ""

    # Tier C — Groq LLM Settings
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    groq_timeout_seconds: int = 30

    # Chatbot — Gemini Settings
    gemini_api_key: str = ""
    gemini_chat_model: str = "gemini-flash-latest"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    def __init__(self, **data):
        """Initialize settings and resolve db_path if needed."""
        super().__init__(**data)

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # If db_path not set, default to project_root/data/events.db
        if not self.db_path:
            self.db_path = os.path.join(project_root, "data", "events.db")
        elif not os.path.isabs(self.db_path):
            # Ensure it is an absolute path to survive restarts across different working directories
            self.db_path = os.path.abspath(os.path.join(project_root, self.db_path))

        # Normalize database_url to empty string if not provided
        if not getattr(self, "database_url", None):
            self.database_url = ""

        # Ensure we have a secret key for signing session tokens
        if not getattr(self, "secret_key", None):
            secret_path = os.path.join(project_root, "data", ".session_secret")
            try:
                os.makedirs(os.path.dirname(secret_path), exist_ok=True)
                if os.path.exists(secret_path):
                    with open(secret_path, "r", encoding="utf-8") as f:
                        stored_secret = f.read().strip()
                    if stored_secret:
                        self.secret_key = stored_secret
                if not getattr(self, "secret_key", None):
                    self.secret_key = secrets.token_urlsafe(32)
                    with open(secret_path, "w", encoding="utf-8") as f:
                        f.write(self.secret_key)
            except Exception:
                logger.exception(
                    "Failed to load or persist session secret; generating ephemeral secret"
                )
                self.secret_key = secrets.token_urlsafe(32)

    @property
    def parsed_frontend_origins(self) -> list[str]:
        """Parse comma-separated frontend origins into a list."""
        origins = [
            origin.strip()
            for origin in self.frontend_origins.split(",")
            if origin.strip()
        ]
        if "*" in origins:
            logger.warning(
                "Wildcard '*' found in FRONTEND_ORIGINS. This is insecure for production."
            )
        return origins

    def validate_owner(self) -> str:
        """Validate and normalize kernel_monitor_owner."""
        owner = self.kernel_monitor_owner.lower()
        if owner not in ("backend", "agent", "disabled"):
            logger.warning(
                f"Invalid KERNEL_MONITOR_OWNER='{owner}', falling back to 'backend'"
            )
            return "backend"
        return owner


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get or create the global Settings instance.

    Returns:
        The global Settings object
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
