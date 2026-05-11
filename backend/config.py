"""
Centralized configuration for Aegix backend.
All environment variables and settings are defined here using pydantic.
"""

import os
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
    event_cache_size: int = 1000

    # Agent settings
    backend_url: str = "http://localhost:8000"
    agent_event_timeout: int = 5
    

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


    @property
    def parsed_frontend_origins(self) -> list[str]:
        """Parse comma-separated frontend origins into a list."""
        origins = [origin.strip() for origin in self.frontend_origins.split(",") if origin.strip()]
        if "*" in origins:
            logger.warning("Wildcard '*' found in FRONTEND_ORIGINS. This is insecure for production.")
        return origins

    def validate_owner(self) -> str:
        """Validate and normalize kernel_monitor_owner."""
        owner = self.kernel_monitor_owner.lower()
        if owner not in ("backend", "agent", "disabled"):
            logger.warning(f"Invalid KERNEL_MONITOR_OWNER='{owner}', falling back to 'backend'")
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
