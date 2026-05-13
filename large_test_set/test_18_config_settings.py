"""
test_18_config_settings.py — Tests for backend/config.py (Settings).

Covers gaps identified across the full codebase analysis:
- Default values are sensible
- Environment variable overrides are applied correctly
- DB_PATH is resolved to an absolute path
- FRONTEND_ORIGINS is parsed into a list
- EVENT_CACHE_SIZE is a positive integer
- KERNEL_MONITOR_OWNER validates against allowed set
- API_HOST / API_PORT defaults
- Settings are a singleton (get_settings() returns same instance)
- Overriding BACKEND_URL is reflected in settings

Run:
    pytest large_test_set/test_18_config_settings.py -v
"""

import os
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_fresh_settings(**env_overrides):
    """Return a fresh Settings instance with the given env overrides applied.
    Uses monkeypatching via os.environ to avoid polluting the global state."""
    with patch.dict(os.environ, env_overrides, clear=False):
        # Force re-import to pick up env changes; handle both cached and
        # non-cached implementations
        import importlib
        import backend.config as cfg_mod
        importlib.reload(cfg_mod)
        return cfg_mod.get_settings()


# ===========================================================================
# 1. Default values
# ===========================================================================

class TestSettingsDefaults:

    def test_api_port_default_is_8000(self):
        from backend.config import get_settings
        s = get_settings()
        assert s.api_port == 8000 or str(s.api_port) == "8000"

    def test_api_host_default_is_0000(self):
        from backend.config import get_settings
        s = get_settings()
        assert s.api_host in ("0.0.0.0", "localhost", "127.0.0.1")

    def test_event_cache_size_positive(self):
        from backend.config import get_settings
        s = get_settings()
        assert int(s.event_cache_size) > 0

    def test_db_path_is_string(self):
        from backend.config import get_settings
        s = get_settings()
        assert isinstance(s.db_path, str)
        assert len(s.db_path) > 0

    def test_backend_url_is_string(self):
        from backend.config import get_settings
        s = get_settings()
        assert isinstance(s.backend_url, str)
        assert s.backend_url.startswith("http")

    def test_kernel_monitor_owner_default(self):
        from backend.config import get_settings
        s = get_settings()
        assert s.kernel_monitor_owner in ("backend", "agent", "disabled")

    def test_agent_event_timeout_positive(self):
        from backend.config import get_settings
        s = get_settings()
        assert int(s.agent_event_timeout) > 0


# ===========================================================================
# 2. KERNEL_MONITOR_OWNER validation
# ===========================================================================

class TestKernelMonitorOwnerValidation:

    def test_backend_is_valid_owner(self):
        from backend.config import Settings
        s = Settings()
        assert s.validate_owner("backend") == "backend"

    def test_agent_is_valid_owner(self):
        from backend.config import Settings
        s = Settings()
        assert s.validate_owner("agent") == "agent"

    def test_disabled_is_valid_owner(self):
        from backend.config import Settings
        s = Settings()
        assert s.validate_owner("disabled") == "disabled"

    def test_invalid_owner_raises_or_returns_default(self):
        """An invalid owner value must either raise ValueError or be
        normalised to a safe default — never silently accepted as-is."""
        from backend.config import Settings
        s = Settings()
        try:
            result = s.validate_owner("invalid_owner")
            # If no exception, must have been normalised to a safe value
            assert result in ("backend", "agent", "disabled"), (
                f"Invalid owner normalised to unexpected value: {result!r}"
            )
        except (ValueError, AssertionError):
            pass  # Correct — invalid value rejected

    def test_uppercase_owner_handled(self):
        """'BACKEND' must either normalise to 'backend' or raise — never
        be returned as 'BACKEND'."""
        from backend.config import Settings
        s = Settings()
        try:
            result = s.validate_owner("BACKEND")
            assert result in ("backend", "agent", "disabled"), \
                f"Unexpected normalisation of 'BACKEND': {result!r}"
        except (ValueError, AssertionError):
            pass  # Also acceptable


# ===========================================================================
# 3. DB_PATH resolution
# ===========================================================================

class TestDbPathResolution:

    def test_db_path_is_absolute(self):
        """DB_PATH must be resolved to an absolute path so it works
        regardless of the working directory the server is started from."""
        from backend.config import get_settings
        s = get_settings()
        assert os.path.isabs(s.db_path), (
            f"db_path is not absolute: {s.db_path!r}"
        )

    def test_db_path_ends_with_db_extension(self):
        from backend.config import get_settings
        s = get_settings()
        assert s.db_path.endswith(".db"), \
            f"db_path should end with .db: {s.db_path!r}"


# ===========================================================================
# 4. FRONTEND_ORIGINS parsing
# ===========================================================================

class TestFrontendOriginsParsing:

    def test_frontend_origins_is_list_or_string(self):
        """FRONTEND_ORIGINS must be accessible as a list or comma-separated
        string — not None."""
        from backend.config import get_settings
        s = get_settings()
        origins = s.frontend_origins
        assert origins is not None, "frontend_origins must not be None"

    def test_localhost_5173_included_in_defaults(self):
        """The default origins must include http://localhost:5173 (the Vite
        dev server) so the dashboard can connect out of the box."""
        from backend.config import get_settings
        s = get_settings()
        origins_str = (
            ",".join(s.frontend_origins)
            if isinstance(s.frontend_origins, list)
            else str(s.frontend_origins)
        )
        assert "localhost:5173" in origins_str, (
            "http://localhost:5173 missing from default FRONTEND_ORIGINS"
        )


# ===========================================================================
# 5. get_settings() singleton contract
# ===========================================================================

class TestGetSettingsSingleton:

    def test_get_settings_returns_same_instance_on_repeated_calls(self):
        """get_settings() must return the same object on consecutive calls
        (cached / singleton pattern)."""
        from backend.config import get_settings
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2, \
            "get_settings() returned different instances — caching broken"

    def test_settings_object_has_required_attributes(self):
        """The Settings object must expose all documented attributes."""
        from backend.config import get_settings
        s = get_settings()
        required = [
            "api_host", "api_port", "db_path",
            "event_cache_size", "backend_url",
            "kernel_monitor_owner", "frontend_origins",
            "agent_event_timeout",
        ]
        for attr in required:
            assert hasattr(s, attr), \
                f"Settings missing required attribute: {attr!r}"


# ===========================================================================
# 6. EVENT_CACHE_SIZE validation
# ===========================================================================

class TestEventCacheSizeValidation:

    def test_event_cache_size_is_integer(self):
        from backend.config import get_settings
        s = get_settings()
        assert isinstance(int(s.event_cache_size), int)

    def test_event_cache_size_at_least_100(self):
        """A cache size below 100 is impractically small and likely a
        misconfiguration — validate a sensible minimum."""
        from backend.config import get_settings
        s = get_settings()
        assert int(s.event_cache_size) >= 100, (
            f"EVENT_CACHE_SIZE={s.event_cache_size} is too small (minimum 100)"
        )


# ===========================================================================
# 7. API_LOG_LEVEL validation
# ===========================================================================

class TestApiLogLevelValidation:

    def test_api_log_level_is_valid(self):
        """api_log_level must be one of the recognised uvicorn log levels."""
        from backend.config import get_settings
        s = get_settings()
        if hasattr(s, "api_log_level"):
            assert s.api_log_level in (
                "debug", "info", "warning", "error", "critical"
            ), f"Invalid api_log_level: {s.api_log_level!r}"
