"""
Always-on agent runtime for Aegix.

The agent is the background process users keep running on an endpoint. On
Linux it can enable kernel capture through the existing backend bootstrap.
On macOS and Windows it falls back to API-only mode until a native endpoint
collector is added.
"""

from dataclasses import dataclass
from typing import Literal
import platform


RunMode = Literal["kernel", "api-only", "unsupported"]


@dataclass(frozen=True)
class AgentCapabilities:
    os_name: str
    run_mode: RunMode
    kernel_capture_supported: bool
    notes: str


def detect_capabilities() -> AgentCapabilities:
    """Return the supported mode for the current platform."""
    os_name = platform.system()

    if os_name == "Linux":
        return AgentCapabilities(
            os_name=os_name,
            run_mode="kernel",
            kernel_capture_supported=True,
            notes="Full kernel monitoring is available when BCC and kernel headers are installed.",
        )

    if os_name == "Darwin":
        return AgentCapabilities(
            os_name=os_name,
            run_mode="api-only",
            kernel_capture_supported=False,
            notes="macOS can run the backend/dashboard and manual analysis mode, but Linux eBPF kernel capture is not available.",
        )

    if os_name == "Windows":
        return AgentCapabilities(
            os_name=os_name,
            run_mode="api-only",
            kernel_capture_supported=False,
            notes="Windows can run the backend/dashboard and manual analysis mode; kernel capture remains Linux-only.",
        )

    return AgentCapabilities(
        os_name=os_name,
        run_mode="unsupported",
        kernel_capture_supported=False,
        notes="This platform is not explicitly supported yet.",
    )


def format_startup_message() -> str:
    """Return a human-readable startup summary for the agent."""
    capabilities = detect_capabilities()
    return (
        f"Aegix agent on {capabilities.os_name}: "
        f"mode={capabilities.run_mode}, "
        f"kernel_capture={capabilities.kernel_capture_supported}. "
        f"{capabilities.notes}"
    )
