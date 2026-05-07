import pytest
import asyncio
import os
from unittest.mock import patch, MagicMock
from backend.agent.runtime import AgentCapabilities


@pytest.mark.asyncio
async def test_agent_respects_owner_backend_no_local_start(monkeypatch):
    """When KERNEL_MONITOR_OWNER=backend and monitor not running, agent should not start monitor."""
    monkeypatch.setenv("KERNEL_MONITOR_OWNER", "backend")

    with patch("backend.agent.main.detect_capabilities") as mock_detect:
        mock_detect.return_value = AgentCapabilities("Linux", "kernel", True, "mock")

        import sys
        mock_kernel_module = MagicMock()
        mock_manager = MagicMock()
        # simulate monitor not running
        mock_manager.monitor = MagicMock()
        mock_manager.monitor.running = False
        mock_kernel_module.get_hook_manager.return_value = mock_manager
        sys.modules['backend.kernel.execve_hook'] = mock_kernel_module

        try:
            from backend.agent.main import agent_event_loop
            task = asyncio.create_task(agent_event_loop())
            await asyncio.sleep(0.1)

            # Agent should NOT start the monitor when backend is the owner and monitor isn't running here
            assert not mock_manager.start.called
            assert not mock_manager.set_callback.called

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        finally:
            del sys.modules['backend.kernel.execve_hook']


@pytest.mark.asyncio
async def test_agent_sets_callback_when_monitor_running(monkeypatch):
    """If a monitor is already running in-process, agent should register callback via set_callback."""
    monkeypatch.setenv("KERNEL_MONITOR_OWNER", "backend")

    with patch("backend.agent.main.detect_capabilities") as mock_detect:
        mock_detect.return_value = AgentCapabilities("Linux", "kernel", True, "mock")

        import sys
        mock_kernel_module = MagicMock()
        mock_manager = MagicMock()
        # simulate monitor already running in this process
        mock_manager.monitor = MagicMock()
        mock_manager.monitor.running = True
        mock_kernel_module.get_hook_manager.return_value = mock_manager
        sys.modules['backend.kernel.execve_hook'] = mock_kernel_module

        try:
            from backend.agent.main import agent_event_loop
            task = asyncio.create_task(agent_event_loop())
            await asyncio.sleep(0.1)

            # When monitor is running, agent should call set_callback
            assert mock_manager.set_callback.called

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        finally:
            del sys.modules['backend.kernel.execve_hook']


@pytest.mark.asyncio
async def test_agent_starts_when_owner_agent(monkeypatch):
    """When KERNEL_MONITOR_OWNER=agent and no monitor running, agent should start local monitor."""
    monkeypatch.setenv("KERNEL_MONITOR_OWNER", "agent")

    with patch("backend.agent.main.detect_capabilities") as mock_detect:
        mock_detect.return_value = AgentCapabilities("Linux", "kernel", True, "mock")

        import sys
        mock_kernel_module = MagicMock()
        mock_manager = MagicMock()
        mock_manager.monitor = MagicMock()
        mock_manager.monitor.running = False
        mock_kernel_module.get_hook_manager.return_value = mock_manager
        sys.modules['backend.kernel.execve_hook'] = mock_kernel_module

        try:
            from backend.agent.main import agent_event_loop
            task = asyncio.create_task(agent_event_loop())
            await asyncio.sleep(0.1)

            assert mock_manager.start.called

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        finally:
            del sys.modules['backend.kernel.execve_hook']
