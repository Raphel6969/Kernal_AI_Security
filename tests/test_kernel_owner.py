import pytest
import asyncio
import os
from unittest.mock import patch, MagicMock
from backend.agent.runtime import AgentCapabilities


@pytest.mark.asyncio
async def test_agent_respects_owner_backend_no_local_start():
    """When KERNEL_MONITOR_OWNER=backend and monitor not running, agent should not start monitor."""
    with patch("backend.agent.main.detect_capabilities") as mock_detect, \
         patch("backend.config.Settings.validate_owner", return_value="backend"):
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
async def test_agent_sets_callback_when_monitor_running():
    """If a monitor is already running in-process, agent should register callback via set_callback."""
    with patch("backend.agent.main.detect_capabilities") as mock_detect, \
         patch("backend.config.Settings.validate_owner", return_value="backend"):
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
async def test_agent_starts_when_owner_agent():
    """When KERNEL_MONITOR_OWNER=agent and no monitor running, agent should start local monitor."""
    with patch("backend.agent.main.detect_capabilities") as mock_detect, \
         patch("backend.config.Settings.validate_owner", return_value="agent"):
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


@pytest.mark.asyncio
async def test_agent_respects_owner_disabled():
    """When KERNEL_MONITOR_OWNER=disabled, agent should not start monitor or register callback."""
    with patch("backend.agent.main.detect_capabilities") as mock_detect, \
         patch("backend.config.Settings.validate_owner", return_value="disabled"):
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
async def test_agent_thread_safe_queue_handoff():
    """Test that on_event callback successfully enqueues an event and it gets forwarded."""
    with patch("backend.agent.main.detect_capabilities") as mock_detect, \
         patch("backend.agent.main.requests.post") as mock_post, \
         patch("backend.config.Settings.validate_owner", return_value="agent"):
        
        mock_detect.return_value = AgentCapabilities("Linux", "kernel", True, "mock")
        mock_post.return_value = MagicMock(status_code=200)
        mock_post.return_value.json.return_value = {"classification": "safe"}

        import sys
        mock_kernel_module = MagicMock()
        mock_manager = MagicMock()
        mock_manager.monitor = MagicMock()
        mock_manager.monitor.running = False
        mock_kernel_module.get_hook_manager.return_value = mock_manager
        sys.modules['backend.kernel.execve_hook'] = mock_kernel_module

        try:
            from backend.agent.main import agent_event_loop
            from backend.events.models import ExecveEvent
            
            task = asyncio.create_task(agent_event_loop())
            await asyncio.sleep(0.1)

            # Get the registered callback
            assert mock_manager.start.called
            on_event_cb = mock_manager.start.call_args[0][0]

            # Trigger the callback
            mock_event = ExecveEvent(
                pid=123, ppid=1, uid=0, gid=0, command="ls", argv_str="ls", timestamp=1.0, comm="bash"
            )
            on_event_cb(mock_event)

            # Let the loop process the queue
            await asyncio.sleep(0.1)

            # Check if requests.post was called
            assert mock_post.called
            called_json = mock_post.call_args[1]['json']
            assert called_json['pid'] == 123
            assert called_json['command'] == "ls"

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        finally:
            del sys.modules['backend.kernel.execve_hook']
