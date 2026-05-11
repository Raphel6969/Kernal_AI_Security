import pytest
import asyncio
from unittest.mock import patch, MagicMock
from backend.agent.main import agent_event_loop
from backend.agent.runtime import AgentCapabilities
from backend.events.models import ExecveEvent
from backend.agent.main import settings

@pytest.mark.asyncio
async def test_agent_main_api_only():
    """Test that agent idles in api-only mode."""
    with patch("backend.agent.main.detect_capabilities") as mock_detect:
        mock_detect.return_value = AgentCapabilities("Windows", "api-only", False, "mock")
        
        task = asyncio.create_task(agent_event_loop())
        
        # It should run fine without crashing for a bit
        done, pending = await asyncio.wait([task], timeout=0.1)
        assert not done
        
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

@pytest.mark.asyncio
async def test_agent_main_kernel():
    """Test that agent forwards events in kernel mode."""
    # Mocking out the linux-specific imports that happen inside the if block
    with patch("backend.agent.main.detect_capabilities") as mock_detect, \
         patch("backend.agent.main.requests.post") as mock_post:
         
        mock_detect.return_value = AgentCapabilities("Linux", "kernel", True, "mock")
        
        original_owner = settings.kernel_monitor_owner
        settings.kernel_monitor_owner = "agent"
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"classification": "safe"}
        mock_post.return_value = mock_response
        
        # We need to mock get_hook_manager carefully since it's imported conditionally inside the function
        import sys
        
        # Create a fake module for backend.kernel.execve_hook
        mock_kernel_module = MagicMock()
        mock_manager = MagicMock()
        mock_kernel_module.get_hook_manager.return_value = mock_manager
        
        # Temporarily inject our mock module
        sys.modules['backend.kernel.execve_hook'] = mock_kernel_module
        
        try:
            task = asyncio.create_task(agent_event_loop())
            
            await asyncio.sleep(0.1)
            
            assert mock_manager.start.called
            
            callback = mock_manager.start.call_args[0][0]
            
            event = ExecveEvent(pid=1, ppid=2, uid=3, gid=4, command="ls", argv_str="ls -l", timestamp=123.4, comm="ls")
            callback(event)
            
            await asyncio.sleep(0.1)
            
            assert mock_post.called
            call_kwargs = mock_post.call_args[1]
            assert call_kwargs["json"]["command"] == "ls"
            
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            assert mock_manager.stop.called
        finally:
            # Restore sys.modules
            del sys.modules['backend.kernel.execve_hook']
            settings.kernel_monitor_owner = original_owner
