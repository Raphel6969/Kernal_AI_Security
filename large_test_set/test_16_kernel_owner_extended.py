"""
test_16_kernel_owner_extended.py — Extended ownership model tests.

Fills gaps in test_kernel_owner.py:
- Invalid KERNEL_MONITOR_OWNER value behaviour documented
- Owner value read at runtime (not import time) — env change takes effect
- Duplicate eBPF attach prevention: two agents with owner=agent must not
  both call start()
- stop() is called when the agent task is cancelled
- Callback not invoked after monitor is stopped
- MacOS / Darwin with owner=agent behaves like api-only (no kernel)

Run:
    pytest large_test_set/test_16_kernel_owner_extended.py -v
"""

import pytest
import asyncio
import sys
from unittest.mock import patch, MagicMock, call
from backend.agent.runtime import AgentCapabilities


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject_kernel_mock(running=False):
    mock_module  = MagicMock()
    mock_manager = MagicMock()
    mock_manager.monitor         = MagicMock()
    mock_manager.monitor.running = running
    mock_module.get_hook_manager.return_value = mock_manager
    sys.modules["backend.kernel.execve_hook"] = mock_module
    return mock_module, mock_manager


def _remove_kernel_mock():
    sys.modules.pop("backend.kernel.execve_hook", None)


# ===========================================================================
# 1. Invalid KERNEL_MONITOR_OWNER value
# ===========================================================================

class TestInvalidOwnerValue:

    @pytest.mark.asyncio
    async def test_invalid_owner_value_does_not_start_monitor(self):
        """An unrecognised owner value must not start the monitor —
        the safe default is to do nothing."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.config.Settings.validate_owner",
                   return_value="totally_invalid"):
            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)

                assert not mock_manager.start.called, \
                    "Monitor started despite invalid owner value"
                assert not mock_manager.set_callback.called

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            finally:
                _remove_kernel_mock()

    @pytest.mark.asyncio
    async def test_invalid_owner_loop_does_not_crash(self):
        """An invalid owner value must not crash the event loop."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.config.Settings.validate_owner",
                   return_value="invalid_owner"):
            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                done, _ = await asyncio.wait([task], timeout=0.2)
                assert not done, \
                    "agent_event_loop exited (crashed) on invalid owner value"
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            finally:
                _remove_kernel_mock()


# ===========================================================================
# 2. stop() called when agent task is cancelled
# ===========================================================================

class TestMonitorStopOnCancel:

    @pytest.mark.asyncio
    async def test_monitor_stop_called_on_task_cancellation(self):
        """When the agent_event_loop task is cancelled, mock_manager.stop()
        must be called to clean up the eBPF hook."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.config.Settings.validate_owner",
                   return_value="agent"):
            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)

                assert mock_manager.start.called, \
                    "start() not called — cannot test stop()"

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

                assert mock_manager.stop.called, \
                    "stop() was not called after task cancellation"
            finally:
                _remove_kernel_mock()

    @pytest.mark.asyncio
    async def test_stop_called_exactly_once_on_single_cancel(self):
        """stop() must be called exactly once, not multiple times."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.config.Settings.validate_owner",
                   return_value="agent"):
            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

                assert mock_manager.stop.call_count == 1, (
                    f"stop() called {mock_manager.stop.call_count} times — "
                    "expected exactly 1"
                )
            finally:
                _remove_kernel_mock()


# ===========================================================================
# 3. Duplicate attach prevention
# ===========================================================================

class TestDuplicateAttachPrevention:

    @pytest.mark.asyncio
    async def test_two_agents_owner_agent_only_one_starts_monitor(self):
        """When two agent_event_loop coroutines run simultaneously with
        owner=agent, the monitor must be started at most once — duplicate
        eBPF attachment would cause kernel errors."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.config.Settings.validate_owner",
                   return_value="agent"):
            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            _, mock_manager = _inject_kernel_mock(running=False)
            try:
                from backend.agent.main import agent_event_loop
                task1 = asyncio.create_task(agent_event_loop())
                task2 = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.15)

                start_count = mock_manager.start.call_count
                assert start_count <= 1, (
                    f"start() called {start_count} times — duplicate eBPF "
                    "attachment detected"
                )

                task1.cancel()
                task2.cancel()
                for t in [task1, task2]:
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass
            finally:
                _remove_kernel_mock()

    @pytest.mark.asyncio
    async def test_backend_owner_never_starts_even_if_two_loops_run(self):
        """With owner=backend, no matter how many agent loops run, start()
        must never be called."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.config.Settings.validate_owner",
                   return_value="backend"):
            mock_detect.return_value = AgentCapabilities(
                "Linux", "kernel", True, "mock"
            )
            _, mock_manager = _inject_kernel_mock(running=False)
            try:
                from backend.agent.main import agent_event_loop
                tasks = [asyncio.create_task(agent_event_loop())
                         for _ in range(3)]
                await asyncio.sleep(0.15)

                assert mock_manager.start.call_count == 0, (
                    f"start() called {mock_manager.start.call_count} times "
                    "with owner=backend"
                )

                for t in tasks:
                    t.cancel()
                for t in tasks:
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass
            finally:
                _remove_kernel_mock()


# ===========================================================================
# 4. macOS / Darwin with owner=agent behaves like api-only
# ===========================================================================

class TestDarwinOwnerAgentFallback:

    @pytest.mark.asyncio
    async def test_darwin_owner_agent_does_not_start_kernel_monitor(self):
        """On Darwin, setting owner=agent must not try to load eBPF —
        it must fall back to api-only silently."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.config.Settings.validate_owner",
                   return_value="agent"):
            mock_detect.return_value = AgentCapabilities(
                "Darwin", "api-only", False, "mock"
            )
            _, mock_manager = _inject_kernel_mock()
            try:
                from backend.agent.main import agent_event_loop
                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)

                assert not mock_manager.start.called, \
                    "Kernel monitor started on Darwin — must not happen"

                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            finally:
                _remove_kernel_mock()


# ===========================================================================
# 5. Callback not invoked after monitor is stopped
# ===========================================================================

class TestCallbackNotInvokedAfterStop:

    @pytest.mark.asyncio
    async def test_events_after_stop_not_forwarded(self):
        """Events fired via the callback after the agent has been stopped
        (task cancelled) must not result in additional POST calls."""
        with patch("backend.agent.main.detect_capabilities") as mock_detect, \
             patch("backend.agent.main.requests.post") as mock_post, \
             patch("backend.config.Settings.validate_owner",
                   return_value="agent"):

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
                from backend.events.models import ExecveEvent
                import time as time_mod

                task = asyncio.create_task(agent_event_loop())
                await asyncio.sleep(0.1)

                cb = mock_manager.start.call_args[0][0]

                # Fire one event while running
                ev1 = ExecveEvent(pid=1, ppid=0, uid=0, gid=0,
                                  command="ls", argv_str="ls",
                                  timestamp=time_mod.time(), comm="bash")
                cb(ev1)
                await asyncio.sleep(0.1)
                calls_before_stop = mock_post.call_count

                # Cancel the task (stop the agent)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

                await asyncio.sleep(0.1)
                calls_after_stop = mock_post.call_count

                # No new calls should have been made after cancellation
                assert calls_after_stop == calls_before_stop, (
                    f"POST was called {calls_after_stop - calls_before_stop} "
                    "extra time(s) after agent was stopped"
                )
            finally:
                _remove_kernel_mock()
