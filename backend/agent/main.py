import asyncio
import logging
import os
import psutil
import requests
from backend.agent.runtime import detect_capabilities
from backend.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

async def agent_event_loop():
    """Continuously monitor kernel and forward events to backend"""
    capabilities = detect_capabilities()
    
    if capabilities.run_mode == "kernel":
        # Import Linux-specific modules only when in kernel mode
        from backend.kernel.execve_hook import get_hook_manager
        
        logger.info("Starting in KERNEL mode - eBPF monitoring active")

        # Respect ownership configuration. If backend owns the monitor, do not start it here.
        owner = settings.validate_owner()

        # We need an async queue to pass events from the background thread to the async loop
        queue = asyncio.Queue()
        
        # Capture the running loop in async context BEFORE defining the callback
        # This avoids asyncio.get_running_loop() failure when callback is invoked from monitor thread
        loop = asyncio.get_running_loop()

        def on_event(event):
            # This is called from the background thread of RCEMonitor
            # We use the captured loop to safely enqueue from the background thread
            try:
                loop.call_soon_threadsafe(queue.put_nowait, event)
            except Exception as e:
                logger.error(f"Failed to queue event: {e}")

        manager = get_hook_manager()

        # If the monitor is already running in another process, prefer to set the callback only.
        # If this process is the owner, start the monitor; if disabled, do nothing.
        try:
            # Only treat the monitor as running when the attribute explicitly equals True.
            monitor = getattr(manager, "monitor", None)
            monitor_running = False
            if monitor is not None and hasattr(monitor, "running"):
                monitor_running = getattr(monitor, "running") is True
        except Exception:
            monitor_running = False

        if owner == "disabled":
            logger.info("Kernel monitoring disabled by configuration; agent will not attach hooks")
        elif owner == "backend":
            # Backend owns the monitor; if it's already running in this process, set callback; otherwise do not start.
            if monitor_running:
                logger.info("Monitor already running in this process; registering callback")
                manager.set_callback(on_event)
            else:
                logger.info("Backend is owner; agent will not start local monitor")
        else:  # owner == 'agent'
            if monitor_running:
                logger.info("Monitor already running; registering callback")
                manager.set_callback(on_event)
            else:
                logger.info("Agent owns the monitor; starting local monitor")
                manager.start(on_event)

        try:
            # Continuously read from the queue
            while True:
                execve_event = await queue.get()
                try:
                    # Capture memory footprint immediately
                    try:
                        proc = psutil.Process(execve_event.pid)
                        process_memory_mb = proc.memory_info().rss / (1024 * 1024)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_memory_mb = 0.0
                    
                    system_memory_percent = psutil.virtual_memory().percent

                    # Send to backend
                    response = requests.post(
                        f"{settings.backend_url}/agent/events",
                        json={
                            "agent_id": os.getenv("AI_BOUNCER_AGENT_ID") or None,
                            "pid": execve_event.pid,
                            "ppid": execve_event.ppid,
                            "uid": execve_event.uid,
                            "gid": execve_event.gid,
                            "command": execve_event.command,
                            "argv_str": execve_event.argv_str,
                            "comm": execve_event.comm,
                            "timestamp": execve_event.timestamp,
                            "process_memory_mb": process_memory_mb,
                            "system_memory_percent": system_memory_percent,
                        },
                        timeout=settings.agent_event_timeout
                    )
                    if response.status_code == 200:
                        result = response.json()
                        logger.debug(f"Event forwarded: {result.get('classification', 'unknown')}")
                    else:
                        logger.error(f"Backend error: {response.status_code} - {response.text}")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to reach backend ({e}). Retrying in 5 seconds...")
                    await asyncio.sleep(5)
                    # Future Phase: Queue event locally if backend down
                finally:
                    queue.task_done()
        except asyncio.CancelledError:
            logger.info("Agent loop cancelled, stopping monitor...")
            try:
                manager.stop()
            except Exception:
                pass
            raise
            
    elif capabilities.run_mode == "api-only":
        logger.info("Starting in API-ONLY mode (non-Linux)")
        logger.info("Waiting for manual POST requests to /analyze endpoint")
        # Just keep running (agent launcher manages the process)
        try:
            while True:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            logger.info("Agent loop cancelled.")
            raise
    else:
        logger.warning(f"Unsupported mode: {capabilities.run_mode}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(agent_event_loop())
    except KeyboardInterrupt:
        logger.info("Exiting...")
