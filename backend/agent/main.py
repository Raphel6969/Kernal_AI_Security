import asyncio
import logging
import requests
from backend.agent.runtime import detect_capabilities

logger = logging.getLogger(__name__)

async def agent_event_loop():
    """Continuously monitor kernel and forward events to backend"""
    capabilities = detect_capabilities()
    
    if capabilities.run_mode == "kernel":
        # Import Linux-specific modules only when in kernel mode
        from backend.kernel.execve_hook import get_hook_manager
        
        logger.info("Starting in KERNEL mode - eBPF monitoring active")
        
        # We need an async queue to pass events from the background thread to the async loop
        queue = asyncio.Queue()
        
        def on_event(event):
            # This is called from the background thread of RCEMonitor
            # We must use call_soon_threadsafe to put it into the async queue
            try:
                loop = asyncio.get_running_loop()
                loop.call_soon_threadsafe(queue.put_nowait, event)
            except Exception as e:
                logger.error(f"Failed to queue event: {e}")

        manager = get_hook_manager()
        manager.start(on_event)
        
        try:
            # Continuously read from the queue
            while True:
                execve_event = await queue.get()
                try:
                    # Send to backend
                    response = requests.post(
                        "http://localhost:8000/agent/events",
                        json={
                            "pid": execve_event.pid,
                            "ppid": execve_event.ppid,
                            "uid": execve_event.uid,
                            "gid": execve_event.gid,
                            "command": execve_event.command,
                            "argv_str": execve_event.argv_str,
                            "comm": execve_event.comm,
                            "timestamp": execve_event.timestamp
                        },
                        timeout=5
                    )
                    if response.status_code == 200:
                        result = response.json()
                        logger.debug(f"Event forwarded: {result.get('classification', 'unknown')}")
                    else:
                        logger.error(f"Backend error: {response.status_code} - {response.text}")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to reach backend: {e}")
                    # Future Phase: Queue event locally if backend down
                finally:
                    queue.task_done()
        except asyncio.CancelledError:
            logger.info("Agent loop cancelled, stopping monitor...")
            manager.stop()
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
