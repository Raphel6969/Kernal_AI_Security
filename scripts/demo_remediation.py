import os
import sys
import subprocess
import time
import requests
import psutil

# Add parent directory to path so we can import backend modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import get_settings

def main():
    settings = get_settings()
    backend_url = settings.backend_url
    
    print("[INFO] Aegix Auto-Remediation & Resource Guard Demo")
    print("=================================================")
    print(f"Connecting to backend: {backend_url}")
    
    # 1. Spawn a background memory clogger process
    # This allocates 120MB and sleeps. We use base64 import in the signature to trigger suspicious rules.
    cmd = [
        sys.executable, "-c",
        "import time, base64; print('Allocating dummy memory...'); data = ' ' * (120 * 1024 * 1024); time.sleep(15)"
    ]
    
    print("\n[1] Spawning memory-hogging process...")
    proc = subprocess.Popen(cmd)
    pid = proc.pid
    print(f"    -> Spawned process PID: {pid}")
    
    # Wait a moment for the process to allocate memory
    time.sleep(1.5)
    
    # 2. Query its memory RSS using psutil
    try:
        ps_proc = psutil.Process(pid)
        mem_mb = ps_proc.memory_info().rss / (1024 * 1024)
        print(f"    -> Measured RSS memory: {mem_mb:.1f} MB")
    except Exception as e:
        print(f"    [ERROR] Failed to measure memory: {e}")
        proc.kill()
        return

    # 3. Construct a payload that matches eBPF telemetry formatting
    # We include base64 payload to trigger rules and push risk score past the malicious threshold
    mock_command = "python -c 'import base64; clogger = \" \" * (120 * 1024 * 1024); time.sleep(15)'"
    payload = {
        "agent_id": "demo-agent-remediation",
        "pid": pid,
        "ppid": 0,
        "uid": 1000,
        "gid": 1000,
        "command": mock_command,
        "argv_str": mock_command,
        "comm": "python",
        "process_memory_mb": mem_mb,
        "system_memory_percent": psutil.virtual_memory().percent
    }
    
    print("\n[2] Forwarding event to Aegix backend...")
    try:
        res = requests.post(f"{backend_url}/agent/events", json=payload)
        if res.status_code == 200:
            data = res.json()
            verdict = data.get("classification")
            score = data.get("risk_score")
            print(f"    -> Backend Response: [{verdict.upper()}] Risk Score: {score}/100")
            
            # Wait a moment to check if backend terminated the process
            time.sleep(2)
            poll = proc.poll()
            if poll is not None:
                print("\n[3] [REMEDIATION ACTIVE]")
                print(f"    [SUCCESS] Process {pid} was successfully terminated by Aegix (Exit code: {poll})!")
                print("\n[NOTE] Check the Dashboard home page - the event is logged with Remediation status: SUCCESS.")
            else:
                print("\n[3] [WARNING] Process is still running.")
                print("    Is Auto-Remediation toggled ON in the dashboard settings?")
                print("    (Terminating process manually to clean up...)")
                proc.kill()
        else:
            print(f"    [ERROR] Backend returned error: {res.status_code} - {res.text}")
            proc.kill()
    except Exception as e:
        print(f"    [ERROR] Failed to contact backend: {e}")
        proc.kill()

if __name__ == "__main__":
    main()
