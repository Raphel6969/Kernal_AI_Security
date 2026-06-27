import os
import sys
import subprocess
import time
import requests

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def print_banner():
    print("""
=========================================================
 ???  AEGIX Windows Intercept Agent Shell (Demo Mode)  ???
=========================================================
 This shell simulates the eBPF native hook on Windows.
 Every command you run here is intercepted, sent to the 
 Aegix bouncer, and evaluated in real-time.

 If Auto-Remediation is ON, malicious command processes 
 will be killed instantly!
=========================================================
""")

def main():
    print_banner()

    backend_url = "http://localhost:8000"
    
    print("To show events in your browser dashboard, enter your Session Token.")
    print("You can copy it from the 'System Settings' tab in the web UI.")
    session_token = input("Session Token (optional, press Enter to skip): ").strip()
    
    print("\nStarting shell. Type 'exit' to quit.\n")
    
    while True:
        try:
            cwd = os.getcwd()
            prompt = f"AEGIX@WIN-AGENT:{cwd} $ "
            command = input(prompt).strip()
            
            if not command:
                continue
                
            if command.lower() in ("exit", "quit"):
                print("Exiting Aegix agent shell.")
                break

            print(f"[*] Intercepting command: {command}")
            
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
                print(f"? Failed to execute command: {e}")
                continue

            mem_mb = 0.0
            sys_mem = 0.0
            if PSUTIL_AVAILABLE:
                try:
                    ps_proc = psutil.Process(pid)
                    mem_mb = ps_proc.memory_info().rss / (1024 * 1024)
                    sys_mem = psutil.virtual_memory().percent
                except:
                    pass

            payload = {
                "agent_id": "windows-agent-shell",
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
                    rules = data.get("matched_rules", [])
                    
                    emoji = "??" if classification == "safe" else "??" if classification == "suspicious" else "??"
                    print(f"    -> {emoji} Bouncer Verdict: [{classification.upper()}] Risk: {score:.0f}/100")
                    if rules:
                        print(f"    -> Matched Rules: {', '.join(rules)}")
                    
                    time.sleep(0.5)
                    
                    poll = proc.poll()
                    if poll is not None:
                        print(f"    -> ?? [REMEDIATION] Process {pid} was terminated (Exit code: {poll})!")
                    else:
                        stdout, stderr = proc.communicate()
                        if stdout:
                            print(stdout, end="")
                        if stderr:
                            print(stderr, file=sys.stderr, end="")
                else:
                    print(f"    [Error] Backend API error: {res.status_code}")
                    proc.kill()
            except Exception as e:
                print(f"    [Error] Failed to connect to backend: {e}")
                proc.kill()

        except KeyboardInterrupt:
            print("\nUse 'exit' to quit.")
        except Exception as e:
            print(f"Error in shell loop: {e}")

if __name__ == "__main__":
    main()
