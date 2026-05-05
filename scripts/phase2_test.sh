#!/bin/bash
# Phase 2 Kernel Guard Testing Script
# Tests eBPF compilation, BCC loading, and kernel event capture

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_test() {
    echo -e "${YELLOW}[TEST $((TESTS_RUN + 1))]${NC} $1"
}

pass_test() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

fail_test() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

skip_test() {
    echo -e "${YELLOW}⊘ SKIP${NC}: $1 (requires Linux)"
    TESTS_RUN=$((TESTS_RUN + 1))
}

# Check platform
check_platform() {
    if [[ ! "$OSTYPE" =~ linux ]]; then
        echo -e "${YELLOW}⚠️  Phase 2 eBPF tests require Linux${NC}"
        echo "Skipping kernel-specific tests on $OSTYPE"
        exit 0
    fi
}

# Test 1: Verify build tools
test_build_tools() {
    print_test "Checking eBPF build tools"
    
    local tools_ok=true
    
    if ! command -v clang &> /dev/null; then
        fail_test "clang not found (install: sudo apt-get install clang)"
        tools_ok=false
    fi
    
    if ! command -v llc &> /dev/null; then
        fail_test "llc not found (install: sudo apt-get install llvm)"
        tools_ok=false
    fi
    
    if ! command -v python3 &> /dev/null; then
        fail_test "python3 not found"
        tools_ok=false
    fi
    
    if [ "$tools_ok" = true ]; then
        pass_test "All build tools installed"
    fi
}

# Test 2: Verify kernel version
test_kernel_version() {
    print_test "Checking kernel version"
    
    KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
    MIN_VERSION="5.4"
    
    if awk "BEGIN {exit !($KERNEL_VERSION >= $MIN_VERSION)}"; then
        pass_test "Kernel $KERNEL_VERSION >= $MIN_VERSION"
    else
        fail_test "Kernel $KERNEL_VERSION < $MIN_VERSION (eBPF tracepoints require 5.4+)"
    fi
}

# Test 3: Verify BCC installation
test_bcc_installed() {
    print_test "Checking BCC Python bindings"
    
    if python3 -c "from bcc import BPF" 2>/dev/null; then
        pass_test "BCC installed"
    else
        fail_test "BCC not installed (run: bash scripts/setup_kernel.sh)"
    fi
}

# Test 4: eBPF program syntax
test_ebpf_syntax() {
    print_test "Verifying eBPF C syntax"
    
    if clang -target bpf -c kernel/execve_hook.c -o /tmp/syntax_check.o 2>/dev/null; then
        pass_test "eBPF C source compiles"
        rm -f /tmp/syntax_check.o
    else
        fail_test "eBPF C source has syntax errors"
    fi
}

# Test 5: Build eBPF program
test_ebpf_build() {
    print_test "Building eBPF program"
    
    cd kernel
    make clean >/dev/null 2>&1
    
    if make all >/dev/null 2>&1; then
        if [ -f ".output/execve_hook.o" ]; then
            SIZE=$(stat -f%z ".output/execve_hook.o" 2>/dev/null || stat -c%s ".output/execve_hook.o")
            pass_test "eBPF program built (.output/execve_hook.o, $SIZE bytes)"
        else
            fail_test "Build succeeded but .output/execve_hook.o not found"
        fi
    else
        fail_test "eBPF program build failed"
    fi
    
    cd "$PROJECT_ROOT"
}

# Test 6: RCEMonitor initialization (non-root)
test_rcemonitor_init() {
    print_test "Testing RCEMonitor initialization"
    
    PYTHON_TEST=$(cat << 'PYEOF'
import sys
sys.path.insert(0, '.')
from backend.kernel.rce_monitor import RCEMonitor
try:
    monitor = RCEMonitor()
    print("init_ok")
except Exception as e:
    print(f"init_error: {e}")
PYEOF
)
    
    if result=$(python3 -c "$PYTHON_TEST" 2>&1); then
        if echo "$result" | grep -q "init_ok"; then
            pass_test "RCEMonitor initializes without errors"
        else
            fail_test "RCEMonitor init failed: $result"
        fi
    else
        fail_test "Python execution failed: $result"
    fi
}

# Test 7: Check if running as root
test_root_check() {
    print_test "Checking for root privileges"
    
    if [ "$EUID" -eq 0 ]; then
        pass_test "Running as root (eBPF loading will work)"
    else
        echo -e "${YELLOW}⚠️  Not running as root (eBPF loading requires root)${NC}"
        echo "   Run with: sudo bash scripts/phase2_test.sh"
    fi
}

# Test 8: RCEMonitor load test (root only)
test_rcemonitor_load() {
    if [ "$EUID" -ne 0 ]; then
        skip_test "RCEMonitor BCC loading (requires root)"
        return
    fi
    
    print_test "Testing RCEMonitor BCC loading"
    
    PYTHON_TEST=$(cat << 'PYEOF'
import sys
sys.path.insert(0, '.')
from backend.kernel.rce_monitor import get_rce_monitor
monitor = get_rce_monitor()
try:
    monitor.start()
    import time
    time.sleep(1)
    monitor.stop()
    print("load_ok")
except Exception as e:
    print(f"load_error: {str(e)[:100]}")
PYEOF
)
    
    if result=$(python3 -c "$PYTHON_TEST" 2>&1); then
        if echo "$result" | grep -q "load_ok"; then
            pass_test "RCEMonitor loads eBPF program successfully"
        else
            fail_test "RCEMonitor load failed: $result"
        fi
    else
        fail_test "Python execution failed"
    fi
}

# Print summary
print_summary() {
    echo ""
    print_header "Test Summary"
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo ""
        echo -e "${GREEN}✅ All tests passed!${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. Start the backend: uvicorn backend.app:app --port 8000"
        echo "  2. Run the demo: bash scripts/demo.sh"
        echo "  3. Test API: curl -X POST http://localhost:8000/analyze -H 'Content-Type: application/json' -d '{\"command\":\"ls\"}'"
        return 0
    else
        echo ""
        echo -e "${RED}❌ Some tests failed${NC}"
        echo ""
        echo "Troubleshooting:"
        echo "  - Run setup: bash scripts/setup_kernel.sh"
        echo "  - Check kernel: uname -r (need 5.4+)"
        echo "  - For root tests: sudo bash scripts/phase2_test.sh"
        return 1
    fi
}

# Main test suite
main() {
    print_header "Phase 2: Kernel Guard eBPF Testing Suite"
    
    check_platform
    
    echo "Platform: $(uname -s) $(uname -r)"
    echo "Python: $(python3 --version)"
    echo ""
    
    test_build_tools
    test_kernel_version
    test_bcc_installed
    test_ebpf_syntax
    test_ebpf_build
    test_rcemonitor_init
    test_root_check
    test_rcemonitor_load
    
    print_summary
}

# Run main
main
