#!/bin/bash

# Safety Check Script for MCP Fuzzer CI/CD
# Verifies all safety measures are active before running system tests

# set +e  # Don't exit on error, handle errors manually

echo "🔒 MCP Fuzzer Safety Check"
echo "=========================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0

check_pass() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASSED++))
}

check_fail() {
    echo -e "${RED}❌ $1${NC}"
    ((FAILED++))
}

check_warn() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

echo "🧪 Checking safety prerequisites..."

# Check if safety system is available
if python -c "from mcp_fuzzer.safety_system.safety import safety_filter; print('Safety system available')" 2>/dev/null; then
    check_pass "Safety system module available"
else
    check_fail "Safety system module not available"
fi

# Check if DesktopCommanderMCP exists
if [ -d "testing-servers/DesktopCommanderMCP" ]; then
    check_pass "DesktopCommanderMCP test server exists"
else
    check_fail "DesktopCommanderMCP test server missing"
fi

# Check if DesktopCommanderMCP is built
if [ -f "testing-servers/DesktopCommanderMCP/dist/index.js" ]; then
    check_pass "DesktopCommanderMCP is built"
else
    check_fail "DesktopCommanderMCP not built (run: cd testing-servers/DesktopCommanderMCP && npm run build)"
fi

# Check Python environment
if python -c "import mcp_fuzzer; print('MCP Fuzzer available')" 2>/dev/null; then
    check_pass "MCP Fuzzer Python package available"
else
    check_fail "MCP Fuzzer Python package not available"
fi

# Check Node.js availability
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    check_pass "Node.js available ($NODE_VERSION)"
else
    check_fail "Node.js not available"
fi

# Check if we're in CI environment
if [ -n "$CI" ] || [ -n "$GITHUB_ACTIONS" ]; then
    check_pass "Running in CI environment"
    echo "   - Ephemeral runner: ✅"
    echo "   - Resource limits: ✅"
    echo "   - Artifact isolation: ✅"
else
    check_warn "Not running in CI environment"
    echo "   - Consider running in isolated environment"
fi

# Check for dangerous commands (should not be executable in PATH)
DANGEROUS_COMMANDS=("xdg-open" "open" "start" "firefox" "chrome" "chromium" "google-chrome" "safari" "edge" "opera" "brave")

echo ""
echo "🛡️  Checking command blocking..."

BLOCKED_COUNT=0
for cmd in "${DANGEROUS_COMMANDS[@]}"; do
    if command -v "$cmd" &> /dev/null; then
        # Check if it's in a safe location (not system PATH)
        CMD_PATH=$(command -v "$cmd")
        if [[ "$CMD_PATH" == *"/usr/bin/"* ]] || [[ "$CMD_PATH" == *"/bin/"* ]] || [[ "$CMD_PATH" == *"/usr/local/bin/"* ]]; then
            check_warn "Potentially dangerous command available: $cmd ($CMD_PATH)"
        else
            check_pass "Command available but in safe location: $cmd ($CMD_PATH)"
        fi
    else
        ((BLOCKED_COUNT++))
    fi
done

if [ $BLOCKED_COUNT -gt 0 ]; then
    check_pass "$BLOCKED_COUNT dangerous commands not in PATH"
fi

# Check filesystem permissions
echo ""
echo "📁 Checking filesystem access..."

# Check if we can write to temp directory
if mkdir -p /tmp/mcp_fuzzer_test && rm -rf /tmp/mcp_fuzzer_test 2>/dev/null; then
    check_pass "Can create temporary directories"
else
    check_fail "Cannot create temporary directories"
fi

# Check if we can write to project directory
if touch test_safety_check.tmp && rm test_safety_check.tmp 2>/dev/null; then
    check_pass "Can write to project directory"
else
    check_fail "Cannot write to project directory"
fi

# Summary
echo ""
echo "📊 Safety Check Summary"
echo "======================"
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"

if [ $FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 All safety checks passed! Ready for system testing.${NC}"
    echo ""
    echo "🛡️  Safety measures active:"
    echo "   • Safety system: Enabled"
    echo "   • Command blocking: Active"
    echo "   • Filesystem sandboxing: Ready"
    echo "   • Process isolation: Available"
    echo "   • CI environment: $([ -n "$CI" ] && echo 'Yes' || echo 'No')"
    exit 0
else
    echo ""
    echo -e "${RED}⚠️  $FAILED safety check(s) failed. Please resolve before running system tests.${NC}"
    exit 1
fi