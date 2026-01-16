#!/bin/bash

# Run All E2E Tests
# This script runs all available e2e tests for MCP Fuzzer
# Used in CI pipelines for comprehensive end-to-end testing

set -e  # Exit on any error

echo "🚀 Starting MCP Fuzzer E2E Test Suite"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Change to project root
cd "$PROJECT_ROOT"

echo "📍 Running from: $PROJECT_ROOT"
echo "📁 Test directory: $SCRIPT_DIR"
echo ""

# Function to run a single test
run_test() {
    local test_name="$1"
    local test_script="$2"

    echo -e "${BLUE}🧪 Running $test_name...${NC}"
    echo "Command: $test_script"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ -x "$test_script" ]; then
        if "$test_script"; then
            echo -e "${GREEN}✅ $test_name PASSED${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}❌ $test_name FAILED${NC}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        echo -e "${RED}❌ $test_name SKIPPED (script not executable)${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi

    echo ""
}

# Run individual e2e tests
run_test "Everything Server Test (Docker)" "$SCRIPT_DIR/test_everything_server_docker.sh"
run_test "MCP Server Chart Test" "$SCRIPT_DIR/test_mcp_server_chart.sh"

# Summary
echo "========================================"
echo -e "${BLUE}📊 E2E Test Results Summary${NC}"
echo "========================================"
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All e2e tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ $FAILED_TESTS e2e test(s) failed${NC}"
    exit 1
fi
