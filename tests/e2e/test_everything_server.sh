#!/bin/bash

# E2E Test for Everything MCP Server
# Uses a local clone in explore/servers when available, otherwise clones upstream

set -e  # Exit on any error

echo "🧪 Starting Everything Server E2E Test"
echo "======================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCAL_REPO_DIR="$PROJECT_ROOT/explore/servers"
REPO_URL="https://github.com/modelcontextprotocol/servers.git"
SERVER_SUBDIR="src/everything"
FUZZ_OUTPUT_DIR="/tmp/everything_server_fuzz_$(date +%s)"
REPO_DIR=""
CLONED_REPO_DIR=""
SCHEMA_VERSION="2025-11-25"
export MCP_SPEC_SCHEMA_VERSION="$SCHEMA_VERSION"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    if [ -n "$CLONED_REPO_DIR" ] && [ -d "$CLONED_REPO_DIR" ]; then
        echo "Removing cloned repo: $CLONED_REPO_DIR"
        rm -rf "$CLONED_REPO_DIR"
    fi
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Set trap for cleanup on exit
trap cleanup EXIT

if [ -d "$LOCAL_REPO_DIR/$SERVER_SUBDIR" ]; then
    REPO_DIR="$LOCAL_REPO_DIR"
    echo -e "${BLUE}📍 Using local servers repo${NC}"
    echo "Location: $REPO_DIR"
else
    echo -e "${BLUE}📥 Local repo not found, cloning servers repo...${NC}"
    CLONED_REPO_DIR="/tmp/mcp-servers-$(date +%s)"
    git clone "$REPO_URL" "$CLONED_REPO_DIR"
    REPO_DIR="$CLONED_REPO_DIR"
fi

SERVER_DIR="$REPO_DIR/$SERVER_SUBDIR"

if [ ! -d "$SERVER_DIR" ]; then
    echo -e "${RED}❌ Everything server directory not found${NC}"
    echo "Expected location: $SERVER_DIR"
    exit 1
fi

echo -e "${BLUE}📍 Everything server directory${NC}"
echo "Location: $SERVER_DIR"

echo "🔧 Installing dependencies (if needed)..."
if [ ! -d "$REPO_DIR/node_modules" ]; then
    if [ -f "$REPO_DIR/package-lock.json" ]; then
        (cd "$REPO_DIR" && npm ci)
    else
        (cd "$REPO_DIR" && npm install)
    fi
fi

if [ ! -f "$SERVER_DIR/dist/index.js" ]; then
    echo "🏗️ Building Everything server..."
    if (cd "$REPO_DIR" && npm run build --workspace @modelcontextprotocol/server-everything); then
        echo -e "${GREEN}✅ Build successful${NC}"
    else
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    fi
fi

if [ ! -f "$SERVER_DIR/dist/index.js" ]; then
    echo -e "${RED}❌ Everything server dist/index.js not found after build${NC}"
    exit 1
fi

echo "🎯 Starting fuzzing tests..."
echo "Output directory: $FUZZ_OUTPUT_DIR"
echo "Project root: $PROJECT_ROOT"

echo "🐍 Ensuring MCP Fuzzer is installed..."
python3 -m pip install -e "$PROJECT_ROOT"

echo "🧪 Running comprehensive fuzzing test (tools + protocol)..."
python3 -m mcp_fuzzer \
    --protocol stdio \
    --endpoint "node $SERVER_DIR/dist/index.js stdio" \
    --mode all \
    --protocol-phase realistic \
    --runs 5 \
    --verbose \
    --enable-safety-system \
    --spec-schema-version "$SCHEMA_VERSION" \
    --output-dir "$FUZZ_OUTPUT_DIR"

FUZZ_EXIT_CODE=$?
echo "Fuzzing test completed with exit code: $FUZZ_EXIT_CODE"

# Check if fuzzing produced expected output
if [ -d "$FUZZ_OUTPUT_DIR" ] && [ "$(ls -A "$FUZZ_OUTPUT_DIR")" ]; then
    echo -e "${GREEN}✅ Fuzzing test completed successfully${NC}"
    echo "📊 Generated reports in: $FUZZ_OUTPUT_DIR"
    ls -la "$FUZZ_OUTPUT_DIR"
else
    echo -e "${RED}❌ Fuzzing test failed to generate output${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 Everything Server E2E Test Completed Successfully!${NC}"
echo "======================================="
echo "Server Directory: $SERVER_DIR"
echo "Output Directory: $FUZZ_OUTPUT_DIR"
echo "Exit Code: $FUZZ_EXIT_CODE"
echo "Safety System: ✅ Enabled"
echo "Test Mode: All"
echo "Test Runs: 5 per tool"
