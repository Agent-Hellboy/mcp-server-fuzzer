r #!/bin/bash

# System Test for MCP Server Chart
# This script clones, builds, and fuzzes the MCP Server Chart
# Used for CI system testing of mcp-fuzzer changes

set -e  # Exit on any error

echo "🧪 Starting MCP Server Chart System Test"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/antvis/mcp-server-chart.git"
SERVER_DIR="mcp-server-chart"
FUZZ_OUTPUT_DIR="/tmp/mcp_server_chart_fuzz_$(date +%s)"
SERVER_PID=""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    if [ ! -z "$SERVER_PID" ] && kill -0 $SERVER_PID 2>/dev/null; then
        echo "Stopping server process (PID: $SERVER_PID)"
        kill $SERVER_PID 2>/dev/null || true
        sleep 2
    fi
    # Clean up cloned repository
    if [ -d "$SERVER_DIR" ]; then
        echo "Removing $SERVER_DIR"
        rm -rf "$SERVER_DIR"
    fi
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Set trap for cleanup on exit
trap cleanup EXIT

echo "📥 Cloning MCP Server Chart repository..."
if [ -d "$SERVER_DIR" ]; then
    echo "Directory $SERVER_DIR already exists, removing..."
    rm -rf "$SERVER_DIR"
fi

git clone "$REPO_URL" "$SERVER_DIR"
cd "$SERVER_DIR"

echo "🔧 Installing dependencies..."
npm install

echo "🏗️ Building server..."
if npm run build; then
    echo "✅ Build successful"
else
    echo "❌ Build failed, trying to use existing server..."
    # Check if we can use the existing working server
    if [ -f "../../../testing-servers/mcp-server-chart/build/index.js" ]; then
        echo "🔄 Using existing server build"
        cp -r ../../../testing-servers/mcp-server-chart/* ./
    else
        echo "❌ No existing server build found"
        exit 1
    fi
fi

echo "� Starting server in background..."
# Start server in background and capture PID
node build/index.js &
SERVER_PID=$!

# Wait for server to start and check multiple times
echo "⏳ Waiting for server to initialize..."
for i in {1..10}; do
    if kill -0 $SERVER_PID 2>/dev/null; then
        echo -e "${GREEN}✅ Server started successfully (PID: $SERVER_PID)${NC}"
        break
    fi
    if [ $i -eq 10 ]; then
        echo -e "${RED}❌ Server failed to start after 10 attempts${NC}"
        exit 1
    fi
    sleep 1
done

# Go back to project root
cd ..

echo "🎯 Starting fuzzing tests..."
echo "Output directory: $FUZZ_OUTPUT_DIR"

# Run comprehensive fuzzing test
echo "🧪 Running comprehensive fuzzing test (tools + protocol)..."
python -m mcp_fuzzer \
    --protocol stdio \
    --endpoint "node $SERVER_DIR/build/index.js" \
    --mode both \
    --runs 5 \
    --verbose \
    --enable-safety-system \
    --output-dir "$FUZZ_OUTPUT_DIR"

FUZZ_EXIT_CODE=$?
echo "Fuzzing test completed with exit code: $FUZZ_EXIT_CODE"

# Check if fuzzing produced expected output
if [ -d "$FUZZ_OUTPUT_DIR" ] && [ "$(ls -A $FUZZ_OUTPUT_DIR)" ]; then
    echo -e "${GREEN}✅ Fuzzing test completed successfully${NC}"
    echo "📊 Generated reports in: $FUZZ_OUTPUT_DIR"
    ls -la "$FUZZ_OUTPUT_DIR"

    # Check for expected vulnerabilities (should detect issues)
    if [ -f "$FUZZ_OUTPUT_DIR/fuzzing_results.json" ]; then
        echo "🔍 Checking for detected vulnerabilities..."
        # Count exceptions in the results
        EXCEPTION_COUNT=$(grep -o '"exceptions":[0-9]*' "$FUZZ_OUTPUT_DIR/fuzzing_results.json" | head -1 | grep -o '[0-9]*' || echo "0")
        if [ "$EXCEPTION_COUNT" -gt 0 ]; then
            echo -e "${GREEN}✅ Detected $EXCEPTION_COUNT exceptions (expected behavior)${NC}"
        else
            echo -e "${YELLOW}⚠️ No exceptions detected - this might indicate an issue${NC}"
        fi
    fi
else
    echo -e "${RED}❌ Fuzzing test failed to generate output${NC}"
    exit 1
fi

echo -e "\n${GREEN}🎉 MCP Server Chart System Test Completed Successfully!${NC}"
echo "=========================================="
echo "Server PID: $SERVER_PID"
echo "Output Directory: $FUZZ_OUTPUT_DIR"
echo "Exit Code: $FUZZ_EXIT_CODE"