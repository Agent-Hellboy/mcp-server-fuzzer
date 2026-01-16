#!/bin/bash

# Docker wrapper for Everything MCP Server E2E Test

set -e

echo "🐳 Starting Everything Server E2E Test (Docker)"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKERFILE="$PROJECT_ROOT/tests/e2e/Dockerfile"
IMAGE_NAME="mcp-fuzzer-e2e:latest"
SCHEMA_VERSION="${MCP_SPEC_SCHEMA_VERSION:-2025-11-25}"

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not available in PATH${NC}"
    exit 1
fi

echo -e "${BLUE}🏗️ Building Docker image: $IMAGE_NAME${NC}"
docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" "$PROJECT_ROOT"

echo -e "${BLUE}🚀 Running e2e test in container...${NC}"
docker run --rm \
    -v "$PROJECT_ROOT:/workspace" \
    -w /workspace \
    -e MCP_FUZZER_IN_DOCKER=1 \
    -e "MCP_SPEC_SCHEMA_VERSION=$SCHEMA_VERSION" \
    "$IMAGE_NAME" \
    bash -lc "./tests/e2e/test_everything_server.sh"

echo -e "${GREEN}✅ Docker e2e test completed${NC}"
