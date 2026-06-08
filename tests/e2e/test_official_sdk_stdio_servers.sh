#!/bin/bash

# E2E test for bundled official Go and TypeScript MCP SDK stdio servers.

set -euo pipefail

echo "Starting Official SDK Stdio Server E2E Test"
echo "==========================================="

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
fi
GO_SERVER_DIR="$PROJECT_ROOT/examples/go_stdio_server"
TS_SERVER_DIR="$PROJECT_ROOT/examples/typescript-stdio-server"
GO_BIN="/tmp/mcp-fuzzer-go-stdio-server"
GO_OUTPUT_DIR="/tmp/go_sdk_stdio_fuzz_$(date +%s)"
TS_OUTPUT_DIR="/tmp/typescript_sdk_stdio_fuzz_$(date +%s)"
export GOCACHE="${GOCACHE:-/tmp/mcp-fuzzer-go-build-cache}"

echo "Ensuring MCP Fuzzer is installed"
if ! "$PYTHON_BIN" -c "import mcp_fuzzer" >/dev/null 2>&1; then
    "$PYTHON_BIN" -m pip install -e "$PROJECT_ROOT"
fi

echo "Building official Go SDK stdio server"
(cd "$GO_SERVER_DIR" && go mod download && go build -o "$GO_BIN" .)

echo "Fuzzing Go SDK stdio server"
"$PYTHON_BIN" -m mcp_fuzzer \
    --protocol stdio \
    --endpoint "$GO_BIN" \
    --mode tools \
    --runs 2 \
    --timeout 30 \
    --output-dir "$GO_OUTPUT_DIR"

echo "Installing and building official TypeScript SDK stdio server"
if [ -f "$TS_SERVER_DIR/package-lock.json" ]; then
    (cd "$TS_SERVER_DIR" && npm ci && npm run build)
else
    (cd "$TS_SERVER_DIR" && npm install && npm run build)
fi

echo "Fuzzing TypeScript SDK stdio server"
"$PYTHON_BIN" -m mcp_fuzzer \
    --protocol stdio \
    --endpoint "node $TS_SERVER_DIR/dist/server.js" \
    --mode tools \
    --runs 2 \
    --timeout 30 \
    --output-dir "$TS_OUTPUT_DIR"

for output_dir in "$GO_OUTPUT_DIR" "$TS_OUTPUT_DIR"; do
    if [ ! -d "$output_dir" ] || [ ! "$(ls -A "$output_dir")" ]; then
        echo "Fuzzing did not generate output in $output_dir"
        exit 1
    fi
    "$PYTHON_BIN" - "$output_dir" <<'PY'
import json
import pathlib
import sys

output_dir = pathlib.Path(sys.argv[1])
reports = sorted(output_dir.glob("sessions/*/*_fuzzing_results.json"))
if not reports:
    raise SystemExit(f"missing fuzzing results report in {output_dir}")

with reports[-1].open() as handle:
    report = json.load(handle)

data = report.get("data", {})
if data.get("total_tools", 0) < 1:
    raise SystemExit(f"expected at least one fuzzed tool in {reports[-1]}")
PY
done

echo "Official SDK stdio server e2e test completed successfully"
echo "Go output directory: $GO_OUTPUT_DIR"
echo "TypeScript output directory: $TS_OUTPUT_DIR"
