#!/bin/bash

# Smoke-test the bundled Streamable HTTP example through the generic HTTP
# transport. For modern MCP spec versions, --protocol http should resolve to
# the Streamable HTTP driver.

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$PROJECT_ROOT/.tox/tests/bin/python}"
HOST="127.0.0.1"
PORT="${PORT:-3027}"
ENDPOINT="http://$HOST:$PORT/mcp/"
OUTPUT_DIR="/tmp/mcp_fuzzer_streamable_http_example_$(date +%s)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
fi

if ! "$PYTHON_BIN" -c "import mcp, uvicorn, starlette" >/dev/null 2>&1; then
    echo "Skipping: optional example server dependencies are not installed"
    exit 0
fi

"$PYTHON_BIN" "$PROJECT_ROOT/examples/streamable_http_server.py" \
    --host "$HOST" \
    --port "$PORT" \
    --log-level WARNING &
SERVER_PID=$!

READY=0
for _ in $(seq 1 50); do
    if "$PYTHON_BIN" -c "import socket; s=socket.create_connection(('$HOST', $PORT), 0.2); s.close()" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.1
done

if [ "$READY" -ne 1 ]; then
    echo "Streamable HTTP example server did not start on $ENDPOINT"
    exit 1
fi

"$PYTHON_BIN" -m mcp_fuzzer \
    --mode tools \
    --phase realistic \
    --protocol http \
    --endpoint "$ENDPOINT" \
    --runs 1 \
    --timeout 10 \
    --fail-if-no-tools \
    --no-network \
    --output-dir "$OUTPUT_DIR"

"$PYTHON_BIN" - "$OUTPUT_DIR" <<'PY'
import json
import sys
from pathlib import Path

output_dir = Path(sys.argv[1])
reports = sorted(output_dir.glob("sessions/*/*_fuzzing_results.json"))
if not reports:
    raise SystemExit("No fuzzing results report was generated")

latest = reports[-1]
data = json.loads(latest.read_text(encoding="utf-8"))["data"]
tools = data.get("tools_tested", [])
if not tools:
    raise SystemExit(f"No tools were fuzzed in {latest}")

names = {tool.get("name") for tool in tools}
if "start-notification-stream" not in names:
    raise SystemExit(f"Expected example tool was not fuzzed in {latest}: {names}")
PY

echo "Streamable HTTP example smoke passed: $OUTPUT_DIR"
