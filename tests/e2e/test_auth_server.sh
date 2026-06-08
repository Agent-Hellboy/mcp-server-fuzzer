#!/bin/bash

# E2E test for OAuth client credentials auth against a local MCP HTTP server.

set -euo pipefail

echo "Starting Auth MCP Server E2E Test"
echo "=================================="

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
fi
PORT="${AUTH_E2E_PORT:-8765}"
HOST="127.0.0.1"
BASE_URL="http://${HOST}:${PORT}"
MCP_URL="${BASE_URL}/mcp/"
FUZZ_OUTPUT_DIR="/tmp/auth_server_fuzz_$(date +%s)"
AUTH_CONFIG="$(mktemp /tmp/mcp-fuzzer-auth-config.XXXXXX.json)"
SERVER_LOG="/tmp/mcp-fuzzer-auth-server-${PORT}.log"
SERVER_PID=""

cleanup() {
    echo "Cleaning up auth e2e resources"
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    rm -f "$AUTH_CONFIG"
}

trap cleanup EXIT

echo "Ensuring MCP Fuzzer is installed"
if ! "$PYTHON_BIN" -c "import mcp_fuzzer" >/dev/null 2>&1; then
    "$PYTHON_BIN" -m pip install -e "$PROJECT_ROOT"
fi
if ! "$PYTHON_BIN" -c "import mcp, uvicorn" >/dev/null 2>&1; then
    "$PYTHON_BIN" -m pip install "mcp[cli]" uvicorn
fi

echo "Starting authenticated MCP server on ${BASE_URL}"
"$PYTHON_BIN" "$PROJECT_ROOT/examples/auth_test_server.py" \
    --host "$HOST" \
    --port "$PORT" \
    --client-id "mcp-fuzzer" \
    --client-secret "mcp-fuzzer-secret" \
    --access-token "mcp-fuzzer-access-token" \
    >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

"$PYTHON_BIN" - "$BASE_URL" <<'PY'
import sys
import time
import urllib.request

base_url = sys.argv[1]
for _ in range(50):
    try:
        with urllib.request.urlopen(f"{base_url}/health", timeout=1) as response:
            if response.status == 200:
                raise SystemExit(0)
    except OSError:
        time.sleep(0.2)
raise SystemExit("auth e2e server did not become healthy")
PY

echo "Verifying secure_tool rejects unauthenticated calls"
"$PYTHON_BIN" - "$BASE_URL" <<'PY'
import json
import sys
import urllib.request

base_url = sys.argv[1]
payload = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": "unauth",
        "method": "tools/call",
        "params": {"name": "secure_tool", "arguments": {"msg": "precheck"}},
    }
).encode()
request = urllib.request.Request(
    f"{base_url}/mcp/",
    data=payload,
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=5) as response:
    result = json.loads(response.read().decode())
if result.get("error", {}).get("code") != -32001:
    raise SystemExit(f"expected secure_tool auth error, got {result}")
PY

cat >"$AUTH_CONFIG" <<EOF
{
  "default_provider": "machine",
  "providers": {
    "machine": {
      "type": "oauth_client_credentials",
      "token_url": "${BASE_URL}/oauth/token",
      "client_id": "mcp-fuzzer",
      "client_secret": "mcp-fuzzer-secret",
      "scope": "tools.read"
    }
  },
  "tool_mapping": {
    "secure_tool": "machine"
  }
}
EOF

echo "Running fuzzer against authenticated MCP server"
"$PYTHON_BIN" -m mcp_fuzzer \
    --protocol http \
    --endpoint "$MCP_URL" \
    --mode tools \
    --runs 3 \
    --auth-config "$AUTH_CONFIG" \
    --output-dir "$FUZZ_OUTPUT_DIR"

echo "Checking auth server metrics"
"$PYTHON_BIN" - "$BASE_URL" <<'PY'
import json
import sys
import urllib.request

base_url = sys.argv[1]
with urllib.request.urlopen(f"{base_url}/metrics", timeout=5) as response:
    metrics = json.loads(response.read().decode())

if metrics["token_requests"] < 1:
    raise SystemExit(f"expected token request, got metrics={metrics}")
if metrics["authorized_tool_calls"] < 1:
    raise SystemExit(f"expected authorized secure_tool calls, got metrics={metrics}")
if metrics["unauthorized_tool_calls"] < 1:
    raise SystemExit(f"expected unauthenticated secure_tool precheck, got {metrics}")
print(json.dumps(metrics, sort_keys=True))
PY

if [ ! -d "$FUZZ_OUTPUT_DIR" ] || [ ! "$(ls -A "$FUZZ_OUTPUT_DIR")" ]; then
    echo "Fuzzing did not generate output in $FUZZ_OUTPUT_DIR"
    echo "Server log:"
    cat "$SERVER_LOG"
    exit 1
fi

echo "Auth MCP Server E2E Test completed successfully"
echo "Output directory: $FUZZ_OUTPUT_DIR"
