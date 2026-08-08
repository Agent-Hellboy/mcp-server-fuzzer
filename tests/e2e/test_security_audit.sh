#!/bin/bash

# E2E coverage for the server security audit.
#
# Runs --security-audit against the bundled Streamable HTTP example and then
# repeats it with --security-audit-intrusive so the foreign-Origin probe is
# exercised against a real server rather than a mock. The target is a local
# example server owned by this repo, so the intrusive probe is in scope.

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$PROJECT_ROOT/.tox/tests/bin/python}"
HOST="127.0.0.1"
PORT="${PORT:-3031}"
ENDPOINT="http://$HOST:$PORT/mcp/"
OUTPUT_DIR="/tmp/mcp_fuzzer_security_audit_$(date +%s)"
SCHEMA_VERSION="${MCP_SPEC_SCHEMA_VERSION:-2025-11-25}"
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

echo "Running read-only security audit..."
"$PYTHON_BIN" -m mcp_fuzzer \
    --mode tools \
    --phase realistic \
    --protocol streamablehttp \
    --endpoint "$ENDPOINT" \
    --runs 1 \
    --timeout 10 \
    --spec-schema-version "$SCHEMA_VERSION" \
    --security-audit \
    --fail-if-no-tools \
    --output-dir "$OUTPUT_DIR/readonly"

echo "Running intrusive security audit (foreign-Origin probe)..."
"$PYTHON_BIN" -m mcp_fuzzer \
    --mode tools \
    --phase realistic \
    --protocol streamablehttp \
    --endpoint "$ENDPOINT" \
    --runs 1 \
    --timeout 10 \
    --spec-schema-version "$SCHEMA_VERSION" \
    --security-audit \
    --security-audit-intrusive \
    --fail-if-no-tools \
    --output-dir "$OUTPUT_DIR/intrusive"

"$PYTHON_BIN" - "$OUTPUT_DIR" <<'PY'
import json
import sys
from pathlib import Path

from mcp_fuzzer.diagnostics.server import SERVER_AUDIT_FLAW_CATEGORIES

root = Path(sys.argv[1])

for phase in ("readonly", "intrusive"):
    reports = sorted((root / phase).glob("sessions/*/*_fuzzing_results.json"))
    if not reports:
        raise SystemExit(f"No fuzzing results report generated for {phase}")

    findings_file = root / phase / "findings.json"
    if not findings_file.exists():
        raise SystemExit(f"No findings.json written for {phase}")

    payload = json.loads(findings_file.read_text(encoding="utf-8"))
    findings = payload if isinstance(payload, list) else payload.get("findings", [])

    # The audit must run and stay inside its declared vocabulary. A clean
    # target legitimately yields no server-audit findings, so assert on the
    # categories that *are* present rather than requiring a hit.
    categories = {f.get("category") for f in findings if isinstance(f, dict)}
    unknown_audit = {
        c
        for c in categories
        if c in SERVER_AUDIT_FLAW_CATEGORIES
    }
    print(f"{phase}: {len(findings)} finding(s); audit categories: {sorted(unknown_audit)}")

    if phase == "intrusive":
        origin = [
            f
            for f in findings
            if isinstance(f, dict)
            and f.get("category")
            in {"missing_origin_validation", "origin_validation_inconclusive"}
        ]
        for f in origin:
            evidence = f.get("evidence", {})
            if evidence.get("origin") != "https://mcp-fuzzer.invalid":
                raise SystemExit(f"Unexpected probe origin in {f}")
            print(f"  origin probe -> {f['category']} (HTTP {evidence.get('response_status')})")
PY

echo "Security audit e2e passed: $OUTPUT_DIR"
