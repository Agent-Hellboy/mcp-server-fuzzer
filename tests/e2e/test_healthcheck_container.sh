#!/usr/bin/env bash

# Smoke-test the distroless image healthcheck.

set -euo pipefail

IMAGE="${IMAGE:-mcp-fuzzer:latest}"

echo "[healthcheck] Running container healthcheck against ${IMAGE}"
docker run --rm --entrypoint /usr/bin/python3 "$IMAGE" -m mcp_fuzzer.healthcheck --verbose

echo "[healthcheck] Success"
