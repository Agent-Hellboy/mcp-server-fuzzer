#!/usr/bin/env python3
"""
Project-wide configuration constants.
"""

# MCP protocol version fallback used in initialize requests when none provided
DEFAULT_PROTOCOL_VERSION: str = "2025-06-18"

# HTTP headers and content-types
CONTENT_TYPE_HEADER: str = "content-type"
JSON_CONTENT_TYPE: str = "application/json"
SSE_CONTENT_TYPE: str = "text/event-stream"
DEFAULT_HTTP_ACCEPT: str = f"{JSON_CONTENT_TYPE}, {SSE_CONTENT_TYPE}"

# MCP headers
MCP_SESSION_ID_HEADER: str = "mcp-session-id"
MCP_PROTOCOL_VERSION_HEADER: str = "mcp-protocol-version"

# Watchdog tuning defaults used by transports when constructing WatchdogConfig
WATCHDOG_DEFAULT_CHECK_INTERVAL: float = 1.0
WATCHDOG_EXTRA_BUFFER: float = 5.0
# Additional seconds added to per-transport timeout for max hang time
WATCHDOG_MAX_HANG_ADDITIONAL: float = 10.0

# Safety defaults
# Hosts allowed for network operations by default. Keep local-only.
SAFETY_LOCAL_HOSTS: set[str] = {"localhost", "127.0.0.1", "::1"}
# Default to deny network to non-local hosts
SAFETY_NO_NETWORK_DEFAULT: bool = False
# Headers that should never be forwarded by default to avoid leakage
SAFETY_HEADER_DENYLIST: set[str] = {"authorization", "cookie"}
# Environment variables related to proxies that should be stripped by default
SAFETY_PROXY_ENV_DENYLIST: set[str] = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
}
# A minimal allowlist for environment keys to pass to subprocesses when
# sanitizing. Empty means passthrough except denied keys.
SAFETY_ENV_ALLOWLIST: set[str] = set()
