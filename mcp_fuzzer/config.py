#!/usr/bin/env python3
"""Project-wide configuration constants and management."""

import os
from typing import Dict, Any

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

# Default fuzzing run counts
DEFAULT_TOOL_RUNS: int = 10
DEFAULT_PROTOCOL_RUNS_PER_TYPE: int = 5

# Default timeout values in seconds
DEFAULT_TIMEOUT: float = 30.0
DEFAULT_TOOL_TIMEOUT: float = 30.0
DEFAULT_MAX_TOOL_TIME: float = 60.0
DEFAULT_MAX_TOTAL_FUZZING_TIME: float = 300.0
DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT: float = 2.0
DEFAULT_FORCE_KILL_TIMEOUT: float = 1.0


class Configuration:
    """Centralized configuration management for MCP Fuzzer."""

    def __init__(self):
        self._config: Dict[str, Any] = {}
        self._load_from_env()

    def _load_from_env(self) -> None:
        """Load configuration values from environment variables."""

        def _get_float(key: str, default: float) -> float:
            try:
                return float(os.getenv(key, str(default)))
            except (TypeError, ValueError):
                return default

        def _get_bool(key: str, default: bool = False) -> bool:
            val = os.getenv(key)
            if val is None:
                return default
            return val.strip().lower() in {"1", "true", "yes", "on"}

        self._config["timeout"] = _get_float("MCP_FUZZER_TIMEOUT", 30.0)
        self._config["log_level"] = os.getenv("MCP_FUZZER_LOG_LEVEL", "INFO")
        self._config["safety_enabled"] = _get_bool("MCP_FUZZER_SAFETY_ENABLED", False)
        self._config["fs_root"] = os.getenv(
            "MCP_FUZZER_FS_ROOT", os.path.expanduser("~/.mcp_fuzzer")
        )
        self._config["http_timeout"] = _get_float("MCP_FUZZER_HTTP_TIMEOUT", 30.0)
        self._config["sse_timeout"] = _get_float("MCP_FUZZER_SSE_TIMEOUT", 30.0)
        self._config["stdio_timeout"] = _get_float("MCP_FUZZER_STDIO_TIMEOUT", 30.0)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key."""
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        self._config[key] = value

    def update(self, config_dict: Dict[str, Any]) -> None:
        """Update configuration with values from a dictionary."""
        self._config.update(config_dict)


# Global configuration instance
config = Configuration()
