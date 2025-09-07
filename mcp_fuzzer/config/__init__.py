#!/usr/bin/env python3
"""Configuration module for MCP Fuzzer."""

# Import all constants explicitly
from .constants import (
    DEFAULT_PROTOCOL_VERSION,
    CONTENT_TYPE_HEADER,
    JSON_CONTENT_TYPE,
    SSE_CONTENT_TYPE,
    DEFAULT_HTTP_ACCEPT,
    MCP_SESSION_ID_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    WATCHDOG_DEFAULT_CHECK_INTERVAL,
    WATCHDOG_EXTRA_BUFFER,
    WATCHDOG_MAX_HANG_ADDITIONAL,
    SAFETY_LOCAL_HOSTS,
    SAFETY_NO_NETWORK_DEFAULT,
    SAFETY_HEADER_DENYLIST,
    SAFETY_PROXY_ENV_DENYLIST,
    SAFETY_ENV_ALLOWLIST,
    DEFAULT_TOOL_RUNS,
    DEFAULT_PROTOCOL_RUNS_PER_TYPE,
    DEFAULT_TIMEOUT,
    DEFAULT_TOOL_TIMEOUT,
    DEFAULT_MAX_TOOL_TIME,
    DEFAULT_MAX_TOTAL_FUZZING_TIME,
    DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
    DEFAULT_FORCE_KILL_TIMEOUT,
)

# Import configuration manager and global instance
from .manager import config

# Import loader functions
from .loader import (
    find_config_file,
    load_config_file,
    apply_config_file,
    get_config_schema,
    load_custom_transports,
)

__all__ = [
    # Constants
    "DEFAULT_PROTOCOL_VERSION",
    "CONTENT_TYPE_HEADER",
    "JSON_CONTENT_TYPE",
    "SSE_CONTENT_TYPE",
    "DEFAULT_HTTP_ACCEPT",
    "MCP_SESSION_ID_HEADER",
    "MCP_PROTOCOL_VERSION_HEADER",
    "WATCHDOG_DEFAULT_CHECK_INTERVAL",
    "WATCHDOG_EXTRA_BUFFER",
    "WATCHDOG_MAX_HANG_ADDITIONAL",
    "SAFETY_LOCAL_HOSTS",
    "SAFETY_NO_NETWORK_DEFAULT",
    "SAFETY_HEADER_DENYLIST",
    "SAFETY_PROXY_ENV_DENYLIST",
    "SAFETY_ENV_ALLOWLIST",
    "DEFAULT_TOOL_RUNS",
    "DEFAULT_PROTOCOL_RUNS_PER_TYPE",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TOOL_TIMEOUT",
    "DEFAULT_MAX_TOOL_TIME",
    "DEFAULT_MAX_TOTAL_FUZZING_TIME",
    "DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT",
    "DEFAULT_FORCE_KILL_TIMEOUT",
    # Manager
    "config",
    # Loader functions
    "find_config_file",
    "load_config_file",
    "apply_config_file",
    "get_config_schema",
    "load_custom_transports",
]