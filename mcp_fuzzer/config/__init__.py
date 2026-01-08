#!/usr/bin/env python3
"""Configuration module for MCP Fuzzer."""

# Import all constants and core functionality
from .core import (
    CONTENT_TYPE_HEADER,
    DEFAULT_FORCE_KILL_TIMEOUT,
    DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
    DEFAULT_HTTP_ACCEPT,
    DEFAULT_MAX_TOTAL_FUZZING_TIME,
    DEFAULT_MAX_TOOL_TIME,
    DEFAULT_PROTOCOL_RUNS_PER_TYPE,
    DEFAULT_PROTOCOL_VERSION,
    DEFAULT_TIMEOUT,
    DEFAULT_TOOL_RUNS,
    DEFAULT_TOOL_TIMEOUT,
    JSON_CONTENT_TYPE,
    MCP_PROTOCOL_VERSION_HEADER,
    MCP_SESSION_ID_HEADER,
    PROCESS_CLEANUP_TIMEOUT,
    PROCESS_FORCE_KILL_TIMEOUT,
    PROCESS_TERMINATION_TIMEOUT,
    PROCESS_WAIT_TIMEOUT,
    SAFETY_ENV_ALLOWLIST,
    SAFETY_HEADER_DENYLIST,
    SAFETY_LOCAL_HOSTS,
    SAFETY_NO_NETWORK_DEFAULT,
    SAFETY_PROXY_ENV_DENYLIST,
    SSE_CONTENT_TYPE,
    WATCHDOG_DEFAULT_CHECK_INTERVAL,
    WATCHDOG_EXTRA_BUFFER,
    WATCHDOG_MAX_HANG_ADDITIONAL,
    config,
)

# Import loader functions
from .loading import (
    ConfigLoader,
    ConfigSearchParams,
    apply_config_file,
    find_config_file,
    load_config_file,
)

# Import schema
from .schema import get_config_schema

# Import extensions
from .extensions import load_custom_transports

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
    "PROCESS_TERMINATION_TIMEOUT",
    "PROCESS_FORCE_KILL_TIMEOUT",
    "PROCESS_CLEANUP_TIMEOUT",
    "PROCESS_WAIT_TIMEOUT",
    # Manager
    "config",
    # Loader helpers
    "ConfigLoader",
    "find_config_file",
    "load_config_file",
    "apply_config_file",
    "get_config_schema",
    "load_custom_transports",
    # Search parameters
    "ConfigSearchParams",
]
