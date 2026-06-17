#!/usr/bin/env python3
"""Configuration management for MCP Fuzzer."""

import os
from typing import Any


def _get_float_from_env(key: str, default: float) -> float:
    """Get a float value from environment variable.

    Args:
        key: Environment variable name
        default: Default value if not set or invalid

    Returns:
        Float value from environment or default
    """
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _get_bool_from_env(key: str, default: bool = False) -> bool:
    """Get a boolean value from environment variable.

    Args:
        key: Environment variable name
        default: Default value if not set

    Returns:
        Boolean value from environment or default
    """
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


class Configuration:
    """Centralized configuration management for MCP Fuzzer."""

    def __init__(self):
        self._config: dict[str, Any] = {}
        self._load_from_env()

    def _load_from_env(self) -> None:
        """Load configuration values from environment variables."""
        self._config["timeout"] = _get_float_from_env("MCP_FUZZER_TIMEOUT", 30.0)
        self._config["log_level"] = os.getenv("MCP_FUZZER_LOG_LEVEL", "INFO")
        self._config["safety_enabled"] = _get_bool_from_env(
            "MCP_FUZZER_SAFETY_ENABLED", False
        )
        self._config["fs_root"] = os.getenv(
            "MCP_FUZZER_FS_ROOT", os.path.expanduser("~/.mcp_fuzzer")
        )
        self._config["http_timeout"] = _get_float_from_env(
            "MCP_FUZZER_HTTP_TIMEOUT", 30.0
        )
        self._config["sse_timeout"] = _get_float_from_env(
            "MCP_FUZZER_SSE_TIMEOUT", 30.0
        )
        self._config["stdio_timeout"] = _get_float_from_env(
            "MCP_FUZZER_STDIO_TIMEOUT", 30.0
        )

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key."""
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        self._config[key] = value

    def update(self, config_dict: dict[str, Any]) -> None:
        """Update configuration with values from a dictionary."""
        self._config.update(config_dict)


# Global configuration instance
config = Configuration()
