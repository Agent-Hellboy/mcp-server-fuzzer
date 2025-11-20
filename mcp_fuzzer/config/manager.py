#!/usr/bin/env python3
"""Configuration management for MCP Fuzzer."""

import os
from typing import Any


def load_env_config() -> dict[str, Any]:
    """Return configuration derived from environment variables."""

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

    return {
        "timeout": _get_float("MCP_FUZZER_TIMEOUT", 30.0),
        "log_level": os.getenv("MCP_FUZZER_LOG_LEVEL", "INFO"),
        "safety_enabled": _get_bool("MCP_FUZZER_SAFETY_ENABLED", False),
        "fs_root": os.getenv("MCP_FUZZER_FS_ROOT", os.path.expanduser("~/.mcp_fuzzer")),
        "http_timeout": _get_float("MCP_FUZZER_HTTP_TIMEOUT", 30.0),
        "sse_timeout": _get_float("MCP_FUZZER_SSE_TIMEOUT", 30.0),
        "stdio_timeout": _get_float("MCP_FUZZER_STDIO_TIMEOUT", 30.0),
    }


class Configuration:
    """Simple in-memory configuration store."""

    def __init__(self):
        self._config: dict[str, Any] = load_env_config()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key."""
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        self._config[key] = value

    def update(self, config_dict: dict[str, Any]) -> None:
        """Update configuration with values from a dictionary."""
        self._config.update(config_dict)

    def get_all(self) -> dict[str, Any]:
        """Get a shallow copy of the configuration."""
        return dict(self._config)

    def clear(self) -> None:
        """Clear all configuration values."""
        self._config.clear()


# Global configuration instance
config = Configuration()
