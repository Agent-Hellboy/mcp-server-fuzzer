#!/usr/bin/env python3
"""Configuration management for MCP Fuzzer."""

import os
from typing import Any

class Configuration:
    """Centralized configuration management for MCP Fuzzer."""

    def __init__(self):
        self._config: dict[str, Any] = {}
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

    def update(self, config_dict: dict[str, Any]) -> None:
        """Update configuration with values from a dictionary."""
        self._config.update(config_dict)

# Global configuration instance
config = Configuration()