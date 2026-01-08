#!/usr/bin/env python3
"""Configuration adapter implementation for Port and Adapter pattern.

This module implements the ConfigPort interface by adapting the config module.
This is the adapter that mediates all configuration access.
"""

from __future__ import annotations

from typing import Any

from ...config import ConfigLoader, get_config_schema, load_config_file
from ...config.core.manager import config as global_config
from ..ports.config_port import ConfigPort


class ConfigAdapter(ConfigPort):
    """Adapter that implements ConfigPort by delegating to the config module.

    This adapter acts as a mediator between other modules and the config module,
    implementing the Port and Adapter (Hexagonal Architecture) pattern.
    """

    def __init__(self, config_instance: Any = None):
        """Initialize the config adapter.

        Args:
            config_instance: Optional configuration instance to use.
                If None, uses the global config instance.
        """
        self._config = config_instance or global_config

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value.

        Args:
            key: Configuration key
            value: Configuration value
        """
        self._config.set(key, value)

    def update(self, config_dict: dict[str, Any]) -> None:
        """Update configuration with values from a dictionary.

        Args:
            config_dict: Dictionary of configuration values to update
        """
        self._config.update(config_dict)

    def load_file(self, file_path: str) -> dict[str, Any]:
        """Load configuration from a file.

        Args:
            file_path: Path to configuration file

        Returns:
            Dictionary containing loaded configuration

        Raises:
            ConfigFileError: If file cannot be loaded
        """
        return load_config_file(file_path)

    def apply_file(
        self,
        config_path: str | None = None,
        search_paths: list[str] | None = None,
        file_names: list[str] | None = None,
    ) -> bool:
        """Load and apply configuration from a file.

        Args:
            config_path: Explicit path to config file
            search_paths: List of directories to search
            file_names: List of file names to search for

        Returns:
            True if configuration was loaded and applied, False otherwise
        """
        loader = ConfigLoader(config_instance=self._config)
        return loader.apply(
            config_path=config_path,
            search_paths=search_paths,
            file_names=file_names,
        )

    def get_schema(self) -> dict[str, Any]:
        """Get the JSON schema for configuration validation.

        Returns:
            JSON schema dictionary
        """
        return get_config_schema()


# Global instance for convenience (acts as the mediator)
config_mediator: ConfigPort = ConfigAdapter()
