#!/usr/bin/env python3
"""Configuration port interface for Port and Adapter pattern.

This module defines the port (interface) for configuration access.
All modules should interact with configuration through this port,
not directly with the config module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ConfigPort(ABC):
    """Port interface for configuration access.

    This defines the contract that all configuration adapters must implement.
    Modules should depend on this interface, not concrete implementations.
    """

    @abstractmethod
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        pass

    @abstractmethod
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value.

        Args:
            key: Configuration key
            value: Configuration value
        """
        pass

    @abstractmethod
    def update(self, config_dict: dict[str, Any]) -> None:
        """Update configuration with values from a dictionary.

        Args:
            config_dict: Dictionary of configuration values to update
        """
        pass

    @abstractmethod
    def load_file(self, file_path: str) -> dict[str, Any]:
        """Load configuration from a file.

        Args:
            file_path: Path to configuration file

        Returns:
            Dictionary containing loaded configuration

        Raises:
            ConfigFileError: If file cannot be loaded
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def get_schema(self) -> dict[str, Any]:
        """Get the JSON schema for configuration validation.

        Returns:
            JSON schema dictionary
        """
        pass
