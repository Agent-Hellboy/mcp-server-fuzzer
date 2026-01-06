#!/usr/bin/env python3
"""Configuration loader helpers that glue the discovery/parser stack."""

from __future__ import annotations

import logging
from typing import Any, Callable

from ..core.manager import Configuration, config
from ..extensions.transports import load_custom_transports
from ..schema.composer import get_config_schema  # noqa: F401 (exported for consumers)
from .discovery import find_config_file
from .parser import load_config_file
from .search_params import ConfigSearchParams
from ...exceptions import ConfigFileError, MCPError

logger = logging.getLogger(__name__)

ConfigDict = dict[str, Any]
FileDiscoverer = Callable[[str | None, list[str] | None, list[str] | None], str | None]
ConfigParser = Callable[[str], ConfigDict]
TransportLoader = Callable[[ConfigDict], None]


class ConfigLoader:
    """Load configuration files with injectable discovery and parser implementations.

    This class reduces coupling by accepting a Configuration instance rather than
    always using the global config object.
    """

    def __init__(
        self,
        discoverer: FileDiscoverer | None = None,
        parser: ConfigParser | None = None,
        transport_loader: TransportLoader | None = None,
        config_instance: Configuration | None = None,
    ):
        self.discoverer = find_config_file if discoverer is None else discoverer
        self.parser = load_config_file if parser is None else parser
        self.transport_loader = (
            load_custom_transports if transport_loader is None else transport_loader
        )
        self.config = config if config_instance is None else config_instance

    def load(
        self,
        config_path: str | None = None,
        search_paths: list[str] | None = None,
        file_names: list[str] | None = None,
    ) -> tuple[ConfigDict | None, str | None]:
        """Return the configuration dictionary and source file path.

        Args:
            config_path: Explicit path to config file
            search_paths: List of directories to search
            file_names: List of file names to search for

        Returns:
            Tuple of (config_dict, file_path) or (None, None) if not found
        """
        file_path = self.discoverer(config_path, search_paths, file_names)
        if not file_path:
            logger.debug("No configuration file found")
            return None, None

        logger.debug("Loading configuration from %s", file_path)
        try:
            config_data = self.parser(file_path)
            self.transport_loader(config_data)
        except (ConfigFileError, MCPError) as exc:
            logger.debug("Failed to load configuration from %s: %s", file_path, exc)
            raise
        except Exception:
            logger.exception(
                "Unexpected error while loading configuration from %s", file_path
            )
            raise

        return config_data, file_path

    def load_from_params(
        self, params: ConfigSearchParams
    ) -> tuple[ConfigDict | None, str | None]:
        """Load configuration using ConfigSearchParams.

        Args:
            params: Configuration search parameters

        Returns:
            Tuple of (config_dict, file_path) or (None, None) if not found
        """
        return self.load(
            config_path=params.config_path,
            search_paths=params.search_paths,
            file_names=params.file_names,
        )

    def apply(
        self,
        config_path: str | None = None,
        search_paths: list[str] | None = None,
        file_names: list[str] | None = None,
    ) -> bool:
        """Load configuration and merge it into the runtime state.

        Args:
            config_path: Explicit path to config file
            search_paths: List of directories to search
            file_names: List of file names to search for

        Returns:
            True if configuration was loaded and applied, False otherwise
        """
        try:
            config_data, file_path = self.load(config_path, search_paths, file_names)
        except (ConfigFileError, MCPError) as e:
            logger.debug("Failed to apply configuration: %s", e)
            return False

        if not file_path:
            return False

        self.config.update(config_data or {})
        return True

    def apply_from_params(self, params: ConfigSearchParams) -> bool:
        """Apply configuration using ConfigSearchParams.

        Args:
            params: Configuration search parameters

        Returns:
            True if configuration was loaded and applied, False otherwise
        """
        return self.apply(
            config_path=params.config_path,
            search_paths=params.search_paths,
            file_names=params.file_names,
        )


def apply_config_file(
    config_path: str | None = None,
    search_paths: list[str] | None = None,
    file_names: list[str] | None = None,
) -> bool:
    """Convenience helper that uses the default loader to update global config.

    Args:
        config_path: Explicit path to config file
        search_paths: List of directories to search
        file_names: List of file names to search for

    Returns:
        True if configuration was loaded and applied, False otherwise
    """
    loader = ConfigLoader()
    return loader.apply(
        config_path=config_path,
        search_paths=search_paths,
        file_names=file_names,
    )
