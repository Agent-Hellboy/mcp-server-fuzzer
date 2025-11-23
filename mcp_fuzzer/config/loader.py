#!/usr/bin/env python3
"""Configuration loader helpers that glue the discovery/parser stack."""

from __future__ import annotations

import logging
from typing import Any, Callable, Tuple

from .discovery import find_config_file
from .manager import config
from .parser import load_config_file
from .schema import get_config_schema  # noqa: F401 (exported for consumers)
from .transports import load_custom_transports
from ..exceptions import ConfigFileError, MCPError

logger = logging.getLogger(__name__)

ConfigDict = dict[str, Any]
FileDiscoverer = Callable[
    [str | None, list[str] | None, list[str] | None], str | None
]
ConfigParser = Callable[[str], ConfigDict]
TransportLoader = Callable[[ConfigDict], None]


class ConfigLoader:
    """Load configuration files with injectable discovery and parser implementations."""

    def __init__(
        self,
        discoverer: FileDiscoverer | None = None,
        parser: ConfigParser | None = None,
        transport_loader: TransportLoader | None = None,
    ):
        self.discoverer = discoverer or find_config_file
        self.parser = parser or load_config_file
        self.transport_loader = transport_loader or load_custom_transports

    def load(
        self,
        config_path: str | None = None,
        search_paths: list[str] | None = None,
        file_names: list[str] | None = None,
    ) -> Tuple[ConfigDict | None, str | None]:
        """Return the configuration dictionary and source file path."""
        file_path = self.discoverer(config_path, search_paths, file_names)
        if not file_path:
            logger.debug("No configuration file found")
            return None, None

        logger.info("Loading configuration from %s", file_path)
        try:
            config_data = self.parser(file_path)
            self.transport_loader(config_data)
        except (ConfigFileError, MCPError):
            logger.exception("Failed to load configuration from %s", file_path)
            raise

        return config_data, file_path

    def apply(
        self,
        config_path: str | None = None,
        search_paths: list[str] | None = None,
        file_names: list[str] | None = None,
    ) -> bool:
        """Load configuration and merge it into the runtime state."""
        try:
            config_data, file_path = self.load(config_path, search_paths, file_names)
        except (ConfigFileError, MCPError):
            return False

        if not file_path:
            return False

        config.update(config_data or {})
        return True


def apply_config_file(
    config_path: str | None = None,
    search_paths: list[str] | None = None,
    file_names: list[str] | None = None,
) -> bool:
    """Convenience helper that uses the default loader to update global config."""

    loader = ConfigLoader()
    return loader.apply(
        config_path=config_path,
        search_paths=search_paths,
        file_names=file_names,
    )
