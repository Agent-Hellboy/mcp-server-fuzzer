#!/usr/bin/env python3
"""Configuration search parameters dataclass to group related parameters."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfigSearchParams:
    """Parameters for searching and loading configuration files.

    Groups related configuration search parameters to reduce parameter
    list length and improve code clarity.

    Attributes:
        config_path: Explicit path to config file, takes precedence if provided
        search_paths: List of directories to search for config files
        file_names: List of file names to search for
    """

    config_path: str | None = None
    search_paths: list[str] | None = None
    file_names: list[str] | None = None
