#!/usr/bin/env python3
"""Helpers for locating configuration files."""

from __future__ import annotations

import os
from pathlib import Path

from .search_params import ConfigSearchParams


def find_config_file(
    config_path: str | None = None,
    search_paths: list[str] | None = None,
    file_names: list[str] | None = None,
) -> str | None:
    """Find a configuration file in the given paths.

    Args:
        config_path: Explicit path to config file, authoritative if provided
        search_paths: List of directories to search for config files
        file_names: List of file names to search for

    Returns:
        Path to the found config file or None if not found
    """
    params = ConfigSearchParams(
        config_path=config_path,
        search_paths=search_paths,
        file_names=file_names,
    )
    return _find_config_file_impl(params)


def find_config_file_from_params(params: ConfigSearchParams) -> str | None:
    """Find a configuration file using ConfigSearchParams.

    Args:
        params: Configuration search parameters

    Returns:
        Path to the found config file or None if not found
    """
    return _find_config_file_impl(params)


def _find_config_file_impl(params: ConfigSearchParams) -> str | None:
    """Internal implementation of config file discovery.

    Args:
        params: Configuration search parameters

    Returns:
        Path to the found config file or None if not found. If an explicit
        config_path is provided, it is authoritative and no fallback search
        occurs when it is missing.
    """
    if params.config_path is not None:
        return params.config_path if os.path.isfile(params.config_path) else None

    search_paths = params.search_paths
    if search_paths is None:
        search_paths = [
            os.getcwd(),
            str(Path.home() / ".config" / "mcp-fuzzer"),
        ]

    file_names = params.file_names
    if file_names is None:
        file_names = ["mcp-fuzzer.yml", "mcp-fuzzer.yaml"]

    for path in search_paths:
        if not os.path.isdir(path):
            continue
        for name in file_names:
            file_path = os.path.join(path, name)
            if os.path.isfile(file_path):
                return file_path

    return None
