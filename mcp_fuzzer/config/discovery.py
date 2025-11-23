#!/usr/bin/env python3
"""Helpers for locating configuration files."""

from __future__ import annotations

import os
from pathlib import Path


def find_config_file(
    config_path: str | None = None,
    search_paths: list[str] | None = None,
    file_names: list[str] | None = None,
) -> str | None:
    """Find a configuration file in the given paths.

    Args:
        config_path: Explicit path to config file, takes precedence if provided
        search_paths: List of directories to search for config files
        file_names: List of file names to search for

    Returns:
        Path to the found config file or None if not found
    """
    if config_path and os.path.isfile(config_path):
        return config_path

    if search_paths is None:
        search_paths = [
            os.getcwd(),
            str(Path.home() / ".config" / "mcp-fuzzer"),
        ]

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
