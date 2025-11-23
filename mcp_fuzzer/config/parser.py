#!/usr/bin/env python3
"""YAML configuration parsing utilities."""

from __future__ import annotations

import os
from typing import Any

import yaml

from ..exceptions import ConfigFileError


def load_config_file(file_path: str) -> dict[str, Any]:
    """Load configuration from a YAML file.

    Args:
        file_path: Path to the configuration file

    Returns:
        Dictionary containing the configuration

    Raises:
        ConfigFileError: If the file cannot be found, parsed, or has permission issues
    """
    if not os.path.isfile(file_path):
        raise ConfigFileError(f"Configuration file not found: {file_path}")

    if not file_path.endswith((".yml", ".yaml")):
        raise ConfigFileError(
            f"Unsupported configuration file format: {file_path}. "
            "Only YAML files with .yml or .yaml extensions are supported."
        )

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigFileError(
            f"Error parsing YAML configuration file {file_path}: {str(e)}"
        )
    except PermissionError:
        raise ConfigFileError(
            f"Permission denied when reading configuration file: {file_path}"
        )
    except Exception as e:
        raise ConfigFileError(
            f"Unexpected error reading configuration file {file_path}: {str(e)}"
        )
