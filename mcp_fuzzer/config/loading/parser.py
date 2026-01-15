#!/usr/bin/env python3
"""YAML configuration parsing utilities."""

from __future__ import annotations

import logging
import os
from typing import Any

import yaml

from ...exceptions import ConfigFileError

logger = logging.getLogger(__name__)


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
            data = yaml.safe_load(f) or {}

        # Validate that top-level config is a mapping/object
        if not isinstance(data, dict):
            raise ConfigFileError(
                f"Top-level configuration in {file_path} must be a mapping/object, "
                f"got {type(data).__name__}"
            )

        if "output_dir" in data:
            logger.warning(
                "Config key 'output_dir' is deprecated; use 'output.directory' instead."
            )
            output_section = data.get("output")
            if output_section is not None and not isinstance(output_section, dict):
                logger.warning(
                    "Config key 'output' must be a mapping; replacing invalid value."
                )
            if not isinstance(output_section, dict):
                output_section = {}
                data["output"] = output_section
            output_section.setdefault("directory", data["output_dir"])
            data.pop("output_dir", None)

        return data
    except yaml.YAMLError as e:
        raise ConfigFileError(
            f"Error parsing YAML configuration file {file_path}: {e}"
        ) from e
    except PermissionError as e:
        raise ConfigFileError(
            f"Permission denied when reading configuration file: {file_path}"
        ) from e
    except ConfigFileError:
        # Re-raise ConfigFileError as-is (already has proper context)
        raise
    except Exception as e:
        raise ConfigFileError(
            f"Unexpected error reading configuration file {file_path}: {e}"
        ) from e
