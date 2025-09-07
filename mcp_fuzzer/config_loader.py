#!/usr/bin/env python3
"""Configuration file loader for MCP Fuzzer.

This module provides functionality to load configuration from YAML files.
"""

import os
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .config import config
from .exceptions import ConfigFileError
from .transport.custom import register_custom_transport
from .transport.base import TransportProtocol
import importlib

logger = logging.getLogger(__name__)


def find_config_file(
    config_path: Optional[str] = None,
    search_paths: Optional[list[str]] = None,
    file_names: Optional[list[str]] = None,
) -> Optional[str]:
    """Find a configuration file in the given paths.

    Args:
        config_path: Explicit path to config file, takes precedence if provided
        search_paths: List of directories to search for config files
        file_names: List of file names to search for

    Returns:
        Path to the found config file or None if not found
    """
    # If explicit path is provided, use it
    if config_path and os.path.isfile(config_path):
        return config_path

    # Default search paths
    if search_paths is None:
        search_paths = [
            os.getcwd(),  # Current directory
            str(Path.home() / ".config" / "mcp-fuzzer"),  # User config directory
        ]

    # Default file names
    if file_names is None:
        file_names = ["mcp-fuzzer.yml", "mcp-fuzzer.yaml"]

    # Search for config files
    for path in search_paths:
        if not os.path.isdir(path):
            continue

        for name in file_names:
            file_path = os.path.join(path, name)
            if os.path.isfile(file_path):
                return file_path

    return None


def load_config_file(file_path: str) -> Dict[str, Any]:
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

    # Verify file extension
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


def apply_config_file(
    config_path: Optional[str] = None,
    search_paths: Optional[list[str]] = None,
    file_names: Optional[list[str]] = None,
) -> bool:
    """Find and apply configuration from a file.

    Args:
        config_path: Explicit path to config file, takes precedence if provided
        search_paths: List of directories to search for config files
        file_names: List of file names to search for

    Returns:
        True if configuration was loaded and applied, False otherwise
    """
    try:
        # Find config file
        file_path = find_config_file(config_path, search_paths, file_names)
        if not file_path:
            logger.debug("No configuration file found")
            return False

        # Load config file
        logger.info(f"Loading configuration from {file_path}")
        config_data = load_config_file(file_path)

        # Load custom transports if configured
        load_custom_transports(config_data)

        # Apply configuration
        config.update(config_data)
        return True
    except Exception as e:
        logger.error(f"Error loading configuration file: {str(e)}")
        return False


def get_config_schema() -> Dict[str, Any]:
    """Get the configuration schema.

    Returns:
        Dictionary describing the configuration schema
    """
    return {
        "type": "object",
        "properties": {
            "timeout": {"type": "number", "description": "Default timeout in seconds"},
            "tool_timeout": {
                "type": "number",
                "description": "Tool-specific timeout in seconds",
            },
            "log_level": {
                "type": "string",
                "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            },
            "safety_enabled": {
                "type": "boolean",
                "description": "Whether safety features are enabled",
            },
            "fs_root": {
                "type": "string",
                "description": "Root directory for file operations",
            },
            "http_timeout": {
                "type": "number",
                "description": "HTTP transport timeout in seconds",
            },
            "sse_timeout": {
                "type": "number",
                "description": "SSE transport timeout in seconds",
            },
            "stdio_timeout": {
                "type": "number",
                "description": "STDIO transport timeout in seconds",
            },
            "mode": {"type": "string", "enum": ["tools", "protocol", "both"]},
            "phase": {"type": "string", "enum": ["realistic", "aggressive", "both"]},
            "protocol": {
                "type": "string",
                "enum": ["http", "https", "sse", "stdio", "streamablehttp"],
            },
            "endpoint": {"type": "string", "description": "Server endpoint URL"},
            "runs": {"type": "integer", "description": "Number of fuzzing runs"},
            "runs_per_type": {
                "type": "integer",
                "description": "Number of runs per protocol type",
            },
            "protocol_type": {
                "type": "string",
                "description": "Specific protocol type to fuzz",
            },
            "no_network": {"type": "boolean", "description": "Disable network access"},
            "allow_hosts": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of allowed hosts",
            },
            "max_concurrency": {
                "type": "integer",
                "description": "Maximum concurrent operations",
            },
            "auth": {
                "type": "object",
                "properties": {
                    "providers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "enum": ["api_key", "basic", "oauth", "custom"],
                                },
                                "id": {"type": "string"},
                                "config": {"type": "object"},
                            },
                            "required": ["type", "id"],
                        },
                    },
                    "mappings": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                },
            },
            "custom_transports": {
                "type": "object",
                "description": "Configuration for custom transport mechanisms",
                "patternProperties": {
                    "^[a-zA-Z][a-zA-Z0-9_]*$": {
                        "type": "object",
                        "properties": {
                            "module": {
                                "type": "string",
                                "description": "Python module containing transport",
                            },
                            "class": {
                                "type": "string",
                                "description": "Transport class name",
                            },
                            "description": {
                                "type": "string",
                                "description": "Human-readable description",
                            },
                            "factory": {
                                "type": "string",
                                "description": "Dotted path to factory function "
                                "(e.g., pkg.mod.create_transport)",
                            },
                            "config_schema": {
                                "type": "object",
                                "description": "JSON schema for transport config",
                            },
                        },
                        "additionalProperties": False,
                        "required": ["module", "class"],
                    }
                },
                "additionalProperties": False,
            },
            "safety": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "local_hosts": {"type": "array", "items": {"type": "string"}},
                    "no_network": {"type": "boolean"},
                    "header_denylist": {"type": "array", "items": {"type": "string"}},
                    "proxy_env_denylist": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "env_allowlist": {"type": "array", "items": {"type": "string"}},
                },
            },
            "output": {
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["json", "yaml", "csv", "xml"],
                        "description": "Output format for standardized reports",
                    },
                    "directory": {
                        "type": "string",
                        "description": "Directory to save output files",
                    },
                    "compress": {
                        "type": "boolean",
                        "description": "Whether to compress output files",
                    },
                    "types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "fuzzing_results",
                                "error_report",
                                "safety_summary",
                                "performance_metrics",
                                "configuration_dump",
                            ],
                        },
                        "description": "Specific output types to generate",
                    },
                    "schema": {
                        "type": "string",
                        "description": "Path to custom output schema file",
                    },
                    "retention": {
                        "type": "object",
                        "properties": {
                            "days": {
                                "type": "integer",
                                "description": "Number of days to retain output files",
                            },
                            "max_size": {
                                "type": "string",
                                "description": (
                                    "Maximum size of output directory "
                                    "(e.g., '1GB', '500MB')"
                                ),
                            },
                        },
                    },
                },
            },
        },
    }


def load_custom_transports(config_data: Dict[str, Any]) -> None:
    """Load and register custom transports from configuration.

    Args:
        config_data: Configuration dictionary containing custom_transports section
    """
    custom_transports = config_data.get("custom_transports", {})

    for transport_name, transport_config in custom_transports.items():
        try:
            # Import the module
            module_path = transport_config["module"]
            class_name = transport_config["class"]

            module = importlib.import_module(module_path)
            transport_class = getattr(module, class_name)
            if not isinstance(transport_class, type):
                raise ConfigFileError(f"{module_path}.{class_name} is not a class")
            if not issubclass(transport_class, TransportProtocol):
                raise ConfigFileError(
                    f"{module_path}.{class_name} must subclass TransportProtocol"
                )

            # Register the transport
            description = transport_config.get("description", "")
            config_schema = transport_config.get("config_schema")
            factory_fn = None
            factory_path = transport_config.get("factory")
            if factory_path:
                try:
                    mod_path, attr = factory_path.rsplit(".", 1)
                except ValueError as ve:
                    raise ConfigFileError(
                        f"Invalid factory path '{factory_path}'; expected 'module.attr'"
                    ) from ve
                fmod = importlib.import_module(mod_path)
                factory_fn = getattr(fmod, attr)
                if not callable(factory_fn):
                    raise ConfigFileError(f"Factory '{factory_path}' is not callable")

            register_custom_transport(
                name=transport_name,
                transport_class=transport_class,
                description=description,
                config_schema=config_schema,
                factory_function=factory_fn,
            )

            logger.info(
                f"Loaded custom transport '{transport_name}' from "
                f"{module_path}.{class_name}"
            )

        except Exception as e:
            logger.error(f"Failed to load custom transport '{transport_name}': {e}")
            raise ConfigFileError(
                f"Failed to load custom transport '{transport_name}': {e}"
            )
