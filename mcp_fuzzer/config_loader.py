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
        with open(file_path, "r") as f:
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
        
        # Apply configuration
        config.update(config_data)
        return True
    except Exception as e:
        logger.warning(f"Error loading configuration file: {str(e)}")
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
                "description": "Tool-specific timeout in seconds"
            },
            "log_level": {
                "type": "string", 
                "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            },
            "safety_enabled": {
                "type": "boolean", 
                "description": "Whether safety features are enabled"
            },
            "fs_root": {
                "type": "string", 
                "description": "Root directory for file operations"
            },
            "http_timeout": {
                "type": "number", 
                "description": "HTTP transport timeout in seconds"
            },
            "sse_timeout": {
                "type": "number", 
                "description": "SSE transport timeout in seconds"
            },
            "stdio_timeout": {
                "type": "number", 
                "description": "STDIO transport timeout in seconds"
            },
            "mode": {"type": "string", "enum": ["tools", "protocol", "both"]},
            "phase": {"type": "string", "enum": ["realistic", "aggressive", "both"]},
            "protocol": {"type": "string", "enum": ["http", "sse", "stdio"]},
            "endpoint": {"type": "string", "description": "Server endpoint URL"},
            "runs": {"type": "integer", "description": "Number of fuzzing runs"},
            "runs_per_type": {
                "type": "integer", 
                "description": "Number of runs per protocol type"
            },
            "protocol_type": {
                "type": "string", 
                "description": "Specific protocol type to fuzz"
            },
            "no_network": {"type": "boolean", "description": "Disable network access"},
            "allow_hosts": {
                "type": "array", 
                "items": {"type": "string"}, 
                "description": "List of allowed hosts"
            },
            "max_concurrency": {
                "type": "integer", 
                "description": "Maximum concurrent operations"
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
                                    "enum": ["api_key", "basic", "oauth", "custom"]
                                },
                                "id": {"type": "string"},
                                "config": {"type": "object"}
                            },
                            "required": ["type", "id"]
                        }
                    },
                    "mappings": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    }
                }
            },
            "safety": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "local_hosts": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "no_network": {"type": "boolean"},
                    "header_denylist": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "proxy_env_denylist": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "env_allowlist": {
                        "type": "array",
                        "items": {"type": "string"}
                    }
                }
            }
        }
    }
