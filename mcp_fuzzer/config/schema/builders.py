#!/usr/bin/env python3
"""Schema builder functions for configuration validation."""

from __future__ import annotations

from typing import Any


def build_timeout_schema() -> dict[str, Any]:
    """Build schema for timeout-related configuration."""
    return {
        "timeout": {"type": "number", "description": "Default timeout in seconds"},
        "tool_timeout": {
            "type": "number",
            "description": "Tool-specific timeout in seconds",
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
    }


def build_basic_schema() -> dict[str, Any]:
    """Build schema for basic configuration properties."""
    return {
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
    }


def build_fuzzing_schema() -> dict[str, Any]:
    """Build schema for fuzzing-related configuration."""
    return {
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
        "max_concurrency": {
            "type": "integer",
            "description": "Maximum concurrent operations",
        },
    }


def build_network_schema() -> dict[str, Any]:
    """Build schema for network-related configuration."""
    return {
        "no_network": {"type": "boolean", "description": "Disable network access"},
        "allow_hosts": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of allowed hosts",
        },
    }


def build_auth_schema() -> dict[str, Any]:
    """Build schema for authentication configuration."""
    return {
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
    }


def build_custom_transports_schema() -> dict[str, Any]:
    """Build schema for custom transport configuration."""
    return {
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
    }


def build_safety_schema() -> dict[str, Any]:
    """Build schema for safety configuration."""
    return {
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
    }


def build_output_schema() -> dict[str, Any]:
    """Build schema for output configuration."""
    return {
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
    }

