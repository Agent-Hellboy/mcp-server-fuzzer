#!/usr/bin/env python3
"""Schema helpers for configuration validation."""

from __future__ import annotations

from typing import Any


def get_config_schema() -> dict[str, Any]:
    """Return the JSON schema describing the configuration structure."""
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
