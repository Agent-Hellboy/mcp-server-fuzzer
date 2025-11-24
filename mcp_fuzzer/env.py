from enum import Enum
from typing import Any, TypedDict

class ValidationType(Enum):
    """Types of validation for environment variables."""

    CHOICE = "choice"
    BOOLEAN = "boolean"
    NUMERIC = "numeric"
    STRING = "string"

class EnvironmentVariable(TypedDict):
    """Definition for an environment variable with validation rules."""

    name: str
    default: str
    validation_type: str  # ValidationType value
    validation_params: dict[str, Any]  # e.g., {"choices": ["DEBUG", "INFO", ...]}
    description: str

# Environment variable registry
ENVIRONMENT_VARIABLES: list[EnvironmentVariable] = [
    {
        "name": "MCP_FUZZER_TIMEOUT",
        "default": "30.0",
        "validation_type": "numeric",
        "validation_params": {},
        "description": "Request timeout in seconds",
    },
    {
        "name": "MCP_FUZZER_LOG_LEVEL",
        "default": "INFO",
        "validation_type": "choice",
        "validation_params": {
            "choices": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        },
        "description": "Logging verbosity level",
    },
    {
        "name": "MCP_FUZZER_SAFETY_ENABLED",
        "default": "false",
        "validation_type": "boolean",
        "validation_params": {},
        "description": "Enable safety system features",
    },
    {
        "name": "MCP_FUZZER_FS_ROOT",
        "default": "~/.mcp_fuzzer",
        "validation_type": "string",
        "validation_params": {},
        "description": "Filesystem sandbox root directory",
    },
    {
        "name": "MCP_FUZZER_AUTO_KILL",
        "default": "true",
        "validation_type": "boolean",
        "validation_params": {},
        "description": "Automatically kill hanging processes",
    },
]
