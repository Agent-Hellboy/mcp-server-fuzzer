"""
MCP Fuzzer - Comprehensive fuzzing for MCP servers

This package provides tools for fuzzing MCP servers using multiple transport protocols.
"""

import sys

if sys.version_info < (3, 10):
    raise RuntimeError(
        f"MCP Fuzzer requires Python 3.10+ (found {sys.version.split()[0]}). "
        "Use a supported interpreter (e.g., tox envs or a 3.10+ venv)."
    )

from .cli import create_argument_parser, build_cli_config
from .client import MCPFuzzerClient
from .fuzz_engine import (
    ToolMutator,
    ProtocolMutator,
    BatchMutator,
    ToolExecutor,
    ProtocolExecutor,
    BatchExecutor,
    ProtocolStrategies,
    ToolStrategies,
)

__version__ = "0.1.9"
__all__ = [
    "ToolMutator",
    "ProtocolMutator",
    "BatchMutator",
    "ToolExecutor",
    "ProtocolExecutor",
    "BatchExecutor",
    "ToolStrategies",
    "ProtocolStrategies",
    "MCPFuzzerClient",
    "create_argument_parser",
    "build_cli_config",
]
