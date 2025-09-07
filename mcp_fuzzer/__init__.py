"""
MCP Fuzzer - Comprehensive fuzzing for MCP servers

This package provides tools for fuzzing MCP servers using multiple transport protocols.
"""

from .cli import create_argument_parser, get_cli_config
from .client import MCPFuzzerClient, UnifiedMCPFuzzerClient
from .fuzz_engine.fuzzer.protocol_fuzzer import ProtocolFuzzer
from .fuzz_engine.fuzzer.tool_fuzzer import ToolFuzzer
from .fuzz_engine.strategy import ProtocolStrategies, ToolStrategies

__version__ = "0.1.9"
__all__ = [
    "ToolFuzzer",
    "ProtocolFuzzer",
    "ToolStrategies",
    "ProtocolStrategies",
    "MCPFuzzerClient",
    "UnifiedMCPFuzzerClient",
    "get_cli_config",
    "create_argument_parser",
]
