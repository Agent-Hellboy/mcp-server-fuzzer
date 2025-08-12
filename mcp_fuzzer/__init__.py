"""
MCP Fuzzer - Comprehensive fuzzing for MCP servers

This package provides tools for fuzzing MCP servers using multiple transport protocols.
"""

from .cli import create_argument_parser, get_cli_config, run_cli
from .client import UnifiedMCPFuzzerClient
from .client import main as unified_client_main
from .fuzz_engine.fuzzer.protocol_fuzzer import ProtocolFuzzer
from .fuzz_engine.fuzzer.tool_fuzzer import ToolFuzzer
from .fuzz_engine.strategy import ProtocolStrategies, ToolStrategies

__version__ = "0.1.6"
__all__ = [
    "ToolFuzzer",
    "ProtocolFuzzer",
    "ToolStrategies",
    "ProtocolStrategies",
    "UnifiedMCPFuzzerClient",
    "unified_client_main",
    "run_cli",
    "get_cli_config",
    "create_argument_parser",
]
