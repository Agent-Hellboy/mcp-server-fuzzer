"""
MCP Fuzzer - Comprehensive fuzzing for MCP servers

This package provides tools for fuzzing MCP servers using multiple transport protocols.
"""

try:
    from .cli import create_argument_parser, get_cli_config
except ImportError:
    # CLI dependencies not available
    create_argument_parser = None
    get_cli_config = None

from .client import MCPFuzzerClient, UnifiedMCPFuzzerClient

try:
    from .fuzz_engine.fuzzer.protocol_fuzzer import ProtocolFuzzer
    from .fuzz_engine.fuzzer.tool_fuzzer import ToolFuzzer
    from .fuzz_engine.strategy import ProtocolStrategies, ToolStrategies
except ImportError:
    # Fuzz engine dependencies not available
    ProtocolFuzzer = None
    ToolFuzzer = None
    ProtocolStrategies = None
    ToolStrategies = None

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
