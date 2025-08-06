"""
MCP Fuzzer - Comprehensive fuzzing for MCP servers

This package provides tools for fuzzing MCP servers using multiple transport protocols.
"""

from .client import UnifiedMCPFuzzerClient
from .client import main as unified_client_main
from .fuzzer.protocol_fuzzer import ProtocolFuzzer
from .fuzzer.tool_fuzzer import ToolFuzzer
from .strategy.protocol_strategies import ProtocolStrategies
from .strategy.tool_strategies import ToolStrategies

__version__ = "0.1.0"
__all__ = [
    "ToolFuzzer",
    "ProtocolFuzzer",
    "ToolStrategies",
    "ProtocolStrategies",
    "UnifiedMCPFuzzerClient",
    "unified_client_main",
]
