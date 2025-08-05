"""
MCP Fuzzer - A CLI tool for fuzzing MCP server tools using multiple transport protocols.
"""

from .client import fuzz_tool, main
from .strategies import make_fuzz_strategy_from_jsonschema
from .transport import TransportProtocol, create_transport

__version__ = "0.1.2"
__all__ = [
    "fuzz_tool",
    "main",
    "create_transport",
    "TransportProtocol",
    "make_fuzz_strategy_from_jsonschema",
]
