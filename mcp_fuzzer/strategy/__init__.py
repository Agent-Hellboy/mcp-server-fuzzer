"""
MCP Fuzzer Strategy Module

This module contains all Hypothesis-based data generation strategies for fuzzing
MCP tools and protocol types. The strategy system is organized into two phases:

- realistic/: Strategies for generating valid, expected data to test functionality
- aggressive/: Strategies for generating malicious, malformed data to test security
"""

# Import main strategy classes
from .strategy_manager import ProtocolStrategies, ToolStrategies

# Import realistic strategies
from .realistic import (
    base64_strings,
    uuid_strings,
    timestamp_strings,
    generate_realistic_text,
    fuzz_tool_arguments_realistic,
    json_rpc_id_values,
    method_names,
    protocol_version_strings,
    fuzz_initialize_request_realistic,
)

# Import aggressive strategies
from .aggressive import (
    generate_aggressive_text,
    fuzz_tool_arguments_aggressive,
    fuzz_initialize_request_aggressive,
)

__all__ = [
    # Main strategy classes
    "ProtocolStrategies",
    "ToolStrategies",
    # Realistic strategies
    "base64_strings",
    "uuid_strings",
    "timestamp_strings",
    "generate_realistic_text",
    "fuzz_tool_arguments_realistic",
    "json_rpc_id_values",
    "method_names",
    "protocol_version_strings",
    "fuzz_initialize_request_realistic",
    # Aggressive strategies
    "generate_aggressive_text",
    "fuzz_tool_arguments_aggressive",
    "fuzz_initialize_request_aggressive",
]
