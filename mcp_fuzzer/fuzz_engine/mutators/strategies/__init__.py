"""
Strategy Module

This module provides unified interfaces for managing fuzzing strategies.
"""

from .realistic import (
    base64_strings,
    uuid_strings,
    timestamp_strings,
    json_rpc_id_values,
    method_names,
    protocol_version_strings,
    generate_realistic_text,
    fuzz_tool_arguments_realistic,
)

from .aggressive import (
    fuzz_tool_arguments_aggressive,
)

from .strategy_manager import ProtocolStrategies, ToolStrategies
from .registry import StrategyRegistry, strategy_registry
from .spec_protocol import get_spec_protocol_fuzzer_method

__all__ = [
    # Realistic strategies
    "base64_strings",
    "uuid_strings",
    "timestamp_strings",
    "json_rpc_id_values",
    "method_names",
    "protocol_version_strings",
    "generate_realistic_text",
    "fuzz_tool_arguments_realistic",
    # Aggressive strategies
    "fuzz_tool_arguments_aggressive",
    # Unified interfaces
    "ProtocolStrategies",
    "ToolStrategies",
    "get_spec_protocol_fuzzer_method",
    "StrategyRegistry",
    "strategy_registry",
]
