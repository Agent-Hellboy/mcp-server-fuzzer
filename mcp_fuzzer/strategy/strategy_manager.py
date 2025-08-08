#!/usr/bin/env python3
"""
Strategy Manager

This module provides a unified interface for managing fuzzing strategies.
It handles the dispatch between realistic and aggressive phases.
"""

from typing import Any, Dict

from .realistic import (
    fuzz_tool_arguments_realistic,
    fuzz_initialize_request_realistic,
)
from .aggressive import (
    fuzz_tool_arguments_aggressive,
    fuzz_initialize_request_aggressive,
    get_protocol_fuzzer_method,
)


class ProtocolStrategies:
    """Unified protocol strategies with two-phase approach."""

    REALISTIC_PHASE = "realistic"
    AGGRESSIVE_PHASE = "aggressive"

    @staticmethod
    def fuzz_initialize_request(phase: str = "aggressive") -> Dict[str, Any]:
        """Generate fuzzed InitializeRequest based on phase."""
        if phase == ProtocolStrategies.REALISTIC_PHASE:
            return fuzz_initialize_request_realistic()
        else:
            return fuzz_initialize_request_aggressive()

    @staticmethod
    def get_protocol_fuzzer_method(protocol_type: str):
        """Get the fuzzer method for a specific protocol type."""
        # For now, we only support aggressive fuzzing for other protocols
        # InitializeRequest supports both phases
        if protocol_type == "InitializeRequest":
            return ProtocolStrategies.fuzz_initialize_request
        else:
            return get_protocol_fuzzer_method(protocol_type)


class ToolStrategies:
    """Unified tool strategies with two-phase approach."""

    REALISTIC_PHASE = "realistic"
    AGGRESSIVE_PHASE = "aggressive"

    @staticmethod
    def fuzz_tool_arguments(
        tool: Dict[str, Any], phase: str = "aggressive"
    ) -> Dict[str, Any]:
        """Generate fuzzed tool arguments based on phase."""
        if phase == ToolStrategies.REALISTIC_PHASE:
            return fuzz_tool_arguments_realistic(tool)
        else:
            return fuzz_tool_arguments_aggressive(tool)
