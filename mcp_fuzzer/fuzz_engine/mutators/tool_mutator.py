#!/usr/bin/env python3
"""
Tool Mutator

This module contains the mutation logic for generating fuzzed tool arguments.
"""

from typing import Any

from .base import Mutator
from .strategies import ToolStrategies


class ToolMutator(Mutator):
    """Generates fuzzed tool arguments."""

    def __init__(self):
        """Initialize the tool mutator."""
        self.strategies = ToolStrategies()

    async def mutate(
        self, tool: dict[str, Any], phase: str = "aggressive"
    ) -> dict[str, Any]:
        """
        Generate fuzzed arguments for a tool.

        Args:
            tool: Tool definition
            phase: Fuzzing phase (realistic or aggressive)

        Returns:
            Dictionary of fuzzed tool arguments
        """
        return await self.strategies.fuzz_tool_arguments(tool, phase=phase)
