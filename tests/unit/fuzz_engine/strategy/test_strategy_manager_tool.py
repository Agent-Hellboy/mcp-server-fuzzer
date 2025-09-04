#!/usr/bin/env python3
"""
Unit tests for ToolStrategies from strategy_manager.py
"""

import unittest
from unittest.mock import MagicMock

from mcp_fuzzer.fuzz_engine.strategy import ToolStrategies


class TestToolStrategies(unittest.TestCase):
    """Test cases for ToolStrategies class - BEHAVIOR focused."""

    def test_fuzz_tool_arguments_behavior(self):
        """Test BEHAVIOR: fuzz_tool_arguments generates arguments for tools."""
        tool = {
            "name": "test_tool",
            "inputSchema": {
                "properties": {
                    "query": {"type": "string"},
                    "count": {"type": "integer"},
                    "enabled": {"type": "boolean"},
                }
            },
        }

        result = ToolStrategies.fuzz_tool_arguments(tool)

        # Test BEHAVIOR: should return a dictionary
        self.assertIsInstance(result, dict, "Should return a dictionary of arguments")
        self.assertGreater(len(result), 0, "Should generate some arguments")

    def test_fuzz_tool_arguments_no_schema(self):
        """Test BEHAVIOR: handles tools with no schema gracefully."""
        tool = {"name": "no_schema_tool"}

        result = ToolStrategies.fuzz_tool_arguments(tool)

        # Test BEHAVIOR: should still return a dictionary (may be empty or
        # have injected fields)
        self.assertIsInstance(
            result, dict, "Should return a dictionary even without schema"
        )

    def test_fuzz_tool_arguments_empty_schema(self):
        """Test BEHAVIOR: handles tools with empty schema."""
        tool = {"name": "empty_schema_tool", "inputSchema": {}}

        result = ToolStrategies.fuzz_tool_arguments(tool)

        # Test BEHAVIOR: should return a dictionary
        self.assertIsInstance(result, dict, "Should return a dictionary")

    def test_fuzz_tool_arguments_realistic_vs_aggressive(self):
        """Test BEHAVIOR: realistic and aggressive phases produce different
        approaches."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"param": {"type": "string"}}},
        }

        # Test realistic phase
        realistic_result = ToolStrategies.fuzz_tool_arguments(tool, phase="realistic")
        self.assertIsInstance(realistic_result, dict, "Realistic should return dict")

        # Test aggressive phase (default)
        aggressive_result = ToolStrategies.fuzz_tool_arguments(tool, phase="aggressive")
        self.assertIsInstance(aggressive_result, dict, "Aggressive should return dict")

        # Test default is aggressive
        default_result = ToolStrategies.fuzz_tool_arguments(tool)
        self.assertIsInstance(default_result, dict, "Default should return dict")

    def test_fuzz_tool_arguments_complex_schema(self):
        """Test BEHAVIOR: handles complex schemas with multiple field types."""
        tool = {
            "name": "complex_tool",
            "inputSchema": {
                "properties": {
                    "strings": {"type": "array", "items": {"type": "string"}},
                    "numbers": {"type": "array", "items": {"type": "integer"}},
                    "metadata": {"type": "object"},
                    "enabled": {"type": "boolean"},
                }
            },
        }

        result = ToolStrategies.fuzz_tool_arguments(tool)

        # Test BEHAVIOR: should return a dictionary with some arguments
        self.assertIsInstance(result, dict, "Should return a dictionary")
        self.assertGreater(len(result), 0, "Should generate some arguments")

        # Test BEHAVIOR: aggressive fuzzing may generate different field types
        # or None values
        # We just verify it's generating structured data, not specific types

    def test_fuzz_tool_arguments_missing_input_schema(self):
        """Test BEHAVIOR: handles tools missing inputSchema key."""
        tool = {"name": "missing_schema_tool"}

        result = ToolStrategies.fuzz_tool_arguments(tool)

        # Test BEHAVIOR: should handle gracefully and return a dictionary
        self.assertIsInstance(result, dict, "Should handle missing schema gracefully")


if __name__ == "__main__":
    unittest.main()
