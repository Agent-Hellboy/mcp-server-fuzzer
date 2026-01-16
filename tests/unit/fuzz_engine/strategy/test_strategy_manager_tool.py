"""
Unit tests for ToolStrategies from strategy_manager.py.
"""

import unittest
import pytest
from mcp_fuzzer.fuzz_engine.mutators.strategies import ToolStrategies


class TestToolStrategies(unittest.TestCase):
    """Test cases for ToolStrategies class."""

    @pytest.mark.asyncio
    async def test_fuzz_tool_arguments_basic(self):
        """Test fuzz_tool_arguments generates arguments for tools."""
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
        result = await ToolStrategies.fuzz_tool_arguments(tool)
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result), 0)

    @pytest.mark.asyncio
    async def test_fuzz_tool_arguments_edge_cases(self):
        """Test fuzz_tool_arguments handles edge cases."""
        # No schema
        result = await ToolStrategies.fuzz_tool_arguments({"name": "no_schema_tool"})
        self.assertIsInstance(result, dict)
        
        # Empty schema
        result = await ToolStrategies.fuzz_tool_arguments(
            {"name": "empty_schema_tool", "inputSchema": {}}
        )
        self.assertIsInstance(result, dict)
        
        # Missing inputSchema
        result = await ToolStrategies.fuzz_tool_arguments(
            {"name": "missing_schema_tool"}
        )
        self.assertIsInstance(result, dict)

    @pytest.mark.asyncio
    async def test_fuzz_tool_arguments_phases(self):
        """Test realistic and aggressive phases."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"param": {"type": "string"}}},
        }
        
        realistic_result = await ToolStrategies.fuzz_tool_arguments(
            tool, phase="realistic"
        )
        aggressive_result = await ToolStrategies.fuzz_tool_arguments(
            tool, phase="aggressive"
        )
        default_result = await ToolStrategies.fuzz_tool_arguments(tool)
        
        self.assertIsInstance(realistic_result, dict)
        self.assertIsInstance(aggressive_result, dict)
        self.assertIsInstance(default_result, dict)

    @pytest.mark.asyncio
    async def test_fuzz_tool_arguments_complex_schema(self):
        """Test fuzz_tool_arguments handles complex schemas."""
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
        result = await ToolStrategies.fuzz_tool_arguments(tool)
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result), 0)


if __name__ == "__main__":
    unittest.main()
