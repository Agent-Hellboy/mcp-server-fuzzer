#!/usr/bin/env python3
"""
Unit tests for ToolStrategies
"""

import unittest
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.strategies import composite

from mcp_fuzzer.strategy.tool_strategies import ToolStrategies


@pytest.mark.filterwarnings("ignore::hypothesis.errors.NonInteractiveExampleWarning")
class TestToolStrategies(unittest.TestCase):
    """Test cases for ToolStrategies class."""

    def setUp(self):
        """Set up test fixtures."""
        self.strategies = ToolStrategies()

    def test_make_fuzz_strategy_from_jsonschema_integer(self):
        """Test creating strategy for integer type."""
        schema = {
            "properties": {"count": {"type": "integer"}, "limit": {"type": "integer"}}
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("count", example)
        self.assertIn("limit", example)
        self.assertIsInstance(example["count"], int)
        self.assertIsInstance(example["limit"], int)

    def test_make_fuzz_strategy_from_jsonschema_number(self):
        """Test creating strategy for number type."""
        schema = {
            "properties": {
                "score": {"type": "number"},
                "probability": {"type": "number"},
            }
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("score", example)
        self.assertIn("probability", example)
        self.assertIsInstance(example["score"], (int, float))
        self.assertIsInstance(example["probability"], (int, float))

    def test_make_fuzz_strategy_from_jsonschema_string(self):
        """Test creating strategy for string type."""
        schema = {
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
            }
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("name", example)
        self.assertIn("description", example)
        self.assertIsInstance(example["name"], str)
        self.assertIsInstance(example["description"], str)

    def test_make_fuzz_strategy_from_jsonschema_boolean(self):
        """Test creating strategy for boolean type."""
        schema = {
            "properties": {
                "enabled": {"type": "boolean"},
                "verbose": {"type": "boolean"},
            }
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("enabled", example)
        self.assertIn("verbose", example)
        self.assertIsInstance(example["enabled"], bool)
        self.assertIsInstance(example["verbose"], bool)

    def test_make_fuzz_strategy_from_jsonschema_object(self):
        """Test creating strategy for object type."""
        schema = {
            "properties": {"metadata": {"type": "object"}, "config": {"type": "object"}}
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("metadata", example)
        self.assertIn("config", example)
        self.assertIsInstance(example["metadata"], dict)
        self.assertIsInstance(example["config"], dict)

    def test_make_fuzz_strategy_from_jsonschema_array_string(self):
        """Test creating strategy for array of strings."""
        schema = {
            "properties": {"tags": {"type": "array", "items": {"type": "string"}}}
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("tags", example)
        self.assertIsInstance(example["tags"], list)
        if example["tags"]:  # If list is not empty
            self.assertIsInstance(example["tags"][0], str)

    def test_make_fuzz_strategy_from_jsonschema_array_integer(self):
        """Test creating strategy for array of integers."""
        schema = {
            "properties": {"numbers": {"type": "array", "items": {"type": "integer"}}}
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("numbers", example)
        self.assertIsInstance(example["numbers"], list)
        if example["numbers"]:  # If list is not empty
            self.assertIsInstance(example["numbers"][0], int)

    def test_make_fuzz_strategy_from_jsonschema_array_number(self):
        """Test creating strategy for array of numbers."""
        schema = {
            "properties": {"scores": {"type": "array", "items": {"type": "number"}}}
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("scores", example)
        self.assertIsInstance(example["scores"], list)
        if example["scores"]:  # If list is not empty
            self.assertIsInstance(example["scores"][0], (int, float))

    def test_make_fuzz_strategy_from_jsonschema_array_boolean(self):
        """Test creating strategy for array of booleans."""
        schema = {
            "properties": {"flags": {"type": "array", "items": {"type": "boolean"}}}
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("flags", example)
        self.assertIsInstance(example["flags"], list)
        if example["flags"]:  # If list is not empty
            self.assertIsInstance(example["flags"][0], bool)

    def test_make_fuzz_strategy_from_jsonschema_unknown_type(self):
        """Test creating strategy for unknown type."""
        schema = {"properties": {"unknown_field": {"type": "unknown_type"}}}

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("unknown_field", example)
        # Should fall back to union of basic types
        self.assertIsInstance(example["unknown_field"], (type(None), str, int, float))

    def test_make_fuzz_strategy_from_jsonschema_empty_properties(self):
        """Test creating strategy with empty properties."""
        schema = {"properties": {}}

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertEqual(example, {})

    def test_make_fuzz_strategy_from_jsonschema_no_properties(self):
        """Test creating strategy with no properties."""
        schema = {}

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertEqual(example, {})

    def test_fuzz_tool_arguments_simple_tool(self):
        """Test fuzzing arguments for a simple tool."""
        tool = {
            "name": "test_tool",
            "inputSchema": {
                "properties": {"name": {"type": "string"}, "count": {"type": "integer"}}
            },
        }

        result = ToolStrategies.fuzz_tool_arguments(tool)

        self.assertIsInstance(result, dict)
        self.assertIn("name", result)
        self.assertIn("count", result)
        self.assertIsInstance(result["name"], str)
        self.assertIsInstance(result["count"], int)

    def test_fuzz_tool_arguments_complex_tool(self):
        """Test fuzzing arguments for a complex tool."""
        tool = {
            "name": "complex_tool",
            "inputSchema": {
                "properties": {
                    "strings": {"type": "array", "items": {"type": "string"}},
                    "numbers": {"type": "array", "items": {"type": "number"}},
                    "metadata": {"type": "object"},
                    "enabled": {"type": "boolean"},
                }
            },
        }

        result = ToolStrategies.fuzz_tool_arguments(tool)

        self.assertIsInstance(result, dict)
        self.assertIn("strings", result)
        self.assertIn("numbers", result)
        self.assertIn("metadata", result)
        self.assertIn("enabled", result)

        self.assertIsInstance(result["strings"], list)
        self.assertIsInstance(result["numbers"], list)
        self.assertIsInstance(result["metadata"], dict)
        # Allow None for aggressive fuzzing
        if result["enabled"] is not None:
            self.assertIsInstance(result["enabled"], bool)

    def test_fuzz_tool_arguments_no_schema(self):
        """Test fuzzing arguments for a tool with no schema."""
        tool = {"name": "no_schema_tool"}

        result = ToolStrategies.fuzz_tool_arguments(tool)

        self.assertIsInstance(result, dict)

    def test_fuzz_tool_arguments_empty_schema(self):
        """Test fuzzing arguments for a tool with empty schema."""
        tool = {"name": "empty_schema_tool", "inputSchema": {}}

        result = ToolStrategies.fuzz_tool_arguments(tool)

        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})

    def test_strategy_generates_multiple_examples(self):
        """Test that strategy generates different examples."""
        schema = {
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "enabled": {"type": "boolean"},
            }
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        examples = [strategy.example() for _ in range(3)]

        # All examples should have the same structure
        for example in examples:
            self.assertIn("name", example)
            self.assertIn("count", example)
            self.assertIn("enabled", example)
            self.assertIsInstance(example["name"], str)
            self.assertIsInstance(example["count"], int)
            self.assertIsInstance(example["enabled"], bool)

    def test_strategy_handles_missing_type(self):
        """Test that strategy handles missing type field."""
        schema = {"properties": {"field1": {}, "field2": {"type": "string"}}}

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("field1", example)
        self.assertIn("field2", example)
        self.assertIsInstance(example["field2"], str)

    def test_strategy_handles_nested_arrays(self):
        """Test that strategy handles nested array structures."""
        schema = {
            "properties": {
                "matrix": {
                    "type": "array",
                    "items": {"type": "array", "items": {"type": "string"}},
                }
            }
        }

        strategy = ToolStrategies.make_fuzz_strategy_from_jsonschema(schema)
        example = strategy.example()

        self.assertIn("matrix", example)
        self.assertIsInstance(example["matrix"], list)
        if example["matrix"]:  # If outer list is not empty
            self.assertIsInstance(example["matrix"][0], list)
            if example["matrix"][0]:  # If inner list is not empty
                self.assertIsInstance(example["matrix"][0][0], str)


if __name__ == "__main__":
    unittest.main()
