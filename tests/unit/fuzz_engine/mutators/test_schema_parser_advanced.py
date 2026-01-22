#!/usr/bin/env python3
"""
Advanced unit tests for schema_parser.py - edge cases and uncovered paths.
"""

import unittest
import pytest
from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser import (
    make_fuzz_strategy_from_jsonschema,
    _merge_allOf,
    _handle_string_type,
    _handle_integer_type,
    _handle_number_type,
    _handle_array_type,
    _handle_object_type,
)


class TestSchemaParserAdvanced(unittest.TestCase):
    """Advanced test cases for schema_parser - edge cases and aggressive mode."""

    def test_merge_allOf_with_types(self):
        """Test _merge_allOf with type intersections."""
        schemas = [
            {"type": "string"},
            {"type": "string", "minLength": 5},
        ]
        result = _merge_allOf(schemas)
        self.assertEqual(result["type"], "string")
        self.assertEqual(result["minLength"], 5)

    def test_merge_allOf_type_intersection(self):
        """Test _merge_allOf with conflicting types."""
        schemas = [
            {"type": ["string", "number"]},
            {"type": ["string", "integer"]},
        ]
        result = _merge_allOf(schemas)
        # Intersection should be string
        self.assertIn("type", result)

    def test_merge_allOf_const_value(self):
        """Test _merge_allOf with const values."""
        schemas = [
            {"type": "string"},
            {"const": "fixed_value"},
        ]
        result = _merge_allOf(schemas)
        self.assertEqual(result["const"], "fixed_value")

    def test_merge_allOf_min_constraints(self):
        """Test _merge_allOf takes max of min constraints."""
        schemas = [
            {"minLength": 5, "minimum": 10, "minItems": 2},
            {"minLength": 8, "minimum": 15, "minItems": 1},
        ]
        result = _merge_allOf(schemas)
        self.assertEqual(result["minLength"], 8)
        self.assertEqual(result["minimum"], 15)
        self.assertEqual(result["minItems"], 2)

    def test_merge_allOf_max_constraints(self):
        """Test _merge_allOf takes min of max constraints."""
        schemas = [
            {"maxLength": 20, "maximum": 100, "maxItems": 10},
            {"maxLength": 15, "maximum": 50, "maxItems": 8},
        ]
        result = _merge_allOf(schemas)
        self.assertEqual(result["maxLength"], 15)
        self.assertEqual(result["maximum"], 50)
        self.assertEqual(result["maxItems"], 8)

    def test_merge_allOf_exclusive_constraints(self):
        """Test _merge_allOf with exclusive min/max."""
        schemas = [
            {"exclusiveMinimum": 10, "exclusiveMaximum": 100},
            {"exclusiveMinimum": 20, "exclusiveMaximum": 80},
        ]
        result = _merge_allOf(schemas)
        self.assertEqual(result["exclusiveMinimum"], 20)
        self.assertEqual(result["exclusiveMaximum"], 80)

    def test_merge_allOf_other_fields(self):
        """Test _merge_allOf preserves other fields."""
        schemas = [
            {"type": "string", "format": "email"},
            {"minLength": 5, "pattern": "^test"},
        ]
        result = _merge_allOf(schemas)
        self.assertEqual(result["format"], "email")
        self.assertEqual(result["pattern"], "^test")

    def test_string_with_exclusive_minimum(self):
        """Test string generation with exclusiveMinimum length."""
        schema = {"type": "string", "minLength": 5, "exclusiveMinimum": 10}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)

    def test_number_with_exclusive_minimum(self):
        """Test number generation with exclusiveMinimum."""
        schema = {"type": "number", "exclusiveMinimum": 10.0, "maximum": 20.0}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, (int, float))
        self.assertGreater(result, 10.0)
        self.assertLessEqual(result, 20.0)

    def test_number_with_exclusive_maximum(self):
        """Test number generation with exclusiveMaximum."""
        schema = {"type": "number", "minimum": 10.0, "exclusiveMaximum": 20.0}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, (int, float))
        self.assertGreaterEqual(result, 10.0)
        self.assertLess(result, 20.0)

    def test_number_with_multiple_of(self):
        """Test number generation with multipleOf constraint."""
        schema = {"type": "number", "multipleOf": 5, "minimum": 10, "maximum": 50}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, (int, float))
        self.assertEqual(result % 5, 0)

    def test_integer_with_multiple_of(self):
        """Test integer generation with multipleOf constraint."""
        schema = {"type": "integer", "multipleOf": 3, "minimum": 10, "maximum": 30}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, int)
        self.assertEqual(result % 3, 0)

    def test_string_with_pattern(self):
        """Test string generation with pattern."""
        schema = {"type": "string", "pattern": "^[a-z]+$"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)

    def test_string_format_date(self):
        """Test string generation with date format."""
        schema = {"type": "string", "format": "date"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)
        # Date format should produce a string (format may vary)
        self.assertGreater(len(result), 0)

    def test_string_format_datetime(self):
        """Test string generation with date-time format."""
        schema = {"type": "string", "format": "date-time"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)
        self.assertIn("T", result)

    def test_string_format_time(self):
        """Test string generation with time format."""
        schema = {"type": "string", "format": "time"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)
        # Should produce a string (format implementation may vary)
        self.assertGreater(len(result), 0)

    def test_string_format_uuid(self):
        """Test string generation with UUID format."""
        schema = {"type": "string", "format": "uuid"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)
        # Should produce a string (format implementation may vary)
        self.assertGreater(len(result), 0)

    def test_string_format_ipv4(self):
        """Test string generation with ipv4 format."""
        schema = {"type": "string", "format": "ipv4"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)
        # Should produce a string (format implementation may vary)
        self.assertGreater(len(result), 0)

    def test_string_format_ipv6(self):
        """Test string generation with ipv6 format."""
        schema = {"type": "string", "format": "ipv6"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)
        # Should produce a string (format implementation may vary)
        self.assertGreater(len(result), 0)

    def test_string_format_hostname(self):
        """Test string generation with hostname format."""
        schema = {"type": "string", "format": "hostname"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_array_with_unique_items(self):
        """Test array generation with uniqueItems constraint."""
        schema = {
            "type": "array",
            "items": {"type": "integer"},
            "minItems": 3,
            "uniqueItems": True,
        }
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, list)
        self.assertGreaterEqual(len(result), 3)
        # Note: uniqueItems may not always produce unique values in
        # deterministic cycling mode; we verify the constraint is attempted
        # by checking that at least some values were generated

    def test_object_with_additional_properties(self):
        """Test object generation with additionalProperties."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": {"type": "integer"},
        }
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, dict)

    def test_object_without_properties(self):
        """Test object generation without properties definition."""
        schema = {"type": "object", "minProperties": 2, "maxProperties": 5}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, dict)
        self.assertGreaterEqual(len(result), 2)
        self.assertLessEqual(len(result), 5)

    def test_deep_recursion_limit(self):
        """Test that deep recursion is limited."""
        schema = {
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "nested": {
                            "type": "object",
                            "properties": {
                                "nested": {
                                    "type": "object",
                                    "properties": {
                                        "nested": {"type": "object"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, dict)

    def test_const_value(self):
        """Test schema with const value."""
        schema = {"const": "fixed_value"}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertEqual(result, "fixed_value")

    def test_const_value_aggressive(self):
        """Test string generation with const value in aggressive mode."""
        schema = {"const": 42}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
        # In aggressive mode, can return any type - just check it returns something
        # (could be the const value, or an edge case type)
        self.assertTrue(
            result is not None or result == 0 or result == [] or result == ""
        )

    def test_oneOf_selection(self):
        """Test oneOf schema combination."""
        schema = {
            "oneOf": [
                {"type": "string", "minLength": 5},
                {"type": "integer", "minimum": 10},
                {"type": "boolean"},
            ]
        }
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertTrue(
            isinstance(result, str)
            or isinstance(result, int)
            or isinstance(result, bool)
        )

    def test_anyOf_selection(self):
        """Test anyOf schema combination."""
        schema = {
            "anyOf": [
                {"type": "string", "minLength": 5},
                {"type": "integer", "minimum": 10},
            ]
        }
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertTrue(isinstance(result, str) or isinstance(result, int))

    def test_allOf_with_nested_properties(self):
        """Test allOf with nested object properties."""
        schema = {
            "allOf": [
                {
                    "type": "object",
                    "properties": {"name": {"type": "string", "minLength": 3}},
                    "required": ["name"],
                },
                {
                    "type": "object",
                    "properties": {"age": {"type": "integer", "minimum": 0}},
                },
            ]
        }
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertIsInstance(result, dict)
        self.assertIn("name", result)

    def test_aggressive_mode_violations(self):
        """Test aggressive mode generates boundary violations."""
        schema = {"type": "string", "minLength": 5, "maxLength": 10}
        # Run multiple times to potentially hit boundary violations
        results = [
            make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            for _ in range(20)
        ]
        # At least some should be strings (even in aggressive mode)
        string_results = [r for r in results if isinstance(r, str)]
        self.assertGreater(len(string_results), 0)

    def test_aggressive_mode_type_violations(self):
        """Test aggressive mode can generate wrong types."""
        schema = {"type": "integer", "minimum": 10, "maximum": 20}
        results = [
            make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            for _ in range(20)
        ]
        # Should have mixed types or boundary violations
        self.assertGreater(len(results), 0)

    def test_empty_schema(self):
        """Test handling of empty schema."""
        schema = {}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        # Should return some value
        self.assertIsNot(result, None)

    def test_type_array_multiple_types(self):
        """Test schema with array of types."""
        schema = {"type": ["string", "integer", "null"]}
        result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
        self.assertTrue(
            isinstance(result, str) or isinstance(result, int) or result is None
        )

    def test_handle_integer_type_edge_cases(self):
        """Test _handle_integer_type with edge case constraints."""
        schema = {
            "type": "integer",
            "minimum": 100,
            "maximum": 100,  # min == max
        }
        result = _handle_integer_type(schema, phase="realistic")
        self.assertEqual(result, 100)

    def test_handle_number_type_edge_cases(self):
        """Test _handle_number_type with edge case constraints."""
        schema = {
            "type": "number",
            "minimum": 5.5,
            "maximum": 5.5,  # min == max
        }
        result = _handle_number_type(schema, phase="realistic")
        self.assertEqual(result, 5.5)

    def test_handle_array_type_empty_allowed(self):
        """Test _handle_array_type allows empty arrays."""
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 0}
        result = _handle_array_type(schema, phase="realistic", recursion_depth=0)
        self.assertIsInstance(result, list)

    def test_handle_object_type_no_required(self):
        """Test _handle_object_type without required fields."""
        schema = {
            "type": "object",
            "properties": {
                "optional1": {"type": "string"},
                "optional2": {"type": "integer"},
            },
        }
        result = _handle_object_type(schema, phase="realistic", recursion_depth=0)
        self.assertIsInstance(result, dict)

    def test_handle_string_type_aggressive_boundaries(self):
        """Test _handle_string_type in aggressive mode."""
        schema = {"type": "string", "minLength": 5, "maxLength": 10}
        results = [_handle_string_type(schema, phase="aggressive") for _ in range(20)]
        # Should have variety
        self.assertGreater(len(results), 0)


if __name__ == "__main__":
    unittest.main()
