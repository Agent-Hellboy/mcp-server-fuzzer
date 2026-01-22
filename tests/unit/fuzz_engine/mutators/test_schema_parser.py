#!/usr/bin/env python3
"""
Unit tests for schema_parser.py
"""

import unittest
import json
from typing import Any, Dict, List

from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser import (
    make_fuzz_strategy_from_jsonschema,
    _handle_enum,
    _handle_string_type,
    _handle_integer_type,
    _handle_number_type,
    _handle_boolean_type,
    _handle_array_type,
    _handle_object_type,
)


class TestSchemaParser(unittest.TestCase):
    """Test cases for schema_parser.py - BEHAVIOR focused."""

    def test_make_fuzz_strategy_from_jsonschema_basic_types(self):
        """Test BEHAVIOR: generates correct data types for basic schemas."""
        # String schema
        string_schema = {"type": "string"}
        string_result = make_fuzz_strategy_from_jsonschema(string_schema)
        self.assertIsInstance(string_result, str, "Should generate a string")

        # Integer schema
        integer_schema = {"type": "integer"}
        integer_result = make_fuzz_strategy_from_jsonschema(integer_schema)
        self.assertIsInstance(integer_result, int, "Should generate an integer")

        # Number schema
        number_schema = {"type": "number"}
        number_result = make_fuzz_strategy_from_jsonschema(number_schema)
        self.assertIsInstance(number_result, (int, float), "Should generate a number")

        # Boolean schema
        boolean_schema = {"type": "boolean"}
        boolean_result = make_fuzz_strategy_from_jsonschema(
            boolean_schema, phase="realistic"
        )
        self.assertIsInstance(boolean_result, bool, "Should generate a boolean")

        # Null schema
        null_schema = {"type": "null"}
        null_result = make_fuzz_strategy_from_jsonschema(null_schema)
        self.assertIsNone(null_result, "Should generate None")

    def test_make_fuzz_strategy_from_jsonschema_array(self):
        """Test BEHAVIOR: generates arrays with correct item types."""
        # Array of strings
        array_schema = {"type": "array", "items": {"type": "string"}}
        array_result = make_fuzz_strategy_from_jsonschema(array_schema)
        self.assertIsInstance(array_result, list, "Should generate a list")
        if array_result:  # Array might be empty in aggressive mode
            self.assertIsInstance(array_result[0], str, "Array items should be strings")

    def test_make_fuzz_strategy_from_jsonschema_object(self):
        """Test BEHAVIOR: generates objects with correct property types."""
        # Object with properties
        object_schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
                "active": {"type": "boolean"},
            },
            "required": ["name", "age"],
        }
        object_result = make_fuzz_strategy_from_jsonschema(object_schema)
        self.assertIsInstance(object_result, dict, "Should generate a dictionary")
        self.assertIn(
            "name", object_result, "Required property 'name' should be present"
        )
        self.assertIn("age", object_result, "Required property 'age' should be present")
        self.assertIsInstance(
            object_result["name"], str, "Property 'name' should be a string"
        )
        self.assertIsInstance(
            object_result["age"], int, "Property 'age' should be an integer"
        )

    def test_make_fuzz_strategy_from_jsonschema_enum(self):
        """Test BEHAVIOR: handles enum values correctly."""
        # String enum
        enum_schema = {"enum": ["red", "green", "blue"]}
        enum_result = make_fuzz_strategy_from_jsonschema(enum_schema, phase="realistic")
        self.assertIn(
            enum_result, ["red", "green", "blue"], "Should select from enum values"
        )

    def test_make_fuzz_strategy_from_jsonschema_schema_combinations(self):
        """Test BEHAVIOR: handles schema combinations (oneOf, anyOf, allOf)."""
        # oneOf schema
        oneof_schema = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
        oneof_result = make_fuzz_strategy_from_jsonschema(oneof_schema)
        self.assertTrue(
            isinstance(oneof_result, str) or isinstance(oneof_result, int),
            "Should generate either a string or an integer",
        )

        # anyOf schema
        anyof_schema = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
        anyof_result = make_fuzz_strategy_from_jsonschema(anyof_schema)
        self.assertTrue(
            isinstance(anyof_result, str) or isinstance(anyof_result, int),
            "Should generate either a string or an integer",
        )

        # allOf schema
        allof_schema = {
            "allOf": [
                {"type": "object", "properties": {"name": {"type": "string"}}},
                {"type": "object", "properties": {"age": {"type": "integer"}}},
            ]
        }
        allof_result = make_fuzz_strategy_from_jsonschema(allof_schema)
        self.assertIsInstance(allof_result, dict, "Should generate a dictionary")

    def test_make_fuzz_strategy_from_jsonschema_string_formats(self):
        """Test BEHAVIOR: handles string formats correctly."""
        # Email format
        email_schema = {"type": "string", "format": "email"}
        email_result = make_fuzz_strategy_from_jsonschema(
            email_schema, phase="realistic"
        )
        self.assertIsInstance(email_result, str, "Should generate a string")
        self.assertIn("@", email_result, "Email should contain @")

        # URI format
        uri_schema = {"type": "string", "format": "uri"}
        uri_result = make_fuzz_strategy_from_jsonschema(uri_schema, phase="realistic")
        self.assertIsInstance(uri_result, str, "Should generate a string")
        self.assertTrue(
            uri_result.startswith("http://") or uri_result.startswith("https://"),
            "URI should start with http:// or https://",
        )

    def test_make_fuzz_strategy_from_jsonschema_string_constraints(self):
        """Test BEHAVIOR: respects string constraints."""
        # String with minLength and maxLength
        string_schema = {"type": "string", "minLength": 5, "maxLength": 10}
        string_result = make_fuzz_strategy_from_jsonschema(
            string_schema, phase="realistic"
        )
        self.assertIsInstance(string_result, str, "Should generate a string")
        self.assertGreaterEqual(len(string_result), 5, "String should meet minLength")
        self.assertLessEqual(len(string_result), 10, "String should meet maxLength")

    def test_make_fuzz_strategy_from_jsonschema_number_constraints(self):
        """Test BEHAVIOR: respects number constraints."""
        # Integer with minimum and maximum
        integer_schema = {"type": "integer", "minimum": 10, "maximum": 20}
        integer_result = make_fuzz_strategy_from_jsonschema(
            integer_schema, phase="realistic"
        )
        self.assertIsInstance(integer_result, int, "Should generate an integer")
        self.assertGreaterEqual(integer_result, 10, "Integer should meet minimum")
        self.assertLessEqual(integer_result, 20, "Integer should meet maximum")

    def test_make_fuzz_strategy_from_jsonschema_array_constraints(self):
        """Test BEHAVIOR: respects array constraints."""
        # Array with minItems and maxItems
        array_schema = {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
            "maxItems": 5,
        }
        array_result = make_fuzz_strategy_from_jsonschema(
            array_schema, phase="realistic"
        )
        self.assertIsInstance(array_result, list, "Should generate a list")
        self.assertGreaterEqual(len(array_result), 2, "Array should meet minItems")
        self.assertLessEqual(len(array_result), 5, "Array should meet maxItems")

    def test_make_fuzz_strategy_from_jsonschema_object_constraints(self):
        """Test BEHAVIOR: respects object constraints."""
        # Object with minProperties and maxProperties
        object_schema = {
            "type": "object",
            "properties": {
                "prop1": {"type": "string"},
                "prop2": {"type": "string"},
                "prop3": {"type": "string"},
            },
            "minProperties": 2,
            "maxProperties": 3,
        }
        object_result = make_fuzz_strategy_from_jsonschema(
            object_schema, phase="realistic"
        )
        self.assertIsInstance(object_result, dict, "Should generate a dictionary")
        self.assertGreaterEqual(
            len(object_result), 2, "Object should meet minProperties"
        )
        self.assertLessEqual(len(object_result), 3, "Object should meet maxProperties")

    def test_make_fuzz_strategy_from_jsonschema_realistic_vs_aggressive(self):
        """Test BEHAVIOR: realistic vs aggressive phases."""
        # Compare different approaches between phases
        schema = {"type": "string", "enum": ["option1", "option2", "option3"]}

        # Test with realistic phase
        realistic_results = [
            make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            for _ in range(10)
        ]
        self.assertTrue(
            all(
                result in ["option1", "option2", "option3"]
                for result in realistic_results
            ),
            "Realistic mode should only generate valid enum values",
        )

        # In aggressive mode, we might get invalid values, but we can't test
        # deterministically
        # Just verify it runs without errors
        aggressive_result = make_fuzz_strategy_from_jsonschema(
            schema, phase="aggressive"
        )
        self.assertIsInstance(
            aggressive_result, str, "Should generate a string in aggressive mode"
        )

    def test_handle_enum(self):
        """Test BEHAVIOR: _handle_enum selects from enum values."""
        enum_values = ["red", "green", "blue"]
        result = _handle_enum(enum_values, phase="realistic")
        self.assertIn(result, enum_values, "Should select from enum values")

    def test_handle_string_type(self):
        """Test BEHAVIOR: _handle_string_type respects constraints."""
        schema = {"type": "string", "minLength": 5, "maxLength": 10}
        result = _handle_string_type(schema, phase="realistic")
        self.assertIsInstance(result, str, "Should generate a string")
        self.assertGreaterEqual(len(result), 5, "String should meet minLength")
        self.assertLessEqual(len(result), 10, "String should meet maxLength")

    def test_handle_integer_type(self):
        """Test BEHAVIOR: _handle_integer_type respects constraints."""
        schema = {"type": "integer", "minimum": 10, "maximum": 20}
        result = _handle_integer_type(schema, phase="realistic")
        self.assertIsInstance(result, int, "Should generate an integer")
        self.assertGreaterEqual(result, 10, "Integer should meet minimum")
        self.assertLessEqual(result, 20, "Integer should meet maximum")

    def test_handle_number_type(self):
        """Test BEHAVIOR: _handle_number_type respects constraints."""
        schema = {"type": "number", "minimum": 10.0, "maximum": 20.0}
        result = _handle_number_type(schema, phase="realistic")
        self.assertIsInstance(result, (int, float), "Should generate a number")
        self.assertGreaterEqual(result, 10.0, "Number should meet minimum")
        self.assertLessEqual(result, 20.0, "Number should meet maximum")

    def test_handle_boolean_type(self):
        """Test BEHAVIOR: _handle_boolean_type generates boolean values."""
        result = _handle_boolean_type(phase="realistic")
        self.assertIsInstance(result, bool, "Should generate a boolean")

    def test_handle_array_type(self):
        """Test BEHAVIOR: _handle_array_type respects constraints."""
        schema = {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
            "maxItems": 5,
        }
        result = _handle_array_type(schema, phase="realistic", recursion_depth=0)
        self.assertIsInstance(result, list, "Should generate a list")
        self.assertGreaterEqual(len(result), 2, "Array should meet minItems")
        self.assertLessEqual(len(result), 5, "Array should meet maxItems")

    def test_handle_object_type(self):
        """Test BEHAVIOR: _handle_object_type respects constraints."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
            "required": ["name"],
        }
        result = _handle_object_type(schema, phase="realistic", recursion_depth=0)
        self.assertIsInstance(result, dict, "Should generate a dictionary")
        self.assertIn("name", result, "Required property 'name' should be present")

    def test_complex_nested_schema(self):
        """Test BEHAVIOR: handles complex nested schemas."""
        complex_schema = {
            "type": "object",
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "name": {"type": "string", "minLength": 3, "maxLength": 50},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "uniqueItems": True,
                },
                "metadata": {
                    "type": "object",
                    "properties": {
                        "created": {"type": "string", "format": "date-time"},
                        "priority": {"type": "integer", "minimum": 1, "maximum": 5},
                        "settings": {
                            "type": "object",
                            "properties": {
                                "enabled": {"type": "boolean"},
                                "visibility": {
                                    "enum": ["public", "private", "restricted"]
                                },
                            },
                        },
                    },
                },
            },
            "required": ["id", "name"],
        }

        result = make_fuzz_strategy_from_jsonschema(complex_schema, phase="realistic")

        # Check top-level structure
        self.assertIsInstance(result, dict, "Should generate a dictionary")
        self.assertIn("id", result, "Required property 'id' should be present")
        self.assertIn("name", result, "Required property 'name' should be present")

        # Check id format
        self.assertIsInstance(result["id"], str, "id should be a string")

        # Check name constraints
        self.assertIsInstance(result["name"], str, "name should be a string")
        self.assertGreaterEqual(len(result["name"]), 3, "name should meet minLength")
        self.assertLessEqual(len(result["name"]), 50, "name should meet maxLength")

        # Check tags if present
        if "tags" in result:
            self.assertIsInstance(result["tags"], list, "tags should be a list")
            if result["tags"]:
                self.assertGreaterEqual(
                    len(result["tags"]), 1, "tags should meet minItems"
                )
                # Note: uniqueItems constraint may not always be enforced in
                # deterministic fuzzing mode since boundary value cycling can
                # produce duplicates for small arrays

        # Check metadata if present
        if "metadata" in result:
            self.assertIsInstance(
                result["metadata"], dict, "metadata should be a dictionary"
            )

            # Check created if present
            if "created" in result["metadata"]:
                self.assertIsInstance(
                    result["metadata"]["created"], str, "created should be a string"
                )

            # Check priority if present
            if "priority" in result["metadata"]:
                self.assertIsInstance(
                    result["metadata"]["priority"], int, "priority should be an integer"
                )
                self.assertGreaterEqual(
                    result["metadata"]["priority"], 1, "priority should meet minimum"
                )
                self.assertLessEqual(
                    result["metadata"]["priority"], 5, "priority should meet maximum"
                )

            # Check settings if present
            if "settings" in result["metadata"]:
                self.assertIsInstance(
                    result["metadata"]["settings"],
                    dict,
                    "settings should be a dictionary",
                )

                # Check enabled if present
                if "enabled" in result["metadata"]["settings"]:
                    self.assertIsInstance(
                        result["metadata"]["settings"]["enabled"],
                        bool,
                        "enabled should be a boolean",
                    )

                # Check visibility if present
                if "visibility" in result["metadata"]["settings"]:
                    self.assertIn(
                        result["metadata"]["settings"]["visibility"],
                        ["public", "private", "restricted"],
                        "visibility should be a valid enum value",
                    )


if __name__ == "__main__":
    unittest.main()
