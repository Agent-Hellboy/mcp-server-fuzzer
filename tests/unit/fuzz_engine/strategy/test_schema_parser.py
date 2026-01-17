#!/usr/bin/env python3
"""
Unit tests for schema_parser.py
"""

import json
from typing import Any, Dict, List

import pytest

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
from mcp_fuzzer.fuzz_engine.mutators.strategies import schema_parser

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.strategy]


def test_make_fuzz_strategy_from_jsonschema_basic_types():
    """Test BEHAVIOR: generates correct data types for basic schemas."""
    # String schema
    string_schema = {"type": "string"}
    string_result = make_fuzz_strategy_from_jsonschema(string_schema)
    assert isinstance(string_result, str), "Should generate a string"

    # Integer schema
    integer_schema = {"type": "integer"}
    integer_result = make_fuzz_strategy_from_jsonschema(integer_schema)
    assert isinstance(integer_result, int), "Should generate an integer"

    # Number schema
    number_schema = {"type": "number"}
    number_result = make_fuzz_strategy_from_jsonschema(number_schema)
    assert isinstance(number_result, (int, float)), "Should generate a number"

    # Boolean schema
    boolean_schema = {"type": "boolean"}
    boolean_result = make_fuzz_strategy_from_jsonschema(
        boolean_schema, phase="realistic"
    )
    assert isinstance(boolean_result, bool), "Should generate a boolean"

    # Null schema
    null_schema = {"type": "null"}
    null_result = make_fuzz_strategy_from_jsonschema(null_schema)
    assert null_result is None, "Should generate None"


def test_make_fuzz_strategy_from_jsonschema_array():
    """Test BEHAVIOR: generates arrays with correct item types."""
    # Array of strings
    array_schema = {"type": "array", "items": {"type": "string"}}
    array_result = make_fuzz_strategy_from_jsonschema(array_schema)
    assert isinstance(array_result, list), "Should generate a list"
    if array_result:  # Array might be empty in aggressive mode
        assert isinstance(array_result[0], str), "Array items should be strings"


def test_make_fuzz_strategy_from_jsonschema_object():
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
    assert isinstance(object_result, dict), "Should generate a dictionary"
    assert "name" in object_result, "Required property 'name' should be present"
    assert "age" in object_result, "Required property 'age' should be present"
    assert isinstance(object_result["name"], str), "Property 'name' should be a string"
    assert isinstance(object_result["age"], int), "Property 'age' should be an integer"


def test_make_fuzz_strategy_from_jsonschema_enum():
    """Test BEHAVIOR: handles enum values correctly."""
    # String enum
    enum_schema = {"enum": ["red", "green", "blue"]}
    enum_result = make_fuzz_strategy_from_jsonschema(enum_schema, phase="realistic")
    assert enum_result in ["red", "green", "blue"], "Should select from enum values"


def test_make_fuzz_strategy_from_jsonschema_schema_combinations():
    """Test BEHAVIOR: handles schema combinations (oneOf, anyOf, allOf)."""
    # oneOf schema
    oneof_schema = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
    oneof_result = make_fuzz_strategy_from_jsonschema(oneof_schema)
    assert isinstance(oneof_result, str) or isinstance(oneof_result, int), (
        "Should generate either a string or an integer"
    )

    # anyOf schema
    anyof_schema = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
    anyof_result = make_fuzz_strategy_from_jsonschema(anyof_schema)
    assert isinstance(anyof_result, str) or isinstance(anyof_result, int), (
        "Should generate either a string or an integer"
    )

    # allOf schema
    allof_schema = {
        "allOf": [
            {"type": "object", "properties": {"name": {"type": "string"}}},
            {"type": "object", "properties": {"age": {"type": "integer"}}},
        ]
    }
    allof_result = make_fuzz_strategy_from_jsonschema(allof_schema)
    assert isinstance(allof_result, dict), "Should generate a dictionary"


def test_make_fuzz_strategy_from_jsonschema_string_formats():
    """Test BEHAVIOR: handles string formats correctly."""
    # Email format
    email_schema = {"type": "string", "format": "email"}
    email_result = make_fuzz_strategy_from_jsonschema(email_schema, phase="realistic")
    assert isinstance(email_result, str), "Should generate a string"
    assert "@" in email_result, "Email should contain @"

    # URI format
    uri_schema = {"type": "string", "format": "uri"}
    uri_result = make_fuzz_strategy_from_jsonschema(uri_schema, phase="realistic")
    assert isinstance(uri_result, str), "Should generate a string"
    assert uri_result.startswith("http://") or uri_result.startswith("https://"), (
        "URI should start with http:// or https://"
    )


def test_make_fuzz_strategy_from_jsonschema_string_constraints():
    """Test BEHAVIOR: respects string constraints."""
    # String with minLength and maxLength
    string_schema = {"type": "string", "minLength": 5, "maxLength": 10}
    string_result = make_fuzz_strategy_from_jsonschema(string_schema, phase="realistic")
    assert isinstance(string_result, str), "Should generate a string"
    assert len(string_result) >= 5, "String should meet minLength"
    assert len(string_result) <= 10, "String should meet maxLength"


def test_make_fuzz_strategy_from_jsonschema_number_constraints():
    """Test BEHAVIOR: respects number constraints."""
    # Integer with minimum and maximum
    integer_schema = {"type": "integer", "minimum": 10, "maximum": 20}
    integer_result = make_fuzz_strategy_from_jsonschema(
        integer_schema, phase="realistic"
    )
    assert isinstance(integer_result, int), "Should generate an integer"
    assert integer_result >= 10, "Integer should meet minimum"
    assert integer_result <= 20, "Integer should meet maximum"


def test_make_fuzz_strategy_from_jsonschema_array_constraints():
    """Test BEHAVIOR: respects array constraints."""
    # Array with minItems and maxItems
    array_schema = {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 2,
        "maxItems": 5,
    }
    array_result = make_fuzz_strategy_from_jsonschema(array_schema, phase="realistic")
    assert isinstance(array_result, list), "Should generate a list"
    assert len(array_result) >= 2, "Array should meet minItems"
    assert len(array_result) <= 5, "Array should meet maxItems"


def test_make_fuzz_strategy_from_jsonschema_object_constraints():
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
    object_result = make_fuzz_strategy_from_jsonschema(object_schema, phase="realistic")
    assert isinstance(object_result, dict), "Should generate a dictionary"
    assert len(object_result) >= 2, "Object should meet minProperties"
    assert len(object_result) <= 3, "Object should meet maxProperties"


def test_make_fuzz_strategy_from_jsonschema_realistic_vs_aggressive():
    """Test BEHAVIOR: realistic vs aggressive phases."""
    # Compare different approaches between phases
    schema = {"type": "string", "enum": ["option1", "option2", "option3"]}

    # Test with realistic phase
    realistic_results = [
        make_fuzz_strategy_from_jsonschema(schema, phase="realistic") for _ in range(10)
    ]
    assert all(
        result in ["option1", "option2", "option3"] for result in realistic_results
    ), "Realistic mode should only generate valid enum values"

    # In aggressive mode, we might get invalid values, but we can't test
    # deterministically
    # Just verify it runs without errors
    aggressive_result = make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
    assert isinstance(aggressive_result, str), "Should be string in aggressive mode"


def test_handle_enum():
    """Test BEHAVIOR: _handle_enum selects from enum values."""
    enum_values = ["red", "green", "blue"]
    result = _handle_enum(enum_values, phase="realistic")
    assert result in enum_values, "Should select from enum values"


def test_handle_string_type():
    """Test BEHAVIOR: _handle_string_type respects constraints."""
    schema = {"type": "string", "minLength": 5, "maxLength": 10}
    result = _handle_string_type(schema, phase="realistic")
    assert isinstance(result, str), "Should generate a string"
    assert len(result) >= 5, "String should meet minLength"
    assert len(result) <= 10, "String should meet maxLength"


def test_handle_integer_type():
    """Test BEHAVIOR: _handle_integer_type respects constraints."""
    schema = {"type": "integer", "minimum": 10, "maximum": 20}
    result = _handle_integer_type(schema, phase="realistic")
    assert isinstance(result, int), "Should generate an integer"
    assert result >= 10, "Integer should meet minimum"
    assert result <= 20, "Integer should meet maximum"


def test_handle_number_type():
    """Test BEHAVIOR: _handle_number_type respects constraints."""
    schema = {"type": "number", "minimum": 10.0, "maximum": 20.0}
    result = _handle_number_type(schema, phase="realistic")
    assert isinstance(result, (int, float)), "Should generate a number"
    assert result >= 10.0, "Number should meet minimum"
    assert result <= 20.0, "Number should meet maximum"


def test_handle_boolean_type():
    """Test BEHAVIOR: _handle_boolean_type generates boolean values."""
    result = _handle_boolean_type(phase="realistic")
    assert isinstance(result, bool), "Should generate a boolean"


def test_handle_array_type():
    """Test BEHAVIOR: _handle_array_type respects constraints."""
    schema = {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 2,
        "maxItems": 5,
    }
    result = _handle_array_type(schema, phase="realistic", recursion_depth=0)
    assert isinstance(result, list), "Should generate a list"
    assert len(result) >= 2, "Array should meet minItems"
    assert len(result) <= 5, "Array should meet maxItems"


def test_handle_object_type():
    """Test BEHAVIOR: _handle_object_type respects constraints."""
    schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
        "required": ["name"],
    }
    result = _handle_object_type(schema, phase="realistic", recursion_depth=0)
    assert isinstance(result, dict), "Should generate a dictionary"
    assert "name" in result, "Required property 'name' should be present"


def test_complex_nested_schema():
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
                            "visibility": {"enum": ["public", "private", "restricted"]},
                        },
                    },
                },
            },
        },
        "required": ["id", "name"],
    }

    result = make_fuzz_strategy_from_jsonschema(complex_schema, phase="realistic")

    # Check top-level structure
    assert isinstance(result, dict), "Should generate a dictionary"
    assert "id" in result, "Required property 'id' should be present"
    assert "name" in result, "Required property 'name' should be present"

    # Check id format
    assert isinstance(result["id"], str), "id should be a string"

    # Check name constraints
    assert isinstance(result["name"], str), "name should be a string"
    assert len(result["name"]) >= 3, "name should meet minLength"
    assert len(result["name"]) <= 50, "name should meet maxLength"

    # Check tags if present
    if "tags" in result:
        assert isinstance(result["tags"], list), "tags should be a list"
        if result["tags"]:
            assert len(result["tags"]) >= 1, "tags should meet minItems"
            # Check uniqueness
            assert len(result["tags"]) == len(set(result["tags"])), (
                "tags should have unique items"
            )

    # Check metadata if present
    if "metadata" in result:
        assert isinstance(result["metadata"], dict), "metadata should be a dictionary"

        # Check created if present
        if "created" in result["metadata"]:
            assert isinstance(result["metadata"]["created"], str), (
                "created should be a string"
            )

        # Check priority if present
        if "priority" in result["metadata"]:
            assert isinstance(result["metadata"]["priority"], int), (
                "priority should be an integer"
            )
            assert result["metadata"]["priority"] >= 1, "priority should meet minimum"
            assert result["metadata"]["priority"] <= 5, "priority should meet maximum"

        # Check settings if present
        if "settings" in result["metadata"]:
            assert isinstance(result["metadata"]["settings"], dict), (
                "settings should be a dictionary"
            )

            # Check enabled if present
            if "enabled" in result["metadata"]["settings"]:
                assert isinstance(result["metadata"]["settings"]["enabled"], bool), (
                    "enabled should be a boolean"
                )

            # Check visibility if present
            if "visibility" in result["metadata"]["settings"]:
                assert result["metadata"]["settings"]["visibility"] in [
                    "public",
                    "private",
                    "restricted",
                ], "visibility should be a valid enum value"


def test_make_fuzz_strategy_recursion_depth_fallback():
    schema = {"type": ["string", "integer"]}
    result = schema_parser.make_fuzz_strategy_from_jsonschema(
        schema, recursion_depth=schema_parser.MAX_RECURSION_DEPTH + 1
    )
    assert result == ""

    result = schema_parser.make_fuzz_strategy_from_jsonschema(
        {}, recursion_depth=schema_parser.MAX_RECURSION_DEPTH + 1
    )
    assert result is None


def test_allof_merge_applies_constraints():
    schema = {
        "allOf": [
            {
                "type": ["string", "number"],
                "minLength": 2,
                "maxLength": 10,
                "required": ["alpha"],
                "properties": {"alpha": {"type": "string"}},
            },
            {
                "type": "string",
                "minLength": 3,
                "maxLength": 5,
                "required": ["beta"],
                "properties": {"beta": {"type": "integer"}},
                "const": "fixed",
            },
        ]
    }
    merged = schema_parser._merge_allOf(schema["allOf"])
    assert merged["type"] == "string"
    assert merged["minLength"] == 3
    assert merged["maxLength"] == 5
    assert merged["required"] == ["alpha", "beta"]
    assert merged["const"] == "fixed"
    assert "alpha" in merged["properties"]
    assert "beta" in merged["properties"]


def test_allof_merge_keeps_multiple_types():
    schema = {
        "allOf": [
            {"type": ["string", "number"]},
            {"type": ["string", "number"]},
        ]
    }
    merged = schema_parser._merge_allOf(schema["allOf"])
    assert sorted(merged["type"]) == ["number", "string"]


def test_oneof_anyof_selection(monkeypatch):
    monkeypatch.setattr(schema_parser.random, "choice", lambda seq: seq[0])
    schema = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
    result = schema_parser.make_fuzz_strategy_from_jsonschema(schema)
    assert isinstance(result, str)

    schema = {"anyOf": [{"type": "integer"}, {"type": "string"}]}
    result = schema_parser.make_fuzz_strategy_from_jsonschema(schema)
    assert isinstance(result, int)


def test_object_type_min_properties_and_additional(monkeypatch):
    schema = {
        "type": "object",
        "properties": {},
        "minProperties": 2,
    }
    result = schema_parser._handle_object_type(schema, "realistic", 0)
    assert sorted(result.keys()) == ["additional_prop_0", "additional_prop_1"]

    schema["additionalProperties"] = False
    result = schema_parser._handle_object_type(schema, "realistic", 0)
    assert result == {}


def test_array_type_tuple_and_unique(monkeypatch):
    tuple_schema = {"type": "array", "items": [{"type": "string"}]}
    result = schema_parser._handle_array_type(tuple_schema, "realistic", 0)
    assert isinstance(result, list)
    assert len(result) == 1

    array_schema = {
        "type": "array",
        "items": {"type": "integer", "minimum": 1, "maximum": 1},
        "minItems": 2,
        "maxItems": 2,
        "uniqueItems": True,
    }
    result = schema_parser._handle_array_type(array_schema, "realistic", 0)
    assert len(result) == 2

    empty_items_schema = {"type": "array", "items": {}}
    result = schema_parser._handle_array_type(empty_items_schema, "realistic", 0)
    assert len(result) >= 1

    small_max_schema = {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 2,
        "maxItems": 1,
    }
    monkeypatch.setattr(schema_parser.random, "randint", lambda low, high: high)
    result = schema_parser._handle_array_type(small_max_schema, "realistic", 0)
    assert len(result) == 2


def test_array_unique_items_repr_fallback(monkeypatch):
    class BadStr:
        def __init__(self, label):
            self.label = label

        def __str__(self):
            raise RuntimeError("bad str")

        def __repr__(self):
            return f"BadStr({self.label})"

    items = [BadStr("same"), BadStr("same"), BadStr("diff")]

    def _next_item(*_args, **_kwargs):
        return items.pop(0)

    monkeypatch.setattr(schema_parser, "make_fuzz_strategy_from_jsonschema", _next_item)
    schema = {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 2,
        "maxItems": 2,
        "uniqueItems": True,
    }
    result = schema_parser._handle_array_type(schema, "realistic", 0)
    assert len(result) == 2


def test_string_format_handlers(monkeypatch):
    formats = [
        "date-time",
        "uuid",
        "email",
        "uri",
        "time",
        "ipv4",
        "ipv6",
        "hostname",
    ]
    for fmt in formats:
        result = schema_parser._handle_string_format(fmt, "realistic")
        assert isinstance(result, str)
        assert result

    monkeypatch.setattr(
        schema_parser,
        "_handle_string_type",
        lambda schema, phase: "fallback",
    )
    assert schema_parser._handle_string_format("unknown", "realistic") == "fallback"


def test_pattern_and_string_edgecases(monkeypatch):
    monkeypatch.setattr(
        schema_parser,
        "_generate_string_from_pattern",
        lambda *args, **kwargs: "abc123",
    )
    result = schema_parser._handle_string_type(
        {"type": "string", "pattern": "^[a-zA-Z0-9]+$"}, "realistic"
    )
    assert result == "abc123"

    def _raise_pattern(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(schema_parser, "_generate_string_from_pattern", _raise_pattern)
    monkeypatch.setattr(schema_parser.random, "randint", lambda low, high: low)
    result = schema_parser._handle_string_type(
        {"type": "string", "pattern": "oops", "minLength": 5, "maxLength": 6},
        "realistic",
    )
    assert len(result) == 5

    monkeypatch.setattr(schema_parser.random, "random", lambda: 0.95)
    monkeypatch.setattr(schema_parser.random, "choice", lambda seq: seq[0])
    result = schema_parser._handle_string_type(
        {"type": "string", "minLength": 10, "maxLength": 12}, "aggressive"
    )
    assert 10 <= len(result) <= 12

    monkeypatch.setattr(schema_parser.random, "randint", lambda low, high: low)
    result = schema_parser._handle_string_type(
        {"type": "string", "minLength": 5, "maxLength": 3}, "realistic"
    )
    assert len(result) == 5


def test_generate_string_from_pattern_variants(monkeypatch):
    monkeypatch.setattr(schema_parser.random, "randint", lambda low, high: low)
    assert schema_parser._generate_string_from_pattern(
        "^[a-zA-Z0-9]+$", 2, 4
    ).isalnum()
    assert schema_parser._generate_string_from_pattern("^[0-9]+$", 2, 4).isdigit()
    assert schema_parser._generate_string_from_pattern("^[a-zA-Z]+$", 2, 4).isalpha()


def test_integer_type_constraints(monkeypatch):
    monkeypatch.setattr(schema_parser.random, "randint", lambda low, high: low)
    result = schema_parser._handle_integer_type(
        {
            "type": "integer",
            "minimum": 10,
            "maximum": 10,
            "exclusiveMinimum": True,
            "exclusiveMaximum": 11,
            "multipleOf": 3,
        },
        "realistic",
    )
    assert result == 10

    monkeypatch.setattr(schema_parser.random, "random", lambda: 0.9)
    result = schema_parser._handle_integer_type(
        {"type": "integer", "minimum": -2, "maximum": 2}, "aggressive"
    )
    assert -2 <= result <= 2

    monkeypatch.setattr(schema_parser.random, "random", lambda: 0.5)
    monkeypatch.setattr(schema_parser.random, "randint", lambda low, high: low)
    result = schema_parser._handle_integer_type(
        {
            "type": "integer",
            "exclusiveMinimum": 2.5,
            "exclusiveMaximum": 9.5,
            "multipleOf": 5,
        },
        "aggressive",
    )
    assert isinstance(result, int)

    monkeypatch.setattr(schema_parser.random, "random", lambda: 0.9)
    monkeypatch.setattr(schema_parser.random, "choice", lambda seq: seq[0])
    result = schema_parser._handle_integer_type(
        {"type": "integer", "minimum": 0, "maximum": 10, "multipleOf": 5},
        "aggressive",
    )
    assert result % 5 == 0


def test_number_type_multiple_of(monkeypatch):
    monkeypatch.setattr(schema_parser.random, "uniform", lambda low, high: 1.0)
    result = schema_parser._handle_number_type(
        {"type": "number", "minimum": 0.0, "maximum": 10.0, "multipleOf": 2.0},
        "realistic",
    )
    assert result % 2 == 0

    monkeypatch.setattr(schema_parser.random, "random", lambda: 0.9)
    monkeypatch.setattr(schema_parser.random, "choice", lambda seq: seq[0])
    result = schema_parser._handle_number_type(
        {"type": "number", "minimum": 0.0, "maximum": 1.0, "multipleOf": 0.5},
        "aggressive",
    )
    assert 0.0 <= result <= 1.0

    result = schema_parser._handle_number_type(
        {"type": "number", "minimum": 5.0, "maximum": 1.0, "exclusiveMinimum": True},
        "realistic",
    )
    assert isinstance(result, float)

    result = schema_parser._handle_number_type(
        {"type": "number", "multipleOf": "bad"},
        "realistic",
    )
    assert isinstance(result, float)


def test_generate_default_value():
    result = schema_parser._generate_default_value("realistic")
    assert result in ["default_value", 123, True, [], {}]
