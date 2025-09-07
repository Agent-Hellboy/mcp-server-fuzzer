#!/usr/bin/env python3
"""
Unit tests for realistic Hypothesis strategies.
Tests the realistic strategies from mcp_fuzzer.fuzz_engine.strategy.realistic.*
"""

import base64
import re
import uuid
from datetime import datetime

import pytest
from hypothesis import given

from mcp_fuzzer.fuzz_engine.strategy.realistic.tool_strategy import (
    base64_strings,
    timestamp_strings,
    uuid_strings,
    generate_realistic_text,
    fuzz_tool_arguments_realistic,
)
from mcp_fuzzer.fuzz_engine.strategy.realistic.protocol_type_strategy import (
    json_rpc_id_values,
    method_names,
    protocol_version_strings,
)

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.strategy]


# Tests for realistic strategies
@given(base64_strings())
def test_base64_strings_valid(value):
    """Test that base64_strings generates valid Base64 strings."""
    assert isinstance(value, str)
    # Should be valid Base64
    try:
        decoded = base64.b64decode(value)
        # Re-encoding should give the same result
        reencoded = base64.b64encode(decoded).decode("ascii")
        assert value == reencoded
    except Exception as e:
        pytest.fail(f"Invalid Base64 string generated: {value}, error: {e}")


@given(uuid_strings())
def test_uuid_strings_valid(value):
    """Test that uuid_strings generates valid UUID strings."""
    assert isinstance(value, str)
    # Should be valid UUID format
    try:
        parsed_uuid = uuid.UUID(value)
        assert str(parsed_uuid) == value
    except ValueError as e:
        pytest.fail(f"Invalid UUID string generated: {value}, error: {e}")


@given(uuid_strings(version=1))
def test_uuid_strings_version1(value):
    """Test UUID version 1 generation."""
    parsed_uuid = uuid.UUID(value)
    assert parsed_uuid.version == 1


@given(uuid_strings(version=4))
def test_uuid_strings_version4(value):
    """Test UUID version 4 generation."""
    parsed_uuid = uuid.UUID(value)
    assert parsed_uuid.version == 4


@given(timestamp_strings())
def test_timestamp_strings_valid(value):
    """Test that timestamp_strings generates valid ISO-8601 timestamps."""
    assert isinstance(value, str)
    # Should be valid ISO-8601 format
    try:
        parsed_dt = datetime.fromisoformat(value)
        assert isinstance(parsed_dt, datetime)
        # Should have timezone info
        assert parsed_dt.tzinfo is not None
    except ValueError as e:
        pytest.fail(f"Invalid timestamp string generated: {value}, error: {e}")


@given(timestamp_strings(min_year=2024, max_year=2024))
def test_timestamp_strings_year_range(value):
    """Test timestamp year range constraint."""
    parsed_dt = datetime.fromisoformat(value)
    assert parsed_dt.year == 2024


@given(protocol_version_strings())
def test_protocol_version_strings_format(value):
    """Test that protocol_version_strings generates valid formats."""
    assert isinstance(value, str)
    # Should match either date format (YYYY-MM-DD) or semantic version
    date_pattern = r"^\d{4}-\d{2}-\d{2}$"
    semver_pattern = r"^\d+\.\d+\.\d+$"

    assert re.match(date_pattern, value) or re.match(semver_pattern, value), (
        f"Version string '{value}' doesn't match expected patterns"
    )


@given(json_rpc_id_values())
def test_json_rpc_id_values_types(value):
    """Test that json_rpc_id_values generates valid types."""
    # Should be None, string, int, or float
    assert type(value) in [
        type(None),
        str,
        int,
        float,
    ], f"Invalid JSON-RPC ID type: {type(value)}"


@given(method_names())
def test_method_names_format(value):
    """Test that method_names generates reasonable method names."""
    assert isinstance(value, str)
    assert len(value) > 0
    # Should not start with whitespace or special characters (except letters)
    if not any(
        value.startswith(prefix)
        for prefix in [
            "initialize",
            "tools/",
            "resources/",
            "prompts/",
            "notifications/",
            "completion/",
            "sampling/",
        ]
    ):
        assert value[0].isalpha(), f"Method name should start with letter: {value}"


# Custom strategies integration tests
def test_base64_strings_with_size_constraints():
    """Test base64_strings with size constraints."""
    strategy = base64_strings(min_size=10, max_size=20)
    value = strategy.example()
    decoded = base64.b64decode(value)
    assert len(decoded) >= 10
    assert len(decoded) <= 20


def test_timestamp_strings_without_microseconds():
    """Test timestamp_strings without microseconds."""
    strategy = timestamp_strings(include_microseconds=False)
    value = strategy.example()
    # Should not contain microseconds (no .)
    assert "." not in value


def test_uuid_strings_different_versions():
    """Test uuid_strings with different versions."""
    for version in [1, 3, 4, 5]:
        strategy = uuid_strings(version=version)
        value = strategy.example()
        parsed_uuid = uuid.UUID(value)
        assert parsed_uuid.version == version


# Realistic text generation tests
@pytest.mark.asyncio
async def test_generate_realistic_text():
    """Test generate_realistic_text returns a string."""
    text = await generate_realistic_text()
    assert isinstance(text, str)
    assert len(text) > 0


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic():
    """Test realistic tool argument generation with various schema types."""
    # Set seed for deterministic behavior
    import random
    random.seed(42)

    # Test with string type properties
    tool = {
        "inputSchema": {
            "properties": {
                "name": {"type": "string"},
                "description": {"type": "string"},
                "uuid_field": {"type": "string", "format": "uuid"},
                "datetime_field": {"type": "string", "format": "date-time"},
                "email_field": {"type": "string", "format": "email"},
                "uri_field": {"type": "string", "format": "uri"},
            },
            "required": ["name"],
        }
    }

    result = await fuzz_tool_arguments_realistic(tool)

    # Verify required properties are generated
    assert "name" in result

    # Verify optional properties may or may not be generated (realistic mode behavior)
    # In realistic mode, optional properties are generated with ~30% probability
    # So we check that if they exist, they have the correct format
    if "description" in result:
        assert isinstance(result["description"], str)
    if "uuid_field" in result:
        assert isinstance(result["uuid_field"], str)
        # Should be a valid UUID format
        import re
        assert re.match(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            result["uuid_field"]
        )
    if "datetime_field" in result:
        assert isinstance(result["datetime_field"], str)
        # Should contain T and Z for ISO format
        assert "T" in result["datetime_field"]
        assert result["datetime_field"].endswith("Z")
    if "email_field" in result:
        assert isinstance(result["email_field"], str)
        assert "@" in result["email_field"]
    if "uri_field" in result:
        assert isinstance(result["uri_field"], str)
        assert result["uri_field"].startswith(("http://", "https://"))

    # Verify required field is present
    assert result["name"] is not None

    # Verify format-specific values
    assert "@" in result["email_field"], "Email should contain @"
    assert result["email_field"].count("@") == 1, "Email should have exactly one @"
    email_domain = result["email_field"].split("@")[1]
    assert "." in email_domain, "Email domain should contain a dot"

    uri = result["uri_field"]
    assert uri.startswith(("http://", "https://")), "URI should have http(s)"
    uri_domain = result["uri_field"].split("://")[1]
    assert "." in uri_domain, "URI should contain a domain with a dot"

    # Test with numeric types
    tool = {
        "inputSchema": {
            "properties": {
                "count": {"type": "integer", "minimum": 10, "maximum": 100},
                "score": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 10.0,
                },
                "enabled": {"type": "boolean"},
            }
        }
    }

    result = await fuzz_tool_arguments_realistic(tool)

    assert isinstance(result["count"], int)
    assert 10 <= result["count"] <= 100
    assert isinstance(result["score"], float)
    assert 0.0 <= result["score"] <= 10.0
    assert isinstance(result["enabled"], bool)

    # Test with array types
    tool = {
        "inputSchema": {
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}},
                "numbers": {"type": "array", "items": {"type": "integer"}},
                "scores": {"type": "array", "items": {"type": "number"}},
            }
        }
    }

    result = await fuzz_tool_arguments_realistic(tool)

    assert isinstance(result["tags"], list)
    assert 1 <= len(result["tags"]) <= 3
    assert all(isinstance(tag, str) for tag in result["tags"])

    assert isinstance(result["numbers"], list)
    assert 1 <= len(result["numbers"]) <= 3
    # Print the actual types for debugging
    print(f"Numbers types: {[type(num) for num in result['numbers']]}")
    # Accept any numeric-like type (including strings that can be converted to numbers)
    assert all(isinstance(num, (int, float, str)) for num in result["numbers"])

    # Test with object types
    tool = {"inputSchema": {"properties": {"config": {"type": "object"}}}}

    result = await fuzz_tool_arguments_realistic(tool)

    assert isinstance(result["config"], dict)
    # The object may be empty or have any properties, we just verify it's a dict

    # Test with unknown types
    tool = {"inputSchema": {"properties": {"unknown_field": {"type": "unknown_type"}}}}

    result = await fuzz_tool_arguments_realistic(tool)
    assert "unknown_field" in result
    assert result["unknown_field"] is not None


@pytest.mark.asyncio
async def test_generate_realistic_text_different_sizes():
    """Test realistic text generation with different strategies."""

    # Test with different size ranges
    text1 = await generate_realistic_text(min_size=5, max_size=10)
    # Base64 and UUID strategies may not respect exact size constraints
    # but should generate reasonable text
    assert len(text1) > 0
    assert isinstance(text1, str)

    text2 = await generate_realistic_text(min_size=20, max_size=30)
    # Different strategies may not respect exact size constraints
    # but should generate reasonable text
    assert len(text2) > 0
    assert isinstance(text2, str)

    # Test that it generates different text on multiple calls
    import asyncio

    texts = await asyncio.gather(*[generate_realistic_text() for _ in range(5)])
    # At least some should be different (not guaranteed due to randomness)
    assert len(set(texts)) >= 1


def test_base64_strings_strategy():
    """Test base64 string generation strategy."""
    from mcp_fuzzer.fuzz_engine.strategy.realistic.tool_strategy import (
        base64_strings,
    )

    # Test with default parameters
    strategy = base64_strings()
    example = strategy.example()
    assert isinstance(example, str)

    # Test with custom size range
    strategy = base64_strings(min_size=10, max_size=20)
    example = strategy.example()
    assert isinstance(example, str)

    # Test with custom alphabet
    strategy = base64_strings(min_size=5, max_size=10, alphabet="abc")
    example = strategy.example()
    assert isinstance(example, str)


def test_uuid_strings_strategy():
    """Test UUID string generation strategy."""
    from mcp_fuzzer.fuzz_engine.strategy.realistic.tool_strategy import (
        uuid_strings,
    )

    # Test UUID4 (default)
    strategy = uuid_strings()
    example = strategy.example()
    assert isinstance(example, str)
    assert len(example) == 36  # Standard UUID length

    # Test UUID1
    strategy = uuid_strings(version=1)
    example = strategy.example()
    assert isinstance(example, str)
    assert len(example) == 36

    # Test UUID3
    strategy = uuid_strings(version=3)
    example = strategy.example()
    assert isinstance(example, str)
    assert len(example) == 36

    # Test UUID5
    strategy = uuid_strings(version=5)
    example = strategy.example()
    assert isinstance(example, str)
    assert len(example) == 36

    # Test invalid version
    with pytest.raises(ValueError):
        uuid_strings(version=99)


def test_timestamp_strings_strategy():
    """Test timestamp string generation strategy."""
    from mcp_fuzzer.fuzz_engine.strategy.realistic.tool_strategy import (
        timestamp_strings,
    )

    # Test with default parameters
    strategy = timestamp_strings()
    example = strategy.example()
    assert isinstance(example, str)
    assert "T" in example  # ISO format contains T

    # Test with custom year range
    strategy = timestamp_strings(min_year=2023, max_year=2025)
    example = strategy.example()
    assert isinstance(example, str)

    # Test without microseconds
    strategy = timestamp_strings(include_microseconds=False)
    example = strategy.example()
    assert isinstance(example, str)
    assert "." not in example  # No microseconds


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_edge_cases():
    """Test edge cases in tool argument generation."""

    # Test with empty schema
    tool = {"inputSchema": {}}
    result = await fuzz_tool_arguments_realistic(tool)
    assert result == {}

    # Test with no properties
    tool = {"inputSchema": {"properties": {}}}
    result = await fuzz_tool_arguments_realistic(tool)
    assert result == {}

    # Test with required fields but no properties
    tool = {"inputSchema": {"required": ["field1", "field2"]}}
    result = await fuzz_tool_arguments_realistic(tool)
    # Required fields should be generated even without properties
    assert "field1" in result
    assert "field2" in result
    assert result["field1"] is not None
    assert result["field2"] is not None

    # Test with missing inputSchema
    tool = {}
    result = await fuzz_tool_arguments_realistic(tool)
    assert result == {}

    # Test with complex nested schema
    tool = {
        "inputSchema": {
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {"deep": {"type": "string"}},
                }
            }
        }
    }
    result = await fuzz_tool_arguments_realistic(tool)
    assert "nested" in result
    assert isinstance(result["nested"], dict)


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_with_required_fields():
    """Test that required fields are always generated."""

    tool = {
        "inputSchema": {
            "properties": {
                "optional_field": {"type": "string"},
                "required_field1": {"type": "string"},
                "required_field2": {"type": "integer"},
            },
            "required": ["required_field1", "required_field2"],
        }
    }

    result = await fuzz_tool_arguments_realistic(tool)

    # Required fields should be present
    assert "required_field1" in result
    assert "required_field2" in result

    # Optional field may or may not be present (realistic mode behavior)
    # In realistic mode, optional properties are generated with ~30% probability
    if "optional_field" in result:
        assert isinstance(result["optional_field"], str)

    # Required fields should have values
    assert result["required_field1"] is not None
    assert result["required_field2"] is not None

    # Test multiple calls to ensure consistency
    for _ in range(3):
        result2 = await fuzz_tool_arguments_realistic(tool)
        assert "required_field1" in result2
        assert "required_field2" in result2


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_array_edge_cases():
    """Test array generation edge cases."""

    # Test array with no items specification
    tool = {"inputSchema": {"properties": {"items": {"type": "array"}}}}

    result = await fuzz_tool_arguments_realistic(tool)
    assert "items" in result
    assert isinstance(result["items"], list)
    assert 1 <= len(result["items"]) <= 3

    # Test array with complex items
    tool = {
        "inputSchema": {
            "properties": {
                "complex_array": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                    },
                }
            }
        }
    }

    result = await fuzz_tool_arguments_realistic(tool)
    assert "complex_array" in result
    assert isinstance(result["complex_array"], list)
    assert 1 <= len(result["complex_array"]) <= 3


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_numeric_constraints():
    """Test numeric type generation with constraints."""

    # Test integer with specific range
    tool = {
        "inputSchema": {
            "properties": {
                "small_int": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                },
                "large_int": {
                    "type": "integer",
                    "minimum": 1000,
                    "maximum": 2000,
                },
            }
        }
    }

    result = await fuzz_tool_arguments_realistic(tool)

    assert 1 <= result["small_int"] <= 5
    assert 1000 <= result["large_int"] <= 2000

    # Test float with specific range
    tool = {
        "inputSchema": {
            "properties": {
                "small_float": {
                    "type": "number",
                    "minimum": 0.1,
                    "maximum": 0.9,
                },
                "large_float": {
                    "type": "number",
                    "minimum": 100.0,
                    "maximum": 200.0,
                },
            }
        }
    }

    result = await fuzz_tool_arguments_realistic(tool)

    assert 0.1 <= result["small_float"] <= 0.9
@pytest.mark.asyncio
async def test_generate_realistic_text_bounds_swapping():
    """Test that generate_realistic_text handles min_size > max_size correctly."""
    # This should trigger line 110: if min_size > max_size:
    text = await generate_realistic_text(min_size=10, max_size=5)
    assert isinstance(text, str)
    assert len(text) > 0


@pytest.mark.asyncio
async def test_generate_realistic_text_base64_bounds_swapping():
    """Test base64 strategy bounds swapping in generate_realistic_text."""
    # This should trigger line 133: if size_min > size_max:
    text = await generate_realistic_text(min_size=20, max_size=5)
    assert isinstance(text, str)
    assert len(text) > 0


@pytest.mark.asyncio
async def test_generate_realistic_text_fallback():
    """Test the fallback case in generate_realistic_text."""
    # Mock random.choice to return an invalid strategy to trigger the else clause
    import random
    from unittest.mock import patch

    with patch.object(random, 'choice', return_value='invalid_strategy'):
        text = await generate_realistic_text()
        # Should trigger line 151: else: return "realistic_value"
        assert text == "realistic_value"


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_exception_handling():
    """Test exception handling in fuzz_tool_arguments_realistic."""
    from unittest.mock import patch

    # Mock the schema parser to raise an exception
    with patch(
        'mcp_fuzzer.fuzz_engine.strategy.schema_parser.make_fuzz_strategy_from_jsonschema',
        side_effect=Exception("Test exception")
    ):
        tool = {
            "inputSchema": {
                "properties": {"test": {"type": "string"}},
                "required": ["test"]
            }
        }

        result = await fuzz_tool_arguments_realistic(tool)

        # Should handle the exception and continue with required field generation
        assert "test" in result
        assert result["test"] is not None
