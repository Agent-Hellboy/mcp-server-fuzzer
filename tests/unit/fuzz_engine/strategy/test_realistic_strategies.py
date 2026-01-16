"""
Unit tests for realistic Hypothesis strategies.
"""

import base64
import re
import uuid
from datetime import datetime

import pytest
from hypothesis import given

from mcp_fuzzer.fuzz_engine.mutators.strategies.realistic.tool_strategy import (
    base64_strings,
    timestamp_strings,
    uuid_strings,
    generate_realistic_text,
    fuzz_tool_arguments_realistic,
)
from mcp_fuzzer.fuzz_engine.mutators.strategies.realistic.protocol_type_strategy import (  # noqa: E501
    json_rpc_id_values,
    method_names,
    protocol_version_strings,
)

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.strategy]


@given(base64_strings())
def test_base64_strings_valid(value):
    """Test base64_strings generates valid Base64 strings."""
    assert isinstance(value, str)
    decoded = base64.b64decode(value)
    reencoded = base64.b64encode(decoded).decode("ascii")
    assert value == reencoded


@given(uuid_strings())
def test_uuid_strings_valid(value):
    """Test uuid_strings generates valid UUID strings."""
    assert isinstance(value, str)
    parsed_uuid = uuid.UUID(value)
    assert str(parsed_uuid) == value


@pytest.mark.parametrize("version", [1, 3, 4, 5])
def test_uuid_strings_versions(version):
    """Test UUID version generation."""
    strategy = uuid_strings(version=version)
    value = strategy.example()
    parsed_uuid = uuid.UUID(value)
    assert parsed_uuid.version == version


@given(timestamp_strings())
def test_timestamp_strings_valid(value):
    """Test timestamp_strings generates valid ISO-8601 timestamps."""
    assert isinstance(value, str)
    parsed_dt = datetime.fromisoformat(value)
    assert isinstance(parsed_dt, datetime)
    assert parsed_dt.tzinfo is not None


@given(timestamp_strings(min_year=2024, max_year=2024))
def test_timestamp_strings_year_range(value):
    """Test timestamp year range constraint."""
    parsed_dt = datetime.fromisoformat(value)
    assert parsed_dt.year == 2024


@given(protocol_version_strings())
def test_protocol_version_strings_format(value):
    """Test protocol_version_strings generates valid formats."""
    assert isinstance(value, str)
    date_pattern = r"^\d{4}-\d{2}-\d{2}$"
    semver_pattern = r"^\d+\.\d+\.\d+$"
    assert re.match(date_pattern, value) or re.match(semver_pattern, value)


@given(json_rpc_id_values())
def test_json_rpc_id_values_types(value):
    """Test json_rpc_id_values generates valid types."""
    assert type(value) in [type(None), str, int, float]


@given(method_names())
def test_method_names_format(value):
    """Test method_names generates reasonable method names."""
    assert isinstance(value, str)
    assert len(value) > 0
    # All method names should start with alpha (filter ensures this)
    if not any(value.startswith(p) for p in [
        "initialize", "tools/", "resources/", "prompts/",
        "notifications/", "completion/", "sampling/",
    ]):
        assert value[0].isalpha()
    
    # Test that filter works - empty strings or non-alpha starters are filtered out
    # This is tested implicitly by Hypothesis, but we verify the property
    prefixes = (
        "tools/", "resources/", "prompts/",
        "notifications/", "completion/", "sampling/"
    )
    assert value and (value[0].isalpha() or value.startswith(prefixes))


def test_base64_strings_with_size_constraints():
    """Test base64_strings with size constraints."""
    strategy = base64_strings(min_size=10, max_size=20)
    value = strategy.example()
    decoded = base64.b64decode(value)
    assert 10 <= len(decoded) <= 20


def test_timestamp_strings_without_microseconds():
    """Test timestamp_strings without microseconds."""
    strategy = timestamp_strings(include_microseconds=False)
    value = strategy.example()
    assert "." not in value


@pytest.mark.asyncio
async def test_generate_realistic_text():
    """Test generate_realistic_text returns a string."""
    text = await generate_realistic_text()
    assert isinstance(text, str)
    assert len(text) > 0


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic():
    """Test realistic tool argument generation."""
    import random
    random.seed(42)
    
    # Test with string type properties
    tool = {
        "inputSchema": {
            "properties": {
                "name": {"type": "string"},
                "uuid_field": {"type": "string", "format": "uuid"},
                "datetime_field": {"type": "string", "format": "date-time"},
                "email_field": {"type": "string", "format": "email"},
                "uri_field": {"type": "string", "format": "uri"},
            },
            "required": ["name"],
        }
    }
    
    result = await fuzz_tool_arguments_realistic(tool)
    assert "name" in result
    
    if "email_field" in result:
        assert "@" in result["email_field"]
        assert result["email_field"].count("@") == 1
    
    if "uri_field" in result:
        assert result["uri_field"].startswith(("http://", "https://"))
    
    # Test with numeric types
    tool = {
        "inputSchema": {
            "properties": {
                "count": {"type": "integer", "minimum": 10, "maximum": 100},
                "score": {"type": "number", "minimum": 0.0, "maximum": 10.0},
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
            }
        }
    }
    
    result = await fuzz_tool_arguments_realistic(tool)
    assert isinstance(result["tags"], list)
    assert all(isinstance(tag, str) for tag in result["tags"])
    assert isinstance(result["numbers"], list)


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_edge_cases():
    """Test edge cases in tool argument generation."""
    # Empty schema
    tool = {"inputSchema": {}}
    result = await fuzz_tool_arguments_realistic(tool)
    assert result == {}
    
    # No properties
    tool = {"inputSchema": {"properties": {}}}
    result = await fuzz_tool_arguments_realistic(tool)
    assert result == {}
    
    # Required fields but no properties
    tool = {"inputSchema": {"required": ["field1", "field2"]}}
    result = await fuzz_tool_arguments_realistic(tool)
    assert "field1" in result
    assert "field2" in result
    
    # Missing inputSchema
    tool = {}
    result = await fuzz_tool_arguments_realistic(tool)
    assert result == {}


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
    assert "required_field1" in result
    assert "required_field2" in result
    assert result["required_field1"] is not None
    assert result["required_field2"] is not None


@pytest.mark.asyncio
async def test_generate_realistic_text_bounds_swapping():
    """Test generate_realistic_text handles min_size > max_size correctly."""
    text = await generate_realistic_text(min_size=10, max_size=5)
    assert isinstance(text, str)
    assert len(text) > 0


@pytest.mark.asyncio
async def test_generate_realistic_text_fallback():
    """Test the fallback case in generate_realistic_text."""
    import random
    from unittest.mock import patch
    
    with patch.object(random, "choice", return_value="invalid_strategy"):
        text = await generate_realistic_text()
        assert text == "realistic_value"


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_exception_handling():
    """Test exception handling in fuzz_tool_arguments_realistic."""
    from unittest.mock import patch
    
    with patch(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        side_effect=Exception("Test exception"),
    ):
        tool = {
            "inputSchema": {
                "properties": {"test": {"type": "string"}},
                "required": ["test"],
            }
        }
        result = await fuzz_tool_arguments_realistic(tool)
        assert "test" in result
        assert result["test"] is not None
