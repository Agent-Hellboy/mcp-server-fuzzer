"""
Unit tests for realistic Hypothesis strategies.
"""

import base64
import re
import uuid
from datetime import datetime
from unittest.mock import AsyncMock

import pytest
from hypothesis import given

from mcp_fuzzer.fuzz_engine.mutators.strategies.realistic.tool_strategy import (
    base64_strings,
    timestamp_strings,
    uuid_strings,
    generate_realistic_text,
    fuzz_tool_arguments_realistic,
)
from mcp_fuzzer.fuzz_engine.mutators.strategies.realistic import tool_strategy
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


def test_uuid_strings_invalid_version():
    with pytest.raises(ValueError):
        uuid_strings(version=2)


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
async def test_generate_realistic_text_normal_title_branch(monkeypatch):
    choices = iter(["normal", "Sales Performance Q4"])
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: next(choices))
    text = await generate_realistic_text(min_size=0, max_size=100)
    assert text == "Sales Performance Q4"


@pytest.mark.asyncio
async def test_generate_realistic_text_base64_branch(monkeypatch):
    loop = type("Loop", (), {})()
    loop.run_in_executor = AsyncMock(return_value="b64")
    monkeypatch.setattr(tool_strategy.asyncio, "get_running_loop", lambda: loop)
    monkeypatch.setattr(tool_strategy.random, "choice", lambda _seq: "base64")
    text = await generate_realistic_text(min_size=4, max_size=2)
    assert text == "b64"
    loop.run_in_executor.assert_awaited_once()


@pytest.mark.asyncio
async def test_generate_realistic_text_uuid_branch(monkeypatch):
    loop = type("Loop", (), {})()
    loop.run_in_executor = AsyncMock(return_value="uuid-value")
    monkeypatch.setattr(tool_strategy.asyncio, "get_running_loop", lambda: loop)
    monkeypatch.setattr(tool_strategy.random, "choice", lambda _seq: "uuid")
    text = await generate_realistic_text()
    assert text == "uuid-value"
    loop.run_in_executor.assert_awaited_once()


@pytest.mark.asyncio
async def test_generate_realistic_text_timestamp_branch(monkeypatch):
    loop = type("Loop", (), {})()
    loop.run_in_executor = AsyncMock(return_value="ts-value")
    monkeypatch.setattr(tool_strategy.asyncio, "get_running_loop", lambda: loop)
    monkeypatch.setattr(tool_strategy.random, "choice", lambda _seq: "timestamp")
    text = await generate_realistic_text()
    assert text == "ts-value"
    loop.run_in_executor.assert_awaited_once()


@pytest.mark.asyncio
async def test_generate_realistic_text_numbers_branch(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "choice", lambda _seq: "numbers")
    monkeypatch.setattr(tool_strategy.random, "randint", lambda *_args: 42)
    text = await generate_realistic_text()
    assert text == "42"


@pytest.mark.asyncio
async def test_generate_realistic_text_mixed_alphanumeric_branch(monkeypatch):
    def _choice(seq):
        if "mixed_alphanumeric" in seq:
            return "mixed_alphanumeric"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", _choice)
    monkeypatch.setattr(tool_strategy.random, "randint", lambda *_args: 5)
    text = await generate_realistic_text()
    assert len(text) == 5


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


@pytest.mark.asyncio
async def test_generate_realistic_text_normal_chars(monkeypatch):
    def _choice(seq):
        if "mixed_alphanumeric" in seq or "normal" in seq:
            return "normal"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", _choice)
    monkeypatch.setattr(tool_strategy.random, "randint", lambda *_args: 5)

    text = await generate_realistic_text(min_size=5, max_size=5)

    assert len(text) == 5


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic_array_object(monkeypatch):
    async def _fake_text(*_args, **_kwargs):
        return "x"

    monkeypatch.setattr(tool_strategy, "generate_realistic_text", _fake_text)
    monkeypatch.setattr(tool_strategy.random, "randint", lambda *_args: 1)

    def _mk(schema, phase="realistic"):
        if schema.get("type") == "object":
            return {"nested": "ok"}
        return {}

    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        _mk,
    )

    tool = {
        "inputSchema": {
            "properties": {
                "items": {"type": "array", "items": {"type": "object"}},
            }
        }
    }
    result = await fuzz_tool_arguments_realistic(tool)
    assert result["items"] == [{"nested": "ok"}]


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic_array_number(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "randint", lambda *_args: 2)
    monkeypatch.setattr(tool_strategy.random, "uniform", lambda *_args: 1.23)
    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        lambda *_args, **_kwargs: {},
    )

    tool = {
        "inputSchema": {
            "properties": {
                "scores": {"type": "array", "items": {"type": "number"}},
            }
        }
    }
    result = await fuzz_tool_arguments_realistic(tool)
    assert result["scores"] == [1.23, 1.23]


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic_object_nested_exception(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        _boom,
    )

    tool = {"inputSchema": {"properties": {"payload": {"type": "object"}}}}
    result = await fuzz_tool_arguments_realistic(tool)
    assert result["payload"] == {}


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic_string_formats(monkeypatch):
    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        tool_strategy.random,
        "choices",
        lambda *_args, **_kwargs: list("username"),
    )
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: seq[0])

    tool = {
        "inputSchema": {
            "properties": {
                "email": {"type": "string", "format": "email"},
                "uri": {"type": "string", "format": "uri"},
                "uuid": {"type": "string", "format": "uuid"},
            }
        }
    }
    result = await fuzz_tool_arguments_realistic(tool)
    assert "@" in result["email"]
    assert result["uri"].startswith("http")
    assert isinstance(result["uuid"], str)


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic_unknown_type(monkeypatch):
    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        tool_strategy,
        "generate_realistic_text",
        AsyncMock(return_value="value"),
    )

    tool = {"inputSchema": {"properties": {"mystery": {"type": "null"}}}}
    result = await fuzz_tool_arguments_realistic(tool)
    assert result["mystery"] == "value"
