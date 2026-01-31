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
    generate_realistic_integer_sync,
    generate_realistic_string_sync,
    generate_realistic_text,
    _generate_realistic_array,
    fuzz_tool_arguments_realistic,
    reset_run_counter,
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


@pytest.mark.parametrize(
    "format_type, validator",
    [
        (
            "date-time",
            lambda value: value.endswith("Z")
            or "+" in value
            or "-" in value[10:],
        ),
        ("date", lambda value: len(value) == 10),
        (
            "time",
            lambda value: re.match(
                r"^\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$",
                value,
            )
            is not None,
        ),
        ("uuid", lambda value: str(uuid.UUID(value)) == value),
        ("email", lambda value: "@" in value),
        (
            "uri",
            lambda value: value.startswith("http://")
            or value.startswith("https://"),
        ),
        ("hostname", lambda value: "." in value),
        ("ipv4", lambda value: value.count(".") == 3),
        ("ipv6", lambda value: ":" in value),
        ("unknown", lambda value: value.isalnum()),
    ],
)
def test_generate_realistic_string_sync_formats(format_type, validator):
    max_len = 40 if format_type == "uuid" else 20
    schema = {"format": format_type, "minLength": 5, "maxLength": max_len}
    value = generate_realistic_string_sync(schema, key="field", run_index=0)
    assert validator(value)


@pytest.mark.parametrize(
    "pattern, expected",
    [
        ("^[a-zA-Z0-9]+$", "Test"),
        ("^[0-9]+$", "1111"),
        ("^[a-zA-Z]+$", "aaaa"),
        ("^[a-z]+$", "aaaa"),
        ("^[A-Z]+$", "AAAA"),
        ("other", "aaaa"),
    ],
)
def test_generate_realistic_string_sync_patterns(pattern, expected):
    schema = {"pattern": pattern, "minLength": 4, "maxLength": 4}
    value = generate_realistic_string_sync(schema, key="field", run_index=0)
    assert value == expected


def test_generate_realistic_integer_sync_constraints():
    schema = {
        "minimum": 2,
        "maximum": 10,
        "exclusiveMinimum": True,
        "exclusiveMaximum": 10,
        "multipleOf": 3,
    }
    value = generate_realistic_integer_sync(schema, run_index=0)
    assert value in {3, 6, 9}

    schema = {"minimum": 10, "maximum": 5}
    value = generate_realistic_integer_sync(schema, run_index=0)
    assert 5 <= value <= 10


@pytest.mark.asyncio
async def test_generate_realistic_text_strategies(monkeypatch):
    original_choice = tool_strategy.random.choice

    monkeypatch.setattr(tool_strategy.random, "choice", lambda _: "base64")
    assert isinstance(await generate_realistic_text(), str)

    monkeypatch.setattr(tool_strategy.random, "choice", lambda _: "uuid")
    assert isinstance(await generate_realistic_text(), str)

    monkeypatch.setattr(tool_strategy.random, "choice", lambda _: "timestamp")
    assert isinstance(await generate_realistic_text(), str)

    monkeypatch.setattr(tool_strategy.random, "choice", lambda _: "numbers")
    assert (await generate_realistic_text()).isdigit()

    def mixed_choice(seq, calls={"count": 0}):
        calls["count"] += 1
        if calls["count"] == 1:
            return "mixed_alphanumeric"
        return original_choice(seq)

    monkeypatch.setattr(tool_strategy.random, "choice", mixed_choice)
    assert isinstance(await generate_realistic_text(min_size=5, max_size=5), str)

    def normal_choice(seq, calls={"count": 0}):
        calls["count"] += 1
        if calls["count"] == 1:
            return "normal"
        return "Sales Performance Q4"

    monkeypatch.setattr(tool_strategy.random, "choice", normal_choice)
    assert (await generate_realistic_text(min_size=1, max_size=50)).startswith(
        "Sales"
    )


@pytest.mark.asyncio
async def test_generate_realistic_array_variants():
    array_schema = {"items": [{"type": "string"}, {"type": "integer"}], "maxItems": 1}
    result = await _generate_realistic_array(array_schema, run_index=0)
    assert isinstance(result, list)

    array_schema = {"items": {"type": "number", "minimum": 1.0, "maximum": 2.0}}
    result = await _generate_realistic_array(array_schema, run_index=0)
    assert all(isinstance(item, float) for item in result)

    array_schema = {"items": {"type": "integer", "minimum": 1, "maximum": 2}}
    result = await _generate_realistic_array(array_schema, run_index=0)
    assert all(isinstance(item, int) for item in result)

    array_schema = {"items": {"type": "string", "minLength": 2, "maxLength": 2}}
    result = await _generate_realistic_array(array_schema, run_index=0)
    assert all(isinstance(item, str) for item in result)

    array_schema = {"items": {"minLength": 1}}
    result = await _generate_realistic_array(array_schema, run_index=0)
    assert isinstance(result, list)


def test_generate_realistic_string_sync_semantic_sample():
    schema = {"minLength": 1, "maxLength": 50}
    value = generate_realistic_string_sync(schema, key="email_address", run_index=0)
    assert "@" in value
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
            },
            "required": ["count", "score", "enabled"],
        }
    }
    
    result = await fuzz_tool_arguments_realistic(tool)
    assert isinstance(result["count"], int)
    assert 10 <= result["count"] <= 100
    assert isinstance(result["score"], (int, float))
    assert 0.0 <= result["score"] <= 10.0
    assert isinstance(result["enabled"], bool)
    
    # Test with array types
    tool = {
        "inputSchema": {
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}},
                "numbers": {"type": "array", "items": {"type": "integer"}},
            },
            "required": ["tags", "numbers"],
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


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic_enum_const_object():
    reset_run_counter()
    tool = {
        "inputSchema": {
            "properties": {
                "mode": {"type": "string", "enum": ["a", "b"]},
                "status": {"const": "ok"},
                "nested": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                },
                "choice": {"type": ["string", "null"]},
            },
            "required": ["mode", "status", "nested", "choice"],
        }
    }
    result = await fuzz_tool_arguments_realistic(tool)
    assert result["mode"] in {"a", "b"}
    assert result["status"] == "ok"
    assert isinstance(result["nested"], dict)
    assert isinstance(result["choice"], str)
    
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
    # With deterministic cycling, generate_realistic_text always returns
    # a valid string based on run_index, no random fallback
    text = await generate_realistic_text()
    assert isinstance(text, str)
    assert len(text) >= 1


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
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1,
                    "items": {"type": "object"},
                },
            }
        }
    }
    result = await fuzz_tool_arguments_realistic(tool)
    assert result["items"] == [{"nested": "ok"}]


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic_array_number(monkeypatch):
    def _mk(schema, phase="realistic"):
        if schema.get("type") == "number":
            return 1.23
        return {}

    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        _mk,
    )

    tool = {
        "inputSchema": {
            "properties": {
                "scores": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 2,
                    "items": {"type": "number"},
                },
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
    reset_run_counter()
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


def test_generate_realistic_string_sync_format_and_pattern():
    tool_strategy.reset_run_counter()
    value = tool_strategy.generate_realistic_string_sync(
        {"format": "email", "minLength": 20, "maxLength": 30},
        key="email",
    )
    assert "@" in value
    assert 20 <= len(value) <= 30

    digits = tool_strategy.generate_realistic_string_sync(
        {"pattern": "^[0-9]+$", "minLength": 2, "maxLength": 4}
    )
    assert digits.isdigit()
    assert 2 <= len(digits) <= 4


def test_generate_realistic_string_sync_semantic_adjusts_bounds():
    value = tool_strategy.generate_realistic_string_sync(
        {"minLength": 10, "maxLength": 5},
        key="name",
        run_index=0,
    )
    assert len(value) == 10

    short = tool_strategy.generate_realistic_string_sync(
        {"minLength": 0, "maxLength": 2},
        key="name",
        run_index=0,
    )
    assert len(short) == 2


def test_generate_formatted_string_fallbacks():
    short_email = tool_strategy._generate_formatted_string("email", 0, 3)
    assert len(short_email) <= 3

    padded_uri = tool_strategy._generate_formatted_string("uri", 25, 40)
    assert padded_uri.startswith("https://")
    assert len(padded_uri) >= 25

    hostname = tool_strategy._generate_formatted_string("hostname", 0, 3)
    assert len(hostname) <= 3

    fallback_uuid = tool_strategy._generate_formatted_string("uuid", 100, 101)
    assert len(fallback_uuid) >= 100

    short_uri = tool_strategy._generate_formatted_string("uri", 0, 10)
    assert len(short_uri) <= 10

    padded_hostname = tool_strategy._generate_formatted_string("hostname", 12, 20)
    assert len(padded_hostname) >= 12


def test_generate_pattern_string_invalid_regex():
    value = tool_strategy._generate_pattern_string("(", 1, 5)
    assert 1 <= len(value) <= 5


def test_generate_realistic_integer_sync_exclusive_multiple():
    value = tool_strategy.generate_realistic_integer_sync(
        {
            "minimum": 1.2,
            "maximum": 5.8,
            "exclusiveMinimum": True,
            "exclusiveMaximum": True,
            "multipleOf": 2,
        },
        run_index=0,
    )
    assert value == 4


def test_generate_realistic_integer_sync_swaps_bounds():
    value = tool_strategy.generate_realistic_integer_sync(
        {"minimum": 10, "maximum": 5},
        run_index=1,
    )
    assert 5 <= value <= 10


@pytest.mark.asyncio
async def test_generate_realistic_text_pads_when_small(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: seq[-1])
    value = await tool_strategy.generate_realistic_text(min_size=50, max_size=60)
    assert len(value) >= 50


@pytest.mark.asyncio
async def test_generate_realistic_array_tuple_items_expanded():
    schema = {
        "minItems": 3,
        "maxItems": 3,
        "items": [{"type": "string"}, {"type": "integer"}],
        "additionalItems": {"type": "string"},
    }
    result = await tool_strategy._generate_realistic_array(schema, run_index=0)
    assert len(result) == 3


@pytest.mark.asyncio
async def test_generate_realistic_array_string_items_and_error(monkeypatch):
    schema = {"minItems": 2, "maxItems": 2, "items": {"type": "string"}}
    result = await tool_strategy._generate_realistic_array(schema, run_index=1)
    assert len(result) == 2

    schema = {"minItems": 3, "maxItems": 1, "items": []}
    result = await tool_strategy._generate_realistic_array(schema, run_index=0)
    assert len(result) == 3

    def boom(*_args, **_kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        boom,
    )
    schema = {"minItems": 1, "maxItems": 1, "items": {"type": "object"}}
    result = await tool_strategy._generate_realistic_array(schema, run_index=0)
    assert result == ["item"]


@pytest.mark.asyncio
async def test_fuzz_tool_arguments_realistic_covers_branches(monkeypatch):
    tool_strategy.reset_run_counter()

    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser.make_fuzz_strategy_from_jsonschema",
        lambda *_args, **_kwargs: {},
    )

    async def fake_text(*_args, **_kwargs):
        return "text"

    monkeypatch.setattr(tool_strategy, "generate_realistic_text", fake_text)

    tool = {
        "inputSchema": {
            "type": "object",
            "required": [
                "ratio",
                "ratio2",
                "bad_number",
                "count",
                "flag",
                "payload",
                "tags",
                "choice",
                "const_val",
                "misc",
            ],
            "properties": {
                "ratio": {
                    "type": "number",
                    "minimum": 0.1,
                    "maximum": 0.3,
                    "exclusiveMinimum": True,
                    "exclusiveMaximum": True,
                    "multipleOf": 0.1,
                },
                "ratio2": {
                    "type": "number",
                    "exclusiveMinimum": 0.05,
                    "exclusiveMaximum": 0.15,
                    "minimum": 0.2,
                    "maximum": 0.1,
                },
                "bad_number": {
                    "type": "number",
                    "minimum": "bad",
                    "maximum": "bad",
                },
                "count": {"type": "integer", "minimum": 1, "maximum": 2},
                "flag": {"type": "boolean"},
                "payload": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
                "tags": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 2,
                    "items": {"type": "string"},
                },
                "choice": {"enum": ["a", "b"]},
                "const_val": {"const": "fixed"},
                "optional": {"type": "string"},
                "misc": "not-a-dict",
            },
        }
    }

    args = await tool_strategy.fuzz_tool_arguments_realistic(tool)
    assert set(
        [
            "ratio",
            "ratio2",
            "bad_number",
            "count",
            "flag",
            "payload",
            "tags",
            "choice",
            "const_val",
            "misc",
        ]
    ).issubset(args)

    # Trigger the "should_include" skip branch with a second run
    args_second = await tool_strategy.fuzz_tool_arguments_realistic(tool)
    assert "optional" not in args_second
