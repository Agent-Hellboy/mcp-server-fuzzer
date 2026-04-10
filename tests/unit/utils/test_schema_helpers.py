"""Coverage tests for schema helper utilities."""

from mcp_fuzzer.utils.schema_helpers import (
    _build_tool_arguments,
    _default_schema_value,
    _first_schema_choice,
    _tool_task_support,
)


def test_first_schema_choice_prefers_enum():
    schema = {"enum": ["alpha", "beta"]}
    assert _first_schema_choice(schema) == "alpha"


def test_default_schema_value_uses_default_and_choice_and_types():
    assert _default_schema_value("field", {"default": 7}) == 7
    assert _default_schema_value("field", {"enum": ["x", "y"]}) == "x"
    assert _default_schema_value("field", {"oneOf": [{"const": "k"}]}) == "k"
    assert _default_schema_value("flag", {"type": "boolean"}) is False
    assert _default_schema_value("num", {"type": "integer", "minimum": 3}) == 3
    assert _default_schema_value("num", {"type": "number"}) == 0


def test_default_schema_value_array_and_object_and_null_and_fallback():
    array_schema = {"type": "array", "items": {"type": "string"}}
    assert _default_schema_value("items", array_schema) == ["items-value"]

    object_schema = {
        "type": "object",
        "required": ["a"],
        "properties": {
            "a": {"type": "integer", "minimum": 2},
            "b": {"type": "string"},
        },
    }
    assert _default_schema_value("obj", object_schema) == {"a": 2}

    assert _default_schema_value("nil", {"type": "null"}) is None
    assert _default_schema_value("unknown", {"type": "string"}) == "unknown-value"


def test_build_tool_arguments_and_task_support():
    tool = {
        "name": "demo",
        "inputSchema": {
            "type": "object",
            "required": ["prompt"],
            "properties": {"prompt": {"type": "string"}},
        },
        "execution": {"taskSupport": "allowed"},
    }
    assert _build_tool_arguments(tool) == {"prompt": "prompt-value"}
    assert _tool_task_support(tool) == "allowed"
    assert _tool_task_support({"execution": {"taskSupport": 123}}) == "forbidden"
