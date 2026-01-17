#!/usr/bin/env python3
"""
Tests for aggressive tool argument strategies.
"""

from mcp_fuzzer.fuzz_engine.mutators.strategies.aggressive import tool_strategy
from mcp_fuzzer.fuzz_engine.mutators.strategies import schema_parser


def test_pick_semantic_string_variants():
    assert tool_strategy._pick_semantic_string("file_path").startswith("/tmp/")
    assert tool_strategy._pick_semantic_string("resource_url").startswith("file://")
    assert tool_strategy._pick_semantic_string("cursor").startswith("cursor_")
    assert tool_strategy._pick_semantic_string("name").startswith("id_")
    assert tool_strategy._pick_semantic_string("query").startswith("q=")
    assert tool_strategy._pick_semantic_string("misc") == "A" * 256


def test_pick_semantic_number_bounds():
    spec = {"minimum": 1, "maximum": 10}
    assert tool_strategy._pick_semantic_number("min_value", spec) == 1
    assert tool_strategy._pick_semantic_number("max_value", spec) == 10
    assert tool_strategy._pick_semantic_number("limit", spec) == 10


def test_apply_semantic_edge_cases_clamps(monkeypatch):
    args = {"file_path": "ok", "user_id": 5, "email": "x"}
    schema = {
        "properties": {
            "file_path": {"type": "string", "minLength": 5, "maxLength": 8},
            "user_id": {"type": "integer", "minimum": 1, "maximum": 9},
            "email": {"type": "string", "format": "email", "minLength": 6},
        }
    }
    tool_strategy._apply_semantic_edge_cases(args, schema)
    assert len(args["file_path"]) == 8
    assert args["user_id"] == 9
    assert args["email"].startswith("fuzzer+")


def test_fuzz_tool_arguments_aggressive_fallbacks(monkeypatch):
    monkeypatch.setattr(
        schema_parser,
        "make_fuzz_strategy_from_jsonschema",
        lambda schema, phase=None: ["not-a-dict"],
    )
    monkeypatch.setattr(tool_strategy.random, "random", lambda: 0.0)
    monkeypatch.setattr(
        tool_strategy,
        "apply_schema_edge_cases",
        lambda args, schema, phase=None, key=None: args,
    )

    schema = {
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer", "minimum": 1, "maximum": 2},
            "ratio": {"type": "number"},
            "flag": {"type": "boolean"},
            "items": {"type": "array"},
            "meta": {"type": "object"},
        },
        "required": ["name"],
    }
    tool = {"name": "demo", "inputSchema": schema}
    args = tool_strategy.fuzz_tool_arguments_aggressive(tool)
    assert "name" in args
    assert "count" in args
    assert "ratio" in args
    assert "flag" in args
    assert "items" in args
    assert "meta" in args
