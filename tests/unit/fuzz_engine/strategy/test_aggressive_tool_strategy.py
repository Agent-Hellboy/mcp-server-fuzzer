#!/usr/bin/env python3
"""
Tests for aggressive tool argument strategies.
"""

import re

from mcp_fuzzer.fuzz_engine.mutators.strategies.aggressive import tool_strategy
from mcp_fuzzer.fuzz_engine.mutators.strategies import schema_parser


def test_pick_semantic_string_variants():
    # With smart fuzzing, aggressive mode returns attack payloads
    file_path = tool_strategy._pick_semantic_string("file_path")
    # Now returns path traversal payloads like "../" or "/tmp/..."
    assert ".." in file_path or file_path.startswith("/tmp/") or file_path.startswith("file://")

    resource_url = tool_strategy._pick_semantic_string("resource_url")
    assert resource_url.startswith("file://") or "://" in resource_url

    cursor = tool_strategy._pick_semantic_string("cursor")
    assert re.search(r"t.*id", cursor)

    name = tool_strategy._pick_semantic_string("name")
    assert re.search(r"t.*id", name)

    query = tool_strategy._pick_semantic_string("query")
    # May contain SQL injection payloads
    assert query.startswith("q=") or "'" in query or " OR " in query

    # Misc no longer returns garbage "A" * 256
    misc = tool_strategy._pick_semantic_string("misc")
    assert len(misc) <= 256  # Conservative, no extreme garbage


def test_pick_semantic_number_bounds():
    spec = {"minimum": 1, "maximum": 10}
    # In aggressive mode, _pick_semantic_number returns off-by-one violations
    # "min_value" tries to go below minimum (minimum - 1)
    assert tool_strategy._pick_semantic_number("min_value", spec) == 0  # 1 - 1
    # "max_value" tries to exceed maximum (maximum + 1)
    assert tool_strategy._pick_semantic_number("max_value", spec) == 11  # 10 + 1
    # "limit" also tries to exceed maximum
    assert tool_strategy._pick_semantic_number("limit", spec) == 11


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
    # String should meet minLength (5) and not exceed maxLength (8)
    assert 5 <= len(args["file_path"]) <= 8
    # In aggressive mode, _pick_semantic_number returns off-by-one: maximum + 1
    assert args["user_id"] == 10  # 9 + 1 (off-by-one above maximum)
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


def test_generate_aggressive_text_semantic_hints(monkeypatch):
    monkeypatch.setattr(
        tool_strategy,
        "get_payload_within_length",
        lambda _, k: f"{k}_payload",
    )
    monkeypatch.setattr(tool_strategy, "SSRF_PAYLOADS", ["ssrf://payload"])
    monkeypatch.setattr(tool_strategy, "PATH_TRAVERSAL", ["../"])
    monkeypatch.setattr(tool_strategy, "COMMAND_INJECTION", ["; ls"])
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: seq[0])

    assert tool_strategy.generate_aggressive_text(key="resource_url") == "ssrf://payload"
    assert tool_strategy.generate_aggressive_text(key="file_path") == "../"
    assert tool_strategy.generate_aggressive_text(key="search_query") == "sql_payload"
    assert tool_strategy.generate_aggressive_text(key="html_body") == "xss_payload"
    assert tool_strategy.generate_aggressive_text(key="command") == "; ls"


def test_generate_aggressive_integer_off_by_one(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: "off_by_one")
    assert tool_strategy._generate_aggressive_integer(schema={"maximum": 5}) == 6


def test_generate_aggressive_integer_negative(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: "negative")
    assert tool_strategy._generate_aggressive_integer(min_value=0, max_value=5) == -1


def test_generate_aggressive_float_off_by_one(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: "off_by_one")
    value = tool_strategy._generate_aggressive_float(schema={"maximum": 3.0})
    assert value == 3.001
