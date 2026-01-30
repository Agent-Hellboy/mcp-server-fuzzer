#!/usr/bin/env python3
"""
Additional tests for aggressive tool argument strategies.
"""

from mcp_fuzzer.fuzz_engine.mutators.strategies.aggressive import tool_strategy


def _force_strategy(monkeypatch, strategy: str) -> None:
    def choice(seq):
        if isinstance(seq, list) and "sql_injection" in seq and "edge_chars" in seq:
            return strategy
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    monkeypatch.setattr(tool_strategy.random, "randint", lambda a, b: a)


def test_generate_aggressive_text_broken_base64(monkeypatch):
    _force_strategy(monkeypatch, "broken_base64")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=30)
    assert "Base64" in value


def test_generate_aggressive_text_padding_and_truncation(monkeypatch):
    _force_strategy(monkeypatch, "broken_base64")
    padded = tool_strategy.generate_aggressive_text(min_size=20, max_size=20)
    assert len(padded) == 20
    truncated = tool_strategy.generate_aggressive_text(min_size=1, max_size=5)
    assert len(truncated) == 5


def test_generate_aggressive_text_unicode(monkeypatch):
    _force_strategy(monkeypatch, "unicode")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=5)
    assert value


def test_generate_aggressive_text_null_bytes(monkeypatch):
    _force_strategy(monkeypatch, "null_bytes")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=5)
    assert "\x00" in value


def test_generate_aggressive_text_nosql_semantic(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: seq[0])
    value = tool_strategy.generate_aggressive_text(
        min_size=1,
        max_size=40,
        key="mongo_doc",
    )
    assert value.startswith("{")


def test_generate_aggressive_text_overflow(monkeypatch):
    _force_strategy(monkeypatch, "overflow")
    value = tool_strategy.generate_aggressive_text(
        min_size=1,
        max_size=10,
        allow_overflow=True,
    )
    assert len(value) >= 1000


def test_generate_aggressive_text_edge_chars(monkeypatch):
    _force_strategy(monkeypatch, "edge_chars")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=4)
    assert value.startswith("'") and value.endswith("'")


def test_generate_aggressive_text_unicode_trick(monkeypatch):
    _force_strategy(monkeypatch, "unicode_trick")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=20)
    assert "test" in value


def test_generate_aggressive_text_broken_format(monkeypatch):
    _force_strategy(monkeypatch, "broken_format")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=30)
    assert "invalid" in value or "uuid" in value


def test_generate_aggressive_text_encoding_bypass(monkeypatch):
    _force_strategy(monkeypatch, "encoding_bypass")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=10)
    assert value.startswith("%")


def test_generate_aggressive_text_nosql_strategy(monkeypatch):
    _force_strategy(monkeypatch, "nosql_injection")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=80)
    assert value.startswith("{")


def test_generate_aggressive_text_command_injection(monkeypatch):
    _force_strategy(monkeypatch, "command_injection")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=20)
    assert ";" in value or "|" in value


def test_generate_aggressive_integer_swaps_bounds(monkeypatch):
    def choice(seq):
        return "normal" if isinstance(seq, list) else seq[0]

    seen = {}

    def randint(a, b):
        seen["args"] = (a, b)
        return a

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    monkeypatch.setattr(tool_strategy.random, "randint", randint)
    value = tool_strategy._generate_aggressive_integer(min_value=10, max_value=5)
    assert value == 5
    assert seen["args"] == (5, 10)


def test_generate_aggressive_integer_overflow(monkeypatch):
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "overflow" in seq:
            return "overflow"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_integer(min_value=-10, max_value=10)
    assert value < -10 or value > 10


def test_generate_aggressive_integer_boundary(monkeypatch):
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "overflow" in seq:
            return "boundary"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_integer(min_value=1, max_value=2)
    assert value in (1, 2)


def test_pick_semantic_string_respects_zero_max():
    value = tool_strategy._pick_semantic_string("query", max_length=0)
    assert value == ""


def test_fallback_array_normalizes_bounds(monkeypatch):
    from mcp_fuzzer.fuzz_engine.mutators.strategies import schema_parser

    monkeypatch.setattr(
        schema_parser,
        "make_fuzz_strategy_from_jsonschema",
        lambda *_: {},
    )
    monkeypatch.setattr(tool_strategy.random, "random", lambda: 0.0)
    monkeypatch.setattr(tool_strategy.random, "randint", lambda a, b: a)
    monkeypatch.setattr(
        tool_strategy,
        "apply_schema_edge_cases",
        lambda args, schema, phase=None, key=None: args,
    )

    schema = {
        "properties": {
            "items": {
                "type": "array",
                "minItems": 7,
                "maxItems": 2,
                "items": {"type": "string"},
            }
        },
    }
    tool = {"name": "demo", "inputSchema": schema}
    args = tool_strategy.fuzz_tool_arguments_aggressive(tool)
    assert len(args["items"]) == 2


def test_generate_aggressive_integer_off_by_one_minimum(monkeypatch):
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "overflow" in seq:
            return "off_by_one"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_integer(schema={"minimum": 3})
    assert value == 2


def test_generate_aggressive_integer_off_by_one_fallback(monkeypatch):
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "overflow" in seq:
            return "off_by_one"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_integer()
    assert value > 1000 or value < -1000


def test_pick_semantic_string_truncates_for_command(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: seq[0])
    value = tool_strategy._pick_semantic_string("command", max_length=2)
    assert len(value) == 2


def test_pick_semantic_string_html_branch(monkeypatch):
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: seq[0])
    value = tool_strategy._pick_semantic_string("html_body", max_length=10)
    assert len(value) <= 10


def test_pick_semantic_number_min_without_minimum():
    value = tool_strategy._pick_semantic_number("min_value", {})
    assert value == -1


def test_pick_semantic_number_no_bounds():
    value = tool_strategy._pick_semantic_number("value", {})
    assert value == 2147483648


def test_apply_semantic_edge_cases_enum_variation(monkeypatch):
    args = {"mode": "alpha"}
    schema = {"properties": {"mode": {"type": "string", "enum": ["alpha"]}}}
    monkeypatch.setattr(tool_strategy.random, "random", lambda: 0.0)
    tool_strategy._apply_semantic_edge_cases(args, schema)
    assert args["mode"] == "ALPHA"


def test_apply_semantic_edge_cases_enum_no_variation(monkeypatch):
    args = {"mode": "beta"}
    schema = {"properties": {"mode": {"type": "string", "enum": ["beta"]}}}
    monkeypatch.setattr(tool_strategy.random, "random", lambda: 0.9)
    tool_strategy._apply_semantic_edge_cases(args, schema)
    assert args["mode"] == "beta"


def test_apply_semantic_edge_cases_const_and_nondict():
    args = {"plain": "value", "fixed": "keep"}
    schema = {
        "properties": {
            "plain": "not-a-dict",
            "fixed": {"type": "string", "const": "keep"},
        }
    }
    tool_strategy._apply_semantic_edge_cases(args, schema)
    assert args["plain"] == "value"
    assert args["fixed"] == "keep"


def test_apply_semantic_edge_cases_uri_format(monkeypatch):
    args = {"site": "http://example.com"}
    schema = {
        "properties": {
            "site": {"type": "string", "format": "uri", "maxLength": 10}
        }
    }
    monkeypatch.setattr(tool_strategy.random, "choice", lambda seq: seq[0])
    tool_strategy._apply_semantic_edge_cases(args, schema)
    assert args["site"].startswith("http")


def test_apply_semantic_edge_cases_uuid_format(monkeypatch):
    args = {"id": "1234"}
    schema = {"properties": {"id": {"type": "string", "format": "uuid"}}}
    tool_strategy._apply_semantic_edge_cases(args, schema)
    assert args["id"].startswith("0000")


def test_generate_aggressive_float_off_by_one_minimum(monkeypatch):
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "infinity" in seq:
            return "off_by_one"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_float(schema={"minimum": 1.5})
    assert value == 1.499


def test_generate_aggressive_float_boundary(monkeypatch):
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "infinity" in seq:
            return "boundary"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_float(min_value=1.0, max_value=2.0)
    assert value in (1.0, 2.0)


def test_generate_aggressive_float_negative_upper_lt_min(monkeypatch):
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "infinity" in seq:
            return "negative"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_float(min_value=0.0, max_value=-5.0)
    assert -5.0 <= value <= -1.0


def test_generate_aggressive_float_off_by_one_default(monkeypatch):
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "infinity" in seq:
            return "off_by_one"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_float()
    assert value > 1000.0


def test_fuzz_tool_arguments_aggressive_non_dict_schema():
    tool = {"name": "demo", "inputSchema": ["not", "a", "dict"]}
    args = tool_strategy.fuzz_tool_arguments_aggressive(tool)
    assert args == {}


def test_fallback_array_handles_invalid_bounds(monkeypatch):
    from mcp_fuzzer.fuzz_engine.mutators.strategies import schema_parser

    monkeypatch.setattr(
        schema_parser,
        "make_fuzz_strategy_from_jsonschema",
        lambda *_: {},
    )
    monkeypatch.setattr(tool_strategy.random, "random", lambda: 0.0)
    monkeypatch.setattr(tool_strategy.random, "randint", lambda a, b: a)
    monkeypatch.setattr(
        tool_strategy,
        "apply_schema_edge_cases",
        lambda args, schema, phase=None, key=None: args,
    )

    schema = {
        "properties": {
            "items": {
                "type": ["array", "null"],
                "minItems": "bad",
                "maxItems": "bad",
                "items": {"type": "string"},
            },
            "large": {
                "type": "array",
                "minItems": 6,
                "maxItems": 7,
                "items": {"type": "string"},
            },
        },
    }
    tool = {"name": "demo", "inputSchema": schema}
    args = tool_strategy.fuzz_tool_arguments_aggressive(tool)
    assert len(args["items"]) == 0
    assert len(args["large"]) == 6
