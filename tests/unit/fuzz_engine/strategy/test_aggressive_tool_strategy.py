#!/usr/bin/env python3
"""
Tests for aggressive tool argument strategies.
"""

import re

from mcp_fuzzer.fuzz_engine.mutators.strategies import aggressive_tool_strategy as tool_strategy  # noqa: E501
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


# ---------------------------------------------------------------------------
# Additional tests (merged from test_aggressive_tool_strategy_more.py)
# ---------------------------------------------------------------------------


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


def test_generate_aggressive_integer_negative_in_range(monkeypatch):
    """The 'negative' strategy returns a random value in [min_value, -1] when
    that sub-range is valid (aggressive_tool_strategy:333)."""
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "overflow" in seq:
            return "negative"
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)
    value = tool_strategy._generate_aggressive_integer(min_value=-100, max_value=100)
    assert -100 <= value <= -1


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


# ---------------------------------------------------------------------------
# generate_aggressive_text branch coverage (folded from test_tool_strategy.py)
# ---------------------------------------------------------------------------


def test_generate_aggressive_text_broken_uuid(monkeypatch):
    _force_strategy(monkeypatch, "broken_uuid")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=100)
    assert value in ("not-a-uuid-at-all", "1234", "zzzz-zzzz-zzzz-zzzz")


def test_generate_aggressive_text_special_chars(monkeypatch):
    _force_strategy(monkeypatch, "special_chars")
    value = tool_strategy.generate_aggressive_text(min_size=3, max_size=3)
    assert len(value) == 3
    assert all(c in tool_strategy.SPECIAL_CHARS for c in value)


def test_generate_aggressive_text_broken_timestamp(monkeypatch):
    _force_strategy(monkeypatch, "broken_timestamp")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=100)
    assert value in ("not-a-timestamp", "2024-13-40T25:70:99Z")


def test_generate_aggressive_text_escape_chars(monkeypatch):
    _force_strategy(monkeypatch, "escape_chars")
    value = tool_strategy.generate_aggressive_text(min_size=2, max_size=2)
    assert len(value) == 2


def test_generate_aggressive_text_html_entities(monkeypatch):
    _force_strategy(monkeypatch, "html_entities")
    value = tool_strategy.generate_aggressive_text(min_size=2, max_size=100)
    # randint -> min (2); each pick -> HTML_ENTITIES[0] == "&lt;"
    assert value == "&lt;&lt;"


def test_generate_aggressive_text_sql_injection(monkeypatch):
    _force_strategy(monkeypatch, "sql_injection")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=100)
    assert value == tool_strategy.SQL_INJECTION[0]


def test_generate_aggressive_text_xss(monkeypatch):
    _force_strategy(monkeypatch, "xss")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=100)
    assert value == tool_strategy.XSS_PAYLOADS[0]


def test_generate_aggressive_text_path_traversal(monkeypatch):
    _force_strategy(monkeypatch, "path_traversal")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=100)
    assert value == tool_strategy.PATH_TRAVERSAL[0]


def test_generate_aggressive_text_mixed(monkeypatch):
    _force_strategy(monkeypatch, "mixed")
    value = tool_strategy.generate_aggressive_text(min_size=3, max_size=3)
    assert len(value) == 3


def test_generate_aggressive_text_extreme(monkeypatch):
    _force_strategy(monkeypatch, "extreme")
    value = tool_strategy.generate_aggressive_text(min_size=1, max_size=5)
    # Extreme can return empty string or other extreme values
    assert isinstance(value, str)


def test_generate_aggressive_text_unknown_fallback(monkeypatch):
    _force_strategy(monkeypatch, "unknown_strategy")
    value = tool_strategy.generate_aggressive_text(min_size=3, max_size=3)
    assert len(value) == 3


# ---------------------------------------------------------------------------
# _generate_aggressive_integer branch coverage (folded from test_tool_strategy.py)
# ---------------------------------------------------------------------------


def _force_int_strategy(monkeypatch, strategy: str) -> None:
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "special" in seq:
            return strategy
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)


def test_generate_aggressive_integer_extreme(monkeypatch):
    _force_int_strategy(monkeypatch, "extreme")
    value = tool_strategy._generate_aggressive_integer()
    assert value in [
        -2147483648,
        2147483647,
        -9223372036854775808,
        9223372036854775807,
        0,
        -1,
        1,
    ]


def test_generate_aggressive_integer_zero(monkeypatch):
    _force_int_strategy(monkeypatch, "zero")
    value = tool_strategy._generate_aggressive_integer()
    assert value == 0


def test_generate_aggressive_integer_special(monkeypatch):
    _force_int_strategy(monkeypatch, "special")
    value = tool_strategy._generate_aggressive_integer()
    assert value in [42, 69, 420, 1337, 8080, 65535]


def test_generate_aggressive_integer_normal_fallback(monkeypatch):
    _force_int_strategy(monkeypatch, "normal")
    monkeypatch.setattr(tool_strategy.random, "randint", lambda a, b: 100)
    value = tool_strategy._generate_aggressive_integer(min_value=0, max_value=1000)
    assert value == 100


# ---------------------------------------------------------------------------
# _generate_aggressive_float branch coverage (folded from test_tool_strategy.py)
# ---------------------------------------------------------------------------


def _force_float_strategy(monkeypatch, strategy: str) -> None:
    def choice(seq):
        if isinstance(seq, list) and "off_by_one" in seq and "infinity" in seq:
            return strategy
        return seq[0]

    monkeypatch.setattr(tool_strategy.random, "choice", choice)


def test_generate_aggressive_float_infinity(monkeypatch):
    _force_float_strategy(monkeypatch, "infinity")
    value = tool_strategy._generate_aggressive_float()
    assert value in (float("inf"), float("-inf"))


def test_generate_aggressive_float_extreme(monkeypatch):
    _force_float_strategy(monkeypatch, "extreme")
    value = tool_strategy._generate_aggressive_float()
    assert value in [0.0, -0.0, 1.0, -1.0, 3.14159, -3.14159]


def test_generate_aggressive_float_zero(monkeypatch):
    _force_float_strategy(monkeypatch, "zero")
    value = tool_strategy._generate_aggressive_float()
    assert value == 0.0


def test_generate_aggressive_float_tiny(monkeypatch):
    _force_float_strategy(monkeypatch, "tiny")
    monkeypatch.setattr(tool_strategy.random, "uniform", lambda a, b: 1e-8)
    value = tool_strategy._generate_aggressive_float()
    assert 1e-10 <= value <= 1e-5


def test_generate_aggressive_float_huge(monkeypatch):
    _force_float_strategy(monkeypatch, "huge")
    monkeypatch.setattr(tool_strategy.random, "uniform", lambda a, b: 1e12)
    value = tool_strategy._generate_aggressive_float()
    assert 1e10 <= value <= 1e15


def test_generate_aggressive_float_normal_fallback(monkeypatch):
    _force_float_strategy(monkeypatch, "normal")
    monkeypatch.setattr(tool_strategy.random, "uniform", lambda a, b: 3.14)
    value = tool_strategy._generate_aggressive_float()
    assert isinstance(value, float)


def test_fuzz_tool_arguments_aggressive_string_schema_fallback(monkeypatch):
    from mcp_fuzzer.fuzz_engine.mutators.strategies import schema_parser

    monkeypatch.setattr(
        schema_parser,
        "make_fuzz_strategy_from_jsonschema",
        lambda schema, phase=None: "not-a-dict",
    )
    monkeypatch.setattr(
        tool_strategy, "generate_aggressive_text", lambda *a, **k: "text"
    )
    monkeypatch.setattr(
        tool_strategy, "_generate_aggressive_integer", lambda *a, **k: 7
    )
    monkeypatch.setattr(
        tool_strategy, "_generate_aggressive_float", lambda *a, **k: 3.14
    )

    random_values = iter([0.1, 0.1] + [0.9] * 5)
    monkeypatch.setattr(tool_strategy.random, "random", lambda: next(random_values))

    tool = {
        "inputSchema": {
            "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
            "required": ["c"],
        }
    }

    args = tool_strategy.fuzz_tool_arguments_aggressive(tool)

    assert args["a"] == "text"
    assert args["b"] == 7
    assert args["c"] == "text"
    assert set(args.keys()).issubset({"a", "b", "c"})
