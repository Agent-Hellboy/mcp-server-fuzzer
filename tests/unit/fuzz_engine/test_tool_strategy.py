#!/usr/bin/env python3
"""
Unit tests for aggressive tool strategy helpers.
"""

import pytest

from mcp_fuzzer.fuzz_engine.mutators.strategies import schema_parser
from mcp_fuzzer.fuzz_engine.mutators.strategies.aggressive import tool_strategy as ts


def test_generate_aggressive_text_broken_uuid(monkeypatch):
    choices = iter(["broken_uuid", "not-a-uuid-at-all"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 5)

    result = ts.generate_aggressive_text()

    assert result == "not-a-uuid-at-all"


def test_generate_aggressive_text_special_chars(monkeypatch):
    choices = iter(["special_chars", "!", "!", "!"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 3)

    result = ts.generate_aggressive_text()

    assert result == "!!!"


def test_generate_aggressive_integer_boundary(monkeypatch):
    choices = iter(["boundary", -1])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))

    result = ts._generate_aggressive_integer()

    assert result == -1


def test_generate_aggressive_float_infinity(monkeypatch):
    choices = iter(["infinity", float("inf")])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))

    result = ts._generate_aggressive_float()

    assert result == float("inf")


def test_fuzz_tool_arguments_aggressive_fallback(monkeypatch):
    monkeypatch.setattr(
        schema_parser,
        "make_fuzz_strategy_from_jsonschema",
        lambda schema, phase=None: "not-a-dict",
    )
    monkeypatch.setattr(ts, "generate_aggressive_text", lambda *args, **kwargs: "text")
    monkeypatch.setattr(ts, "_generate_aggressive_integer", lambda *args, **kwargs: 7)
    monkeypatch.setattr(ts, "_generate_aggressive_float", lambda *args, **kwargs: 3.14)

    random_values = iter([0.1, 0.1] + [0.9] * 5)
    monkeypatch.setattr(ts.random, "random", lambda: next(random_values))

    tool = {
        "inputSchema": {
            "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
            "required": ["c"],
        }
    }

    args = ts.fuzz_tool_arguments_aggressive(tool)

    assert args["a"] == "text"
    assert args["b"] == 7
    assert args["c"] == "text"
    assert set(args.keys()).issubset({"a", "b", "c"})


def test_generate_aggressive_text_broken_base64(monkeypatch):
    """Test broken_base64 strategy."""
    choices = iter(["broken_base64", "InvalidBase64!@#$"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 5)

    result = ts.generate_aggressive_text()
    assert "InvalidBase64" in result or "Base64" in result


def test_generate_aggressive_text_broken_timestamp(monkeypatch):
    """Test broken_timestamp strategy."""
    choices = iter(["broken_timestamp", "not-a-timestamp"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 5)

    result = ts.generate_aggressive_text()
    assert result == "not-a-timestamp"


def test_generate_aggressive_text_unicode(monkeypatch):
    """Test unicode strategy."""
    choices = iter(["unicode", "漢", "字"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 2)

    result = ts.generate_aggressive_text()
    assert len(result) == 2


def test_generate_aggressive_text_null_bytes(monkeypatch):
    """Test null_bytes strategy."""
    choices = iter(["null_bytes", "\x00", "\x01"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 2)

    result = ts.generate_aggressive_text()
    assert len(result) == 2
    assert "\x00" in result or "\x01" in result


def test_generate_aggressive_text_escape_chars(monkeypatch):
    """Test escape_chars strategy."""
    choices = iter(["escape_chars", "\\", "n"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 2)

    result = ts.generate_aggressive_text()
    assert len(result) == 2


def test_generate_aggressive_text_html_entities(monkeypatch):
    """Test html_entities strategy."""
    choices = iter(["html_entities", "&lt;", "&gt;"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 2)

    result = ts.generate_aggressive_text()
    assert result == "&lt;&gt;"


def test_generate_aggressive_text_sql_injection(monkeypatch):
    """Test sql_injection strategy."""
    choices = iter(["sql_injection", "' OR '1'='1"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 5)

    result = ts.generate_aggressive_text()
    assert "' OR '1'='1" in result


def test_generate_aggressive_text_xss(monkeypatch):
    """Test xss strategy."""
    choices = iter(["xss", "<script>alert('xss')</script>"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 5)

    result = ts.generate_aggressive_text()
    assert "<script>" in result


def test_generate_aggressive_text_path_traversal(monkeypatch):
    """Test path_traversal strategy."""
    choices = iter(["path_traversal", "../../../etc/passwd"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 5)

    result = ts.generate_aggressive_text()
    assert "../" in result or "/etc/" in result


def test_generate_aggressive_text_overflow(monkeypatch):
    """Test overflow strategy."""
    choices = iter(["overflow", "A" * 1000])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 5)

    result = ts.generate_aggressive_text()
    assert len(result) >= 1000


def test_generate_aggressive_text_mixed(monkeypatch):
    """Test mixed strategy."""
    choices = iter(["mixed"] + list("abc123!@#"))
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 3)

    result = ts.generate_aggressive_text()
    assert len(result) == 3


def test_generate_aggressive_text_extreme(monkeypatch):
    """Test extreme strategy."""
    choices = iter(["extreme", ""])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 5)

    result = ts.generate_aggressive_text()
    # Extreme can return empty string or other extreme values
    assert isinstance(result, str)


def test_generate_aggressive_text_fallback(monkeypatch):
    """Test else branch (fallback)."""
    choices = iter(["unknown_strategy"] + list("abc"))
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 3)

    result = ts.generate_aggressive_text()
    assert len(result) == 3


def test_generate_aggressive_integer_normal(monkeypatch):
    """Test normal integer strategy."""
    choices = iter(["normal"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 42)

    result = ts._generate_aggressive_integer()
    assert result == 42


def test_generate_aggressive_integer_extreme(monkeypatch):
    """Test extreme integer strategy."""
    choices = iter(["extreme", -2147483648])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 0)

    result = ts._generate_aggressive_integer()
    assert result in [
        -2147483648,
        2147483647,
        -9223372036854775808,
        9223372036854775807,
        0,
        -1,
        1,
    ]


def test_generate_aggressive_integer_zero(monkeypatch):
    """Test zero integer strategy."""
    choices = iter(["zero"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))

    result = ts._generate_aggressive_integer()
    assert result == 0


def test_generate_aggressive_integer_negative(monkeypatch):
    """Test negative integer strategy."""
    choices = iter(["negative", -500])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: -500)

    result = ts._generate_aggressive_integer()
    assert result < 0


def test_generate_aggressive_integer_overflow(monkeypatch):
    """Test overflow integer strategy."""
    choices = iter(["overflow", 999999999])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 0)

    result = ts._generate_aggressive_integer()
    assert result in [999999999, -999999999, 2**31, -(2**31)]


def test_generate_aggressive_integer_special(monkeypatch):
    """Test special integer strategy."""
    choices = iter(["special", 42])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 0)

    result = ts._generate_aggressive_integer()
    assert result in [42, 69, 420, 1337, 8080, 65535]


def test_generate_aggressive_integer_fallback(monkeypatch):
    """Test integer else branch (fallback)."""
    choices = iter(["unknown", 100])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "randint", lambda a, b: 100)

    result = ts._generate_aggressive_integer()
    assert result == 100


def test_generate_aggressive_float_normal(monkeypatch):
    """Test normal float strategy."""
    choices = iter(["normal", 3.14])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "uniform", lambda a, b: 3.14)

    result = ts._generate_aggressive_float()
    assert isinstance(result, float)


def test_generate_aggressive_float_extreme(monkeypatch):
    """Test extreme float strategy."""
    choices = iter(["extreme", 0.0])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "uniform", lambda a, b: 0.0)

    result = ts._generate_aggressive_float()
    assert result in [0.0, -0.0, 1.0, -1.0, 3.14159, -3.14159]


def test_generate_aggressive_float_zero(monkeypatch):
    """Test zero float strategy."""
    choices = iter(["zero"])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))

    result = ts._generate_aggressive_float()
    assert result == 0.0


def test_generate_aggressive_float_negative(monkeypatch):
    """Test negative float strategy."""
    choices = iter(["negative", -500.0])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "uniform", lambda a, b: -500.0)

    result = ts._generate_aggressive_float()
    assert result < 0


def test_generate_aggressive_float_tiny(monkeypatch):
    """Test tiny float strategy."""
    choices = iter(["tiny", 1e-8])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "uniform", lambda a, b: 1e-8)

    result = ts._generate_aggressive_float()
    assert 1e-10 <= result <= 1e-5


def test_generate_aggressive_float_huge(monkeypatch):
    """Test huge float strategy."""
    choices = iter(["huge", 1e12])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "uniform", lambda a, b: 1e12)

    result = ts._generate_aggressive_float()
    assert 1e10 <= result <= 1e15


def test_generate_aggressive_float_fallback(monkeypatch):
    """Test float else branch (fallback)."""
    choices = iter(["unknown", 3.14])
    monkeypatch.setattr(ts.random, "choice", lambda seq: next(choices))
    monkeypatch.setattr(ts.random, "uniform", lambda a, b: 3.14)

    result = ts._generate_aggressive_float()
    assert isinstance(result, float)
