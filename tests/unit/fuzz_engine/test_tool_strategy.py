#!/usr/bin/env python3
"""
Unit tests for aggressive tool strategy helpers.
"""

from unittest.mock import patch

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
