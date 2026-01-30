#!/usr/bin/env python3
"""
Unit tests for phase distinction between REALISTIC and AGGRESSIVE fuzzing.

These tests verify that:
- REALISTIC phase generates schema-valid values
- AGGRESSIVE phase generates attack payloads and violations
"""

import random
import pytest
from jsonschema import validate

from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser import (
    make_fuzz_strategy_from_jsonschema,
)


class TestRealisticPhaseSchemaValidity:
    """Tests that REALISTIC phase always generates schema-valid values."""

    def test_realistic_string_respects_min_length(self):
        """REALISTIC should respect minLength constraint."""
        schema = {"type": "string", "minLength": 5}
        for _ in range(10):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            assert len(result) >= 5, f"Got {result!r} with length {len(result)}"

    def test_realistic_string_respects_max_length(self):
        """REALISTIC should respect maxLength constraint."""
        schema = {"type": "string", "maxLength": 10}
        for _ in range(10):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            assert len(result) <= 10, f"Got {result!r} with length {len(result)}"

    def test_realistic_integer_respects_minimum(self):
        """REALISTIC should respect minimum constraint."""
        schema = {"type": "integer", "minimum": 10}
        for _ in range(10):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            assert result >= 10, f"Got {result}"

    def test_realistic_integer_respects_maximum(self):
        """REALISTIC should respect maximum constraint."""
        schema = {"type": "integer", "maximum": 100}
        for _ in range(10):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            assert result <= 100, f"Got {result}"

    def test_realistic_enum_returns_valid_value(self):
        """REALISTIC should return a value from enum list."""
        schema = {"type": "string", "enum": ["alpha", "beta", "gamma"]}
        for _ in range(10):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            assert result in ["alpha", "beta", "gamma"], f"Got {result!r}"

    def test_realistic_number_respects_range(self):
        """REALISTIC should respect min/max for numbers."""
        schema = {"type": "number", "minimum": 0.0, "maximum": 1.0}
        for _ in range(10):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            assert 0.0 <= result <= 1.0, f"Got {result}"

    def test_realistic_object_validates(self):
        """REALISTIC should generate valid objects."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 20},
                "age": {"type": "integer", "minimum": 0, "maximum": 150},
            },
            "required": ["name"],
        }
        for _ in range(5):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            # Should not raise ValidationError
            validate(instance=result, schema=schema)

    def test_realistic_array_respects_min_items(self):
        """REALISTIC should respect minItems constraint."""
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 2}
        for _ in range(5):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            assert len(result) >= 2, f"Got {len(result)} items"


class TestAggressivePhaseAttackPayloads:
    """Tests that AGGRESSIVE phase generates attack payloads."""

    def setup_method(self):
        random.seed(0)

    def test_aggressive_string_may_contain_sql_injection(self):
        """AGGRESSIVE might generate SQL injection payloads."""
        schema = {"type": "string", "maxLength": 100}
        results = [
            make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            for _ in range(100)
        ]
        # At least one should contain SQL-like patterns
        sql_patterns = ["'", "OR", "--", "SELECT", "DROP"]
        has_sql = any(
            any(p in r for p in sql_patterns)
            for r in results
        )
        assert has_sql, "No SQL injection patterns found"

    def test_aggressive_string_may_contain_xss(self):
        """AGGRESSIVE might generate XSS payloads."""
        schema = {"type": "string", "maxLength": 100}
        results = [
            make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            for _ in range(100)
        ]
        # At least one should contain XSS-like patterns
        xss_patterns = ["<script>", "javascript:", "onerror", "<img"]
        has_xss = any(
            any(p in r for p in xss_patterns)
            for r in results
        )
        assert has_xss, "No XSS patterns found"

    def test_aggressive_integer_may_violate_maximum(self):
        """AGGRESSIVE might generate off-by-one violations."""
        schema = {"type": "integer", "maximum": 100}
        results = [
            make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            for _ in range(100)
        ]
        # At least one should exceed the maximum
        has_violation = any(r > 100 for r in results)
        assert has_violation, f"No maximum violations found, got {results}"

    def test_aggressive_integer_may_use_overflow_values(self):
        """AGGRESSIVE might generate integer overflow values."""
        schema = {"type": "integer"}
        results = [
            make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            for _ in range(100)
        ]
        # At least one should be a large/overflow value
        large_values = [r for r in results if abs(r) > 2**30]
        assert len(large_values) > 0, "No overflow values found"


class TestPhaseDifference:
    """Tests that REALISTIC and AGGRESSIVE phases produce different outputs."""

    def test_phases_produce_different_strings(self):
        """Different phases should produce distinguishable string outputs."""
        schema = {"type": "string", "maxLength": 50}

        realistic = [
            make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            for _ in range(10)
        ]
        aggressive = [
            make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            for _ in range(10)
        ]

        # REALISTIC should be more "normal"
        realistic_special = sum(
            1 for r in realistic
            if any(c in r for c in ["'", "<", ">", ";", "--"])
        )
        aggressive_special = sum(
            1 for a in aggressive
            if any(c in a for c in ["'", "<", ">", ";", "--"])
        )

        # AGGRESSIVE should have more special characters
        assert aggressive_special >= realistic_special, (
            f"AGGRESSIVE ({aggressive_special}) should have >= special chars "
            f"than REALISTIC ({realistic_special})"
        )

    def test_phases_produce_different_integers(self):
        """Different phases should produce distinguishable integer outputs."""
        schema = {"type": "integer", "minimum": 0, "maximum": 100}

        realistic = [
            make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            for _ in range(20)
        ]
        aggressive = [
            make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            for _ in range(20)
        ]

        # All REALISTIC should be in range
        realistic_in_range = all(0 <= r <= 100 for r in realistic)
        assert realistic_in_range, f"REALISTIC violated range: {realistic}"

        # Some AGGRESSIVE should violate range
        aggressive_violations = sum(1 for a in aggressive if a < 0 or a > 100)
        assert aggressive_violations > 0, "AGGRESSIVE should violate range"


class TestNoGarbageValues:
    """Tests that extreme garbage values are no longer generated."""

    def test_no_extremely_long_strings(self):
        """Should not generate strings over 1000 chars."""
        schema = {"type": "string"}
        for _ in range(20):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            assert len(result) <= 1000, f"Got string of length {len(result)}"

    def test_no_a_times_256_garbage(self):
        """Should not generate 'A' * 256 style garbage."""
        schema = {"type": "string", "maxLength": 50}
        for _ in range(20):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
            # Should not be just repeated 'A's
            if len(result) > 10:
                unique_chars = len(set(result))
                assert unique_chars > 1, f"Got garbage string: {result!r}"

    def test_realistic_does_not_use_extreme_fallbacks(self):
        """REALISTIC should not use -2^63 or similar extreme values."""
        schema = {"type": "integer"}
        for _ in range(20):
            result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
            # Should not be extreme values
            assert abs(result) < 2**62, f"Got extreme value: {result}"
