#!/usr/bin/env python3
"""
Unit tests for interesting_values.py

Tests the curated values used for smart fuzzing.
"""

import pytest

from mcp_fuzzer.fuzz_engine.mutators.strategies.interesting_values import (
    BOUNDARY_INTS_SMALL,
    BOUNDARY_INTS_MEDIUM,
    BOUNDARY_STRINGS,
    SQL_INJECTION,
    XSS_PAYLOADS,
    PATH_TRAVERSAL,
    UNICODE_TRICKS,
    TYPE_CONFUSION,
    get_boundary_values_for_range,
    get_payload_within_length,
    inject_unicode_trick,
    get_off_by_one_string,
    get_off_by_one_int,
    get_realistic_boundary_string,
    get_realistic_boundary_int,
    cycle_enum_values,
)


class TestBoundaryValues:
    """Tests for boundary value constants."""

    def test_boundary_ints_small_contains_zero_crossing(self):
        """Boundary ints should include 0, 1, -1."""
        assert 0 in BOUNDARY_INTS_SMALL
        assert 1 in BOUNDARY_INTS_SMALL
        assert -1 in BOUNDARY_INTS_SMALL

    def test_boundary_ints_medium_contains_common_limits(self):
        """Boundary ints should include common integer limits."""
        assert 127 in BOUNDARY_INTS_MEDIUM
        assert 128 in BOUNDARY_INTS_MEDIUM
        assert 255 in BOUNDARY_INTS_MEDIUM
        assert 256 in BOUNDARY_INTS_MEDIUM

    def test_boundary_strings_contains_empty(self):
        """Boundary strings should include empty string."""
        assert "" in BOUNDARY_STRINGS

    def test_boundary_strings_contains_single_char(self):
        """Boundary strings should include single character."""
        assert any(len(s) == 1 for s in BOUNDARY_STRINGS)


class TestAttackPayloads:
    """Tests for attack payload constants."""

    def test_sql_injection_payloads_not_empty(self):
        """SQL injection list should not be empty."""
        assert len(SQL_INJECTION) > 0

    def test_sql_injection_contains_common_patterns(self):
        """SQL injection should contain common patterns."""
        payloads_str = " ".join(SQL_INJECTION)
        assert "OR" in payloads_str
        assert "'" in payloads_str

    def test_xss_payloads_not_empty(self):
        """XSS payloads list should not be empty."""
        assert len(XSS_PAYLOADS) > 0

    def test_xss_contains_script_tag(self):
        """XSS payloads should contain script tag."""
        assert any("<script>" in p for p in XSS_PAYLOADS)

    def test_path_traversal_contains_dot_dot(self):
        """Path traversal should contain .. patterns."""
        assert any(".." in p for p in PATH_TRAVERSAL)

    def test_unicode_tricks_contains_null_byte(self):
        """Unicode tricks should contain null byte."""
        assert "\x00" in UNICODE_TRICKS

    def test_type_confusion_contains_numeric_string(self):
        """Type confusion should contain numeric strings."""
        assert "123" in TYPE_CONFUSION


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_boundary_values_for_range_basic(self):
        """Should return boundary values within range."""
        values = get_boundary_values_for_range(0, 100)
        assert 0 in values
        assert 100 in values
        assert 50 in values  # midpoint

    def test_get_boundary_values_for_range_filters_out_of_range(self):
        """Should filter out values outside range."""
        values = get_boundary_values_for_range(10, 20)
        assert all(10 <= v <= 20 for v in values)

    def test_get_payload_within_length_respects_max(self):
        """Payload should fit within max length."""
        payload = get_payload_within_length(10, "sql")
        assert len(payload) <= 10

    def test_get_payload_within_length_returns_sql(self):
        """Should return SQL injection payload."""
        payload = get_payload_within_length(100, "sql")
        assert payload in SQL_INJECTION

    def test_inject_unicode_trick_embeds_trick(self):
        """Should embed unicode trick in value."""
        result = inject_unicode_trick("test", None)
        # Should be longer than original due to embedded trick
        assert len(result) >= 4

    def test_inject_unicode_trick_respects_max_length(self):
        """Should respect max length constraint."""
        result = inject_unicode_trick("verylongvalue", 5)
        assert len(result) <= 5

    def test_get_off_by_one_string_exceeds_limit(self):
        """Should return string one char over limit."""
        result = get_off_by_one_string(10)
        assert len(result) == 11

    def test_get_off_by_one_int_exceeds_maximum(self):
        """Should return integer one over maximum."""
        result = get_off_by_one_int(maximum=100)
        assert result == 101

    def test_get_off_by_one_int_below_minimum(self):
        """Should return integer one below minimum."""
        result = get_off_by_one_int(minimum=10)
        assert result == 9


class TestRealisticBoundaryGeneration:
    """Tests for realistic boundary value generation."""

    def test_get_realistic_boundary_string_respects_constraints(self):
        """Should generate string within length constraints."""
        result = get_realistic_boundary_string(5, 20)
        assert 5 <= len(result) <= 20

    def test_get_realistic_boundary_string_cycles(self):
        """Should cycle through different lengths."""
        results = [get_realistic_boundary_string(0, 10, i) for i in range(5)]
        lengths = [len(r) for r in results]
        # Should have variety
        assert len(set(lengths)) > 1

    def test_get_realistic_boundary_int_respects_constraints(self):
        """Should generate integer within range."""
        result = get_realistic_boundary_int(0, 100)
        assert 0 <= result <= 100

    def test_get_realistic_boundary_int_cycles(self):
        """Should cycle through boundary values."""
        results = [get_realistic_boundary_int(0, 100, i) for i in range(5)]
        # Should have variety
        assert len(set(results)) > 1


class TestEnumCycling:
    """Tests for enum value cycling."""

    def test_cycle_enum_values_returns_from_list(self):
        """Should return value from enum list."""
        result = cycle_enum_values(["a", "b", "c"], 0)
        assert result in ["a", "b", "c"]

    def test_cycle_enum_values_cycles_through_all(self):
        """Should cycle through all values."""
        enum_values = ["a", "b", "c"]
        results = [cycle_enum_values(enum_values, i) for i in range(6)]
        # Should hit each value at least twice
        assert results.count("a") == 2
        assert results.count("b") == 2
        assert results.count("c") == 2

    def test_cycle_enum_values_handles_empty(self):
        """Should handle empty enum list."""
        result = cycle_enum_values([], 0)
        assert result is None
