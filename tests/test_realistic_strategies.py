#!/usr/bin/env python3
"""
Unit tests for realistic Hypothesis strategies.
Tests the realistic strategies from mcp_fuzzer.strategy.realistic.*
"""

import base64
import re
import unittest
import uuid
from datetime import datetime

from hypothesis import given

from mcp_fuzzer.strategy.realistic.tool_strategy import (
    base64_strings,
    timestamp_strings,
    uuid_strings,
)
from mcp_fuzzer.strategy.realistic.protocol_type_strategy import (
    json_rpc_id_values,
    method_names,
    protocol_version_strings,
)


class TestRealisticStrategies(unittest.TestCase):
    """Test cases for realistic Hypothesis strategies."""

    @given(base64_strings())
    def test_base64_strings_valid(self, value):
        """Test that base64_strings generates valid Base64 strings."""
        self.assertIsInstance(value, str)
        # Should be valid Base64
        try:
            decoded = base64.b64decode(value)
            # Re-encoding should give the same result
            reencoded = base64.b64encode(decoded).decode("ascii")
            self.assertEqual(value, reencoded)
        except Exception as e:
            self.fail(f"Invalid Base64 string generated: {value}, error: {e}")

    @given(uuid_strings())
    def test_uuid_strings_valid(self, value):
        """Test that uuid_strings generates valid UUID strings."""
        self.assertIsInstance(value, str)
        # Should be valid UUID format
        try:
            parsed_uuid = uuid.UUID(value)
            self.assertEqual(str(parsed_uuid), value)
        except ValueError as e:
            self.fail(f"Invalid UUID string generated: {value}, error: {e}")

    @given(uuid_strings(version=1))
    def test_uuid_strings_version1(self, value):
        """Test UUID version 1 generation."""
        parsed_uuid = uuid.UUID(value)
        self.assertEqual(parsed_uuid.version, 1)

    @given(uuid_strings(version=4))
    def test_uuid_strings_version4(self, value):
        """Test UUID version 4 generation."""
        parsed_uuid = uuid.UUID(value)
        self.assertEqual(parsed_uuid.version, 4)

    @given(timestamp_strings())
    def test_timestamp_strings_valid(self, value):
        """Test that timestamp_strings generates valid ISO-8601 timestamps."""
        self.assertIsInstance(value, str)
        # Should be valid ISO-8601 format
        try:
            parsed_dt = datetime.fromisoformat(value)
            self.assertIsInstance(parsed_dt, datetime)
            # Should have timezone info
            self.assertIsNotNone(parsed_dt.tzinfo)
        except ValueError as e:
            self.fail(f"Invalid timestamp string generated: {value}, error: {e}")

    @given(timestamp_strings(min_year=2024, max_year=2024))
    def test_timestamp_strings_year_range(self, value):
        """Test timestamp year range constraint."""
        parsed_dt = datetime.fromisoformat(value)
        self.assertEqual(parsed_dt.year, 2024)

    @given(protocol_version_strings())
    def test_protocol_version_strings_format(self, value):
        """Test that protocol_version_strings generates valid formats."""
        self.assertIsInstance(value, str)
        # Should match either date format (YYYY-MM-DD) or semantic version
        date_pattern = r"^\d{4}-\d{2}-\d{2}$"
        semver_pattern = r"^\d+\.\d+\.\d+$"

        self.assertTrue(
            re.match(date_pattern, value) or re.match(semver_pattern, value),
            f"Version string '{value}' doesn't match expected patterns",
        )

    @given(json_rpc_id_values())
    def test_json_rpc_id_values_types(self, value):
        """Test that json_rpc_id_values generates valid types."""
        # Should be None, string, int, or float
        self.assertIn(
            type(value),
            [type(None), str, int, float],
            f"Invalid JSON-RPC ID type: {type(value)}",
        )

    @given(method_names())
    def test_method_names_format(self, value):
        """Test that method_names generates reasonable method names."""
        self.assertIsInstance(value, str)
        self.assertGreater(len(value), 0)
        # Should not start with whitespace or special characters (except letters)
        if not any(
            value.startswith(prefix)
            for prefix in [
                "initialize",
                "tools/",
                "resources/",
                "prompts/",
                "notifications/",
                "completion/",
                "sampling/",
            ]
        ):
            self.assertTrue(
                value[0].isalpha(), f"Method name should start with letter: {value}"
            )


class TestCustomStrategiesIntegration(unittest.TestCase):
    """Integration tests for custom strategies."""

    def test_base64_strings_with_size_constraints(self):
        """Test base64 strategy with size constraints."""
        strategy = base64_strings(min_size=5, max_size=10)
        for _ in range(10):
            value = strategy.example()
            decoded = base64.b64decode(value)
            self.assertGreaterEqual(len(decoded), 5)
            self.assertLessEqual(len(decoded), 10)

    def test_timestamp_strings_without_microseconds(self):
        """Test timestamp strategy without microseconds."""
        strategy = timestamp_strings(include_microseconds=False)
        for _ in range(10):
            value = strategy.example()
            # Should not contain microseconds (no decimal point)
            self.assertNotIn(".", value.split("+")[0])

    def test_uuid_strings_different_versions(self):
        """Test different UUID versions."""
        for version in [1, 3, 4, 5]:
            strategy = uuid_strings(version=version)
            value = strategy.example()
            parsed_uuid = uuid.UUID(value)
            if version in [1, 4]:  # 3 and 5 might have different version bytes
                self.assertEqual(parsed_uuid.version, version)


if __name__ == "__main__":
    unittest.main()
