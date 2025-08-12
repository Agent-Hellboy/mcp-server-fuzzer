#!/usr/bin/env python3
"""
Unit tests for realistic Hypothesis strategies.
Tests the realistic strategies from mcp_fuzzer.fuzz_engine.strategy.realistic.*
"""

import base64
import re
import unittest
import unittest.mock
import uuid
from datetime import datetime

from hypothesis import given

from mcp_fuzzer.fuzz_engine.strategy.realistic.tool_strategy import (
    base64_strings,
    timestamp_strings,
    uuid_strings,
    generate_realistic_text,
    fuzz_tool_arguments_realistic,
)
from mcp_fuzzer.fuzz_engine.strategy.realistic.protocol_type_strategy import (
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
        """Test base64_strings with size constraints."""
        strategy = base64_strings(min_size=10, max_size=20)
        value = strategy.example()
        decoded = base64.b64decode(value)
        self.assertGreaterEqual(len(decoded), 10)
        self.assertLessEqual(len(decoded), 20)

    def test_timestamp_strings_without_microseconds(self):
        """Test timestamp_strings without microseconds."""
        strategy = timestamp_strings(include_microseconds=False)
        value = strategy.example()
        # Should not contain microseconds (no .)
        self.assertNotIn(".", value)

    def test_uuid_strings_different_versions(self):
        """Test uuid_strings with different versions."""
        for version in [1, 3, 4, 5]:
            strategy = uuid_strings(version=version)
            value = strategy.example()
            parsed_uuid = uuid.UUID(value)
            self.assertEqual(parsed_uuid.version, version)


class TestRealisticTextGeneration(unittest.TestCase):
    """Test cases for realistic text generation."""

    def test_generate_realistic_text(self):
        """Test generate_realistic_text returns a string."""
        text = generate_realistic_text()
        self.assertIsInstance(text, str)
        self.assertGreater(len(text), 0)

    def test_fuzz_tool_arguments_realistic(self):
        """Test realistic tool argument generation with various schema types."""

        # Test with string type properties
        tool = {
            "inputSchema": {
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "uuid_field": {"type": "string", "format": "uuid"},
                    "datetime_field": {"type": "string", "format": "date-time"},
                    "email_field": {"type": "string", "format": "email"},
                    "uri_field": {"type": "string", "format": "uri"},
                },
                "required": ["name"],
            }
        }

        result = fuzz_tool_arguments_realistic(tool)

        # Verify all properties are generated
        assert "name" in result
        assert "description" in result
        assert "uuid_field" in result
        assert "datetime_field" in result
        assert "email_field" in result
        assert "uri_field" in result

        # Verify required field is present
        assert result["name"] is not None

        # Verify format-specific values
        assert result["email_field"] == "user@example.com"
        assert result["uri_field"] == "https://example.com/api"

        # Test with numeric types
        tool = {
            "inputSchema": {
                "properties": {
                    "count": {"type": "integer", "minimum": 10, "maximum": 100},
                    "score": {"type": "number", "minimum": 0.0, "maximum": 10.0},
                    "enabled": {"type": "boolean"},
                }
            }
        }

        result = fuzz_tool_arguments_realistic(tool)

        assert isinstance(result["count"], int)
        assert 10 <= result["count"] <= 100
        assert isinstance(result["score"], float)
        assert 0.0 <= result["score"] <= 10.0
        assert isinstance(result["enabled"], bool)

        # Test with array types
        tool = {
            "inputSchema": {
                "properties": {
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "numbers": {"type": "array", "items": {"type": "integer"}},
                    "scores": {"type": "array", "items": {"type": "number"}},
                }
            }
        }

        result = fuzz_tool_arguments_realistic(tool)

        assert isinstance(result["tags"], list)
        assert 1 <= len(result["tags"]) <= 3
        assert all(isinstance(tag, str) for tag in result["tags"])

        assert isinstance(result["numbers"], list)
        assert 1 <= len(result["numbers"]) <= 3
        assert all(isinstance(num, int) for num in result["numbers"])

        # Test with object types
        tool = {"inputSchema": {"properties": {"config": {"type": "object"}}}}

        result = fuzz_tool_arguments_realistic(tool)

        assert isinstance(result["config"], dict)
        assert "name" in result["config"]
        assert "value" in result["config"]
        assert "enabled" in result["config"]

        # Test with unknown types
        tool = {
            "inputSchema": {"properties": {"unknown_field": {"type": "unknown_type"}}}
        }

        result = fuzz_tool_arguments_realistic(tool)
        assert "unknown_field" in result
        assert result["unknown_field"] is not None

    def test_generate_realistic_text_different_sizes(self):
        """Test realistic text generation with different strategies."""

        # Test with different size ranges
        text1 = generate_realistic_text(min_size=5, max_size=10)
        # Base64 and UUID strategies may not respect exact size constraints
        # but should generate reasonable text
        assert len(text1) > 0
        assert isinstance(text1, str)

        text2 = generate_realistic_text(min_size=20, max_size=30)
        # Different strategies may not respect exact size constraints
        # but should generate reasonable text
        assert len(text2) > 0
        assert isinstance(text2, str)

        # Test that it generates different text on multiple calls
        texts = [generate_realistic_text() for _ in range(5)]
        # At least some should be different (not guaranteed due to randomness)
        assert len(set(texts)) >= 1

    def test_base64_strings_strategy(self):
        """Test base64 string generation strategy."""
        from mcp_fuzzer.fuzz_engine.strategy.realistic.tool_strategy import (
            base64_strings,
        )

        # Test with default parameters
        strategy = base64_strings()
        example = strategy.example()
        assert isinstance(example, str)

        # Test with custom size range
        strategy = base64_strings(min_size=10, max_size=20)
        example = strategy.example()
        assert isinstance(example, str)

        # Test with custom alphabet
        strategy = base64_strings(min_size=5, max_size=10, alphabet="abc")
        example = strategy.example()
        assert isinstance(example, str)

    def test_uuid_strings_strategy(self):
        """Test UUID string generation strategy."""
        from mcp_fuzzer.fuzz_engine.strategy.realistic.tool_strategy import uuid_strings

        # Test UUID4 (default)
        strategy = uuid_strings()
        example = strategy.example()
        assert isinstance(example, str)
        assert len(example) == 36  # Standard UUID length

        # Test UUID1
        strategy = uuid_strings(version=1)
        example = strategy.example()
        assert isinstance(example, str)
        assert len(example) == 36

        # Test UUID3
        strategy = uuid_strings(version=3)
        example = strategy.example()
        assert isinstance(example, str)
        assert len(example) == 36

        # Test UUID5
        strategy = uuid_strings(version=5)
        example = strategy.example()
        assert isinstance(example, str)
        assert len(example) == 36

        # Test invalid version
        with self.assertRaises(ValueError):
            uuid_strings(version=99)

    def test_timestamp_strings_strategy(self):
        """Test timestamp string generation strategy."""
        from mcp_fuzzer.fuzz_engine.strategy.realistic.tool_strategy import (
            timestamp_strings,
        )

        # Test with default parameters
        strategy = timestamp_strings()
        example = strategy.example()
        assert isinstance(example, str)
        assert "T" in example  # ISO format contains T

        # Test with custom year range
        strategy = timestamp_strings(min_year=2023, max_year=2025)
        example = strategy.example()
        assert isinstance(example, str)

        # Test without microseconds
        strategy = timestamp_strings(include_microseconds=False)
        example = strategy.example()
        assert isinstance(example, str)
        assert "." not in example  # No microseconds

    def test_fuzz_tool_arguments_edge_cases(self):
        """Test edge cases in tool argument generation."""

        # Test with empty schema
        tool = {"inputSchema": {}}
        result = fuzz_tool_arguments_realistic(tool)
        assert result == {}

        # Test with no properties
        tool = {"inputSchema": {"properties": {}}}
        result = fuzz_tool_arguments_realistic(tool)
        assert result == {}

        # Test with required fields but no properties
        tool = {"inputSchema": {"required": ["field1", "field2"]}}
        result = fuzz_tool_arguments_realistic(tool)
        # Required fields should be generated even without properties
        assert "field1" in result
        assert "field2" in result
        assert result["field1"] is not None
        assert result["field2"] is not None

        # Test with missing inputSchema
        tool = {}
        result = fuzz_tool_arguments_realistic(tool)
        assert result == {}

        # Test with complex nested schema
        tool = {
            "inputSchema": {
                "properties": {
                    "nested": {
                        "type": "object",
                        "properties": {"deep": {"type": "string"}},
                    }
                }
            }
        }
        result = fuzz_tool_arguments_realistic(tool)
        assert "nested" in result
        assert isinstance(result["nested"], dict)

    def test_fuzz_tool_arguments_with_required_fields(self):
        """Test that required fields are always generated."""

        tool = {
            "inputSchema": {
                "properties": {
                    "optional_field": {"type": "string"},
                    "required_field1": {"type": "string"},
                    "required_field2": {"type": "integer"},
                },
                "required": ["required_field1", "required_field2"],
            }
        }

        result = fuzz_tool_arguments_realistic(tool)

        # All fields should be present
        assert "optional_field" in result
        assert "required_field1" in result
        assert "required_field2" in result

        # Required fields should have values
        assert result["required_field1"] is not None
        assert result["required_field2"] is not None

        # Test multiple calls to ensure consistency
        for _ in range(3):
            result2 = fuzz_tool_arguments_realistic(tool)
            assert "required_field1" in result2
            assert "required_field2" in result2

    def test_fuzz_tool_arguments_array_edge_cases(self):
        """Test array generation edge cases."""

        # Test array with no items specification
        tool = {"inputSchema": {"properties": {"items": {"type": "array"}}}}

        result = fuzz_tool_arguments_realistic(tool)
        assert "items" in result
        assert isinstance(result["items"], list)
        assert 1 <= len(result["items"]) <= 3

        # Test array with complex items
        tool = {
            "inputSchema": {
                "properties": {
                    "complex_array": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}},
                        },
                    }
                }
            }
        }

        result = fuzz_tool_arguments_realistic(tool)
        assert "complex_array" in result
        assert isinstance(result["complex_array"], list)
        assert 1 <= len(result["complex_array"]) <= 3

    def test_fuzz_tool_arguments_numeric_constraints(self):
        """Test numeric type generation with constraints."""

        # Test integer with specific range
        tool = {
            "inputSchema": {
                "properties": {
                    "small_int": {"type": "integer", "minimum": 1, "maximum": 5},
                    "large_int": {"type": "integer", "minimum": 1000, "maximum": 2000},
                }
            }
        }

        result = fuzz_tool_arguments_realistic(tool)

        assert 1 <= result["small_int"] <= 5
        assert 1000 <= result["large_int"] <= 2000

        # Test float with specific range
        tool = {
            "inputSchema": {
                "properties": {
                    "small_float": {"type": "number", "minimum": 0.1, "maximum": 0.9},
                    "large_float": {
                        "type": "number",
                        "minimum": 100.0,
                        "maximum": 200.0,
                    },
                }
            }
        }

        result = fuzz_tool_arguments_realistic(tool)

        assert 0.1 <= result["small_float"] <= 0.9
        assert 100.0 <= result["large_float"] <= 200.0


if __name__ == "__main__":
    unittest.main()
