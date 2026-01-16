#!/usr/bin/env python3
"""
Unit tests for exception classes.
"""

import unittest

from mcp_fuzzer.exceptions import (
    MCPError,
    TransportError,
    ErrorMetadata,
    get_error_registry,
)


class TestMCPError(unittest.TestCase):
    """Test cases for MCPError base class."""

    def test_to_metadata(self):
        """Test that to_metadata returns proper ErrorMetadata."""
        error = MCPError("Test error", context={"key": "value"})
        metadata = error.to_metadata()

        self.assertIsInstance(metadata, ErrorMetadata)
        self.assertEqual(metadata.code, "MCP-000")
        self.assertEqual(metadata.description, "Generic MCP error")
        self.assertEqual(metadata.message, "Test error")
        self.assertEqual(metadata.context, {"key": "value"})

    def test_to_metadata_with_custom_code(self):
        """Test to_metadata with custom error code."""
        error = TransportError("Transport failed", code="10001")
        metadata = error.to_metadata()

        self.assertEqual(metadata.code, "10001")
        self.assertEqual(metadata.description, "Transport failure")
        self.assertEqual(metadata.message, "Transport failed")

    def test_to_metadata_empty_context(self):
        """Test to_metadata with empty context."""
        error = MCPError("Test")
        metadata = error.to_metadata()

        self.assertEqual(metadata.context, {})


class TestErrorRegistry(unittest.TestCase):
    """Test cases for error registry."""

    def test_get_error_registry(self):
        """Test that get_error_registry returns all error codes."""
        registry = get_error_registry()

        self.assertIsInstance(registry, dict)
        self.assertIn("MCP-000", registry)
        self.assertIn("10001", registry)
        self.assertIn("10002", registry)
        # Check that registry is sorted
        codes = list(registry.keys())
        self.assertEqual(codes, sorted(codes))
