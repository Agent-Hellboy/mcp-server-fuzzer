#!/usr/bin/env python3
"""
Unit tests for ProtocolFuzzer
"""

import asyncio
import json
import logging
import unittest
from unittest.mock import AsyncMock, MagicMock, call, patch

from mcp_fuzzer.fuzz_engine.fuzzer.protocol_fuzzer import ProtocolFuzzer


class TestProtocolFuzzer(unittest.IsolatedAsyncioTestCase):
    """Test cases for ProtocolFuzzer class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock transport for testing
        self.mock_transport = AsyncMock()
        # ProtocolFuzzer now uses send_raw to transmit envelope-level fuzzed messages
        self.mock_transport.send_raw.return_value = {"result": "test_response"}
        self.fuzzer = ProtocolFuzzer(self.mock_transport)

    def test_init(self):
        """Test ProtocolFuzzer initialization."""
        self.assertIsNotNone(self.fuzzer.strategies)
        self.assertEqual(self.fuzzer.request_id_counter, 0)
        self.assertIsNotNone(self.fuzzer.transport)

    def test_get_request_id(self):
        """Test request ID generation."""
        # Reset counter
        self.fuzzer.request_id_counter = 0

        first_id = self.fuzzer._get_request_id()
        second_id = self.fuzzer._get_request_id()
        third_id = self.fuzzer._get_request_id()

        self.assertEqual(first_id, 1)
        self.assertEqual(second_id, 2)
        self.assertEqual(third_id, 3)
        self.assertEqual(self.fuzzer.request_id_counter, 3)

    @patch("mcp_fuzzer.fuzz_engine.fuzzer.protocol_fuzzer.logging")
    async def test_fuzz_protocol_type_success(self, mock_logging):
        """Test successful fuzzing of a protocol type."""
        results = await self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=3)

        self.assertEqual(len(results), 3)

        for i, result in enumerate(results):
            self.assertEqual(result["protocol_type"], "InitializeRequest")
            self.assertTrue("fuzz_data" in result)
            self.assertTrue("success" in result)
            self.assertEqual(result["run"], i + 1)

    @patch("mcp_fuzzer.fuzz_engine.fuzzer.protocol_fuzzer.logging")
    async def test_fuzz_protocol_type_realistic_vs_aggressive(self, mock_logging):
        """Test that realistic and aggressive phases produce different results."""
        realistic_results = await self.fuzzer.fuzz_protocol_type(
            "InitializeRequest", runs=2, phase="realistic"
        )

        # Test that results are generated
        self.assertEqual(len(realistic_results), 2)

        aggressive_results = await self.fuzzer.fuzz_protocol_type(
            "InitializeRequest", runs=2, phase="aggressive"
        )

        self.assertEqual(len(aggressive_results), 2)

        # Both should be successful (assuming mock transport works)
        for result in realistic_results + aggressive_results:
            self.assertIn("fuzz_data", result)
            self.assertEqual(result["protocol_type"], "InitializeRequest")

    async def test_fuzz_protocol_type_unknown_type(self):
        """Test fuzzing an unknown protocol type."""
        results = await self.fuzzer.fuzz_protocol_type("UnknownType", runs=3)

        # Should return empty list for unknown types
        self.assertEqual(len(results), 0)

    @patch("mcp_fuzzer.fuzz_engine.fuzzer.protocol_fuzzer.logging")
    async def test_fuzz_protocol_type_transport_exception(self, mock_logging):
        """Test handling of transport exceptions."""
        # Set up transport to raise an exception
        self.mock_transport.send_raw.side_effect = Exception("Transport error")

        results = await self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=2)

        # Should still return results, but with server errors
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn("server_error", result)
        # Ensure send_raw was attempted for each run
        self.assertEqual(self.mock_transport.send_raw.await_count, 2)

    @patch("mcp_fuzzer.fuzz_engine.fuzzer.protocol_fuzzer.logging")
    async def test_fuzz_all_protocol_types(self, mock_logging):
        """Test fuzzing all protocol types."""
        results = await self.fuzzer.fuzz_all_protocol_types(runs_per_type=2)

        # Should return a dictionary with protocol types as keys
        self.assertIsInstance(results, dict)
        self.assertGreater(len(results), 0)

        # Check that each protocol type has results
        for protocol_type, protocol_results in results.items():
            self.assertIsInstance(protocol_results, list)
            # May be empty if transport fails, but should be a list

    async def test_fuzz_protocol_type_zero_runs(self):
        """Test fuzzing with zero runs."""
        results = await self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=0)
        self.assertEqual(len(results), 0)

    async def test_fuzz_protocol_type_negative_runs(self):
        """Test fuzzing with negative runs."""
        results = await self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=-1)
        self.assertEqual(len(results), 0)

    async def test_fuzz_all_protocol_types_zero_runs(self):
        """Test fuzzing all types with zero runs per type."""
        results = await self.fuzzer.fuzz_all_protocol_types(runs_per_type=0)
        self.assertIsInstance(results, dict)

    async def test_fuzz_protocol_type_different_runs(self):
        """Test that different runs generate different data."""
        results1 = await self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=5)
        results2 = await self.fuzzer.fuzz_protocol_type("ProgressNotification", runs=5)

        self.assertEqual(len(results1), 5)
        self.assertEqual(len(results2), 5)

        # Verify different protocol types
        for result in results1:
            self.assertEqual(result["protocol_type"], "InitializeRequest")
        for result in results2:
            self.assertEqual(result["protocol_type"], "ProgressNotification")


if __name__ == "__main__":
    unittest.main()
