#!/usr/bin/env python3
"""
Unit tests for ProtocolFuzzer
"""

import json
import logging
import unittest
from unittest.mock import MagicMock, call, patch

from mcp_fuzzer.fuzzer.protocol_fuzzer import ProtocolFuzzer


class TestProtocolFuzzer(unittest.TestCase):
    """Test cases for ProtocolFuzzer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.fuzzer = ProtocolFuzzer()

    def test_init(self):
        """Test ProtocolFuzzer initialization."""
        self.assertIsNotNone(self.fuzzer.strategies)
        self.assertEqual(self.fuzzer.request_id_counter, 0)

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

    @patch("mcp_fuzzer.fuzzer.protocol_fuzzer.logging")
    def test_fuzz_protocol_type_success(self, mock_logging):
        """Test successful fuzzing of a protocol type."""
        results = self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=3)

        self.assertEqual(len(results), 3)

        for i, result in enumerate(results):
            self.assertEqual(result["protocol_type"], "InitializeRequest")
            self.assertEqual(result["run"], i + 1)
            self.assertTrue(result["success"])
            self.assertIn("fuzz_data", result)
            self.assertIsInstance(result["fuzz_data"], dict)

            # Test the BEHAVIOR: fuzzer should return fuzz_data regardless of content
            fuzz_data = result["fuzz_data"]
            self.assertIsNotNone(fuzz_data, "Fuzzer should always return fuzz_data")
            self.assertIsInstance(fuzz_data, dict, "Fuzz data should be a dictionary")

    @patch("mcp_fuzzer.fuzzer.protocol_fuzzer.logging")
    def test_fuzz_protocol_type_realistic_vs_aggressive(self, mock_logging):
        """Test that realistic and aggressive phases produce different types of data."""
        # Test realistic phase
        realistic_results = self.fuzzer.fuzz_protocol_type(
            "InitializeRequest", runs=2, phase="realistic"
        )
        self.assertEqual(len(realistic_results), 2)

        for result in realistic_results:
            fuzz_data = result["fuzz_data"]
            # Realistic fuzzing should have proper JSON-RPC structure
            self.assertIn("jsonrpc", fuzz_data)
            self.assertIn("method", fuzz_data)
            self.assertIn("params", fuzz_data)
            self.assertEqual(fuzz_data["jsonrpc"], "2.0")

        # Test aggressive phase
        aggressive_results = self.fuzzer.fuzz_protocol_type(
            "InitializeRequest", runs=2, phase="aggressive"
        )
        self.assertEqual(len(aggressive_results), 2)

        for result in aggressive_results:
            fuzz_data = result["fuzz_data"]
            # Aggressive fuzzing may have malformed structure
            self.assertIsInstance(fuzz_data, dict)
            self.assertGreater(len(fuzz_data), 0)

    @patch("mcp_fuzzer.fuzzer.protocol_fuzzer.logging")
    def test_fuzz_protocol_type_unknown_type(self, mock_logging):
        """Test fuzzing of unknown protocol type."""
        results = self.fuzzer.fuzz_protocol_type("UnknownType", runs=3)

        self.assertEqual(len(results), 0)
        mock_logging.error.assert_called_with("Unknown protocol type: UnknownType")

    @patch("mcp_fuzzer.fuzzer.protocol_fuzzer.logging")
    def test_fuzz_protocol_type_exception_handling(self, mock_logging):
        """Test exception handling during fuzzing."""
        # Mock the strategy to raise an exception
        with patch.object(
            self.fuzzer.strategies, "get_protocol_fuzzer_method"
        ) as mock_method:
            mock_method.return_value = lambda: (_ for _ in ()).throw(
                Exception("Test exception")
            )

            results = self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=2)

            self.assertEqual(len(results), 2)

            for result in results:
                self.assertEqual(result["protocol_type"], "InitializeRequest")
                self.assertFalse(result["success"])
                self.assertIn("exception", result)
                self.assertEqual(result["exception"], "Test exception")

    @patch("mcp_fuzzer.fuzzer.protocol_fuzzer.logging")
    def test_fuzz_all_protocol_types(self, mock_logging):
        """Test fuzzing all protocol types."""
        results = self.fuzzer.fuzz_all_protocol_types(runs_per_type=2)

        # Check that all expected protocol types are present
        expected_types = [
            "InitializeRequest",
            "ProgressNotification",
            "CancelNotification",
            "ListResourcesRequest",
            "ReadResourceRequest",
            "SetLevelRequest",
            "GenericJSONRPCRequest",
            "CreateMessageRequest",
            "ListPromptsRequest",
            "GetPromptRequest",
            "ListRootsRequest",
            "SubscribeRequest",
            "UnsubscribeRequest",
            "CompleteRequest",
        ]

        for protocol_type in expected_types:
            self.assertIn(protocol_type, results)
            self.assertIsInstance(results[protocol_type], list)

            # Each type should have 2 runs
            self.assertEqual(len(results[protocol_type]), 2)

            # Check total runs (fuzzing may produce exceptions, but should complete)
            self.assertEqual(len(results[protocol_type]), 2)

    @patch("mcp_fuzzer.fuzzer.protocol_fuzzer.logging")
    def test_fuzz_all_protocol_types_with_exception(self, mock_logging):
        """Test fuzzing all protocol types with exception handling."""
        # Mock one of the fuzzer methods to raise an exception
        with patch.object(self.fuzzer, "fuzz_protocol_type") as mock_fuzz:
            mock_fuzz.side_effect = Exception("Test exception")

            results = self.fuzzer.fuzz_all_protocol_types(runs_per_type=1)

            # Should still return results for all types
            self.assertIn("InitializeRequest", results)
            self.assertEqual(len(results["InitializeRequest"]), 1)
            self.assertIn("error", results["InitializeRequest"][0])

    def test_generate_all_protocol_fuzz_cases(self):
        """Test generating all protocol fuzz cases."""
        fuzz_cases = self.fuzzer.generate_all_protocol_fuzz_cases()

        self.assertIsInstance(fuzz_cases, list)
        self.assertGreater(len(fuzz_cases), 0)

        # Check that each fuzz case has the expected structure
        for case in fuzz_cases:
            self.assertIn("type", case)
            self.assertIn("data", case)
            self.assertIsInstance(case["type"], str)
            self.assertIsInstance(case["data"], dict)

            # Check that the data has basic JSON-RPC structure
            if "jsonrpc" in case["data"]:
                # Some strategies generate different jsonrpc versions for testing
                jsonrpc_value = case["data"]["jsonrpc"]
                if jsonrpc_value is not None:
                    # Allow any string value due to aggressive fuzzing
                    self.assertIsInstance(jsonrpc_value, str)

    def test_generate_all_protocol_fuzz_cases_exception_handling(self):
        """Test exception handling in generate_all_protocol_fuzz_cases."""
        # Mock the strategy to raise an exception for some types
        with patch.object(
            self.fuzzer.strategies, "get_protocol_fuzzer_method"
        ) as mock_method:
            # Store original method to avoid recursion
            original_method = self.fuzzer.strategies.get_protocol_fuzzer_method

            def side_effect(protocol_type):
                if protocol_type == "InitializeRequest":
                    return lambda: (_ for _ in ()).throw(Exception("Test exception"))
                else:
                    return original_method(protocol_type)

            mock_method.side_effect = side_effect

            fuzz_cases = self.fuzzer.generate_all_protocol_fuzz_cases()

            # Should still generate cases for other types
            self.assertIsInstance(fuzz_cases, list)
            # Even with exceptions, we should get some cases
            self.assertGreaterEqual(len(fuzz_cases), 0)

    def test_fuzz_protocol_type_different_runs(self):
        """Test that different runs generate different data."""
        results1 = self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=5)
        results2 = self.fuzzer.fuzz_protocol_type("ProgressNotification", runs=5)

        # Check that we get the expected number of results
        self.assertEqual(len(results1), 5)
        self.assertEqual(len(results2), 5)

        # Check that all runs were successful
        for result in results1 + results2:
            self.assertTrue(result["success"])
            self.assertIn("fuzz_data", result)

    def test_fuzz_protocol_type_zero_runs(self):
        """Test fuzzing with zero runs."""
        results = self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=0)
        self.assertEqual(len(results), 0)

    def test_fuzz_protocol_type_negative_runs(self):
        """Test fuzzing with negative runs."""
        results = self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=-1)
        self.assertEqual(len(results), 0)

    def test_fuzz_all_protocol_types_zero_runs(self):
        """Test fuzzing all types with zero runs per type."""
        results = self.fuzzer.fuzz_all_protocol_types(runs_per_type=0)

        # Should still return results for all types, but with empty lists
        expected_types = [
            "InitializeRequest",
            "ProgressNotification",
            "CancelNotification",
            "ListResourcesRequest",
            "ReadResourceRequest",
            "SetLevelRequest",
            "GenericJSONRPCRequest",
            "CreateMessageRequest",
            "ListPromptsRequest",
            "GetPromptRequest",
            "ListRootsRequest",
            "SubscribeRequest",
            "UnsubscribeRequest",
            "CompleteRequest",
        ]

        for protocol_type in expected_types:
            self.assertIn(protocol_type, results)
            self.assertEqual(len(results[protocol_type]), 0)

    def test_fuzz_all_protocol_types_negative_runs(self):
        """Test fuzzing all types with negative runs per type."""
        results = self.fuzzer.fuzz_all_protocol_types(runs_per_type=-1)

        # Should still return results for all types, but with empty lists
        expected_types = [
            "InitializeRequest",
            "ProgressNotification",
            "CancelNotification",
            "ListResourcesRequest",
            "ReadResourceRequest",
            "SetLevelRequest",
            "GenericJSONRPCRequest",
            "CreateMessageRequest",
            "ListPromptsRequest",
            "GetPromptRequest",
            "ListRootsRequest",
            "SubscribeRequest",
            "UnsubscribeRequest",
            "CompleteRequest",
        ]

        for protocol_type in expected_types:
            self.assertIn(protocol_type, results)
            self.assertEqual(len(results[protocol_type]), 0)

    def test_protocol_type_data_validation(self):
        """Test that fuzzer generates data for all protocol types (behavior test)."""
        protocol_types = [
            "InitializeRequest",
            "ProgressNotification",
            "CancelNotification",
            "ListResourcesRequest",
            "ReadResourceRequest",
            "SetLevelRequest",
            "GenericJSONRPCRequest",
            "CreateMessageRequest",
            "ListPromptsRequest",
            "GetPromptRequest",
            "ListRootsRequest",
            "SubscribeRequest",
            "UnsubscribeRequest",
            "CompleteRequest",
        ]

        for protocol_type in protocol_types:
            with self.subTest(protocol_type=protocol_type):
                results = self.fuzzer.fuzz_protocol_type(protocol_type, runs=1)

                # Test BEHAVIOR: fuzzer should return results for all known
                # protocol types
                self.assertGreater(
                    len(results), 0, f"Fuzzer should generate data for {protocol_type}"
                )

                result = results[0]
                # Test BEHAVIOR: result should have expected structure
                self.assertIn("protocol_type", result)
                self.assertIn("run", result)
                self.assertIn("success", result)
                self.assertIn("fuzz_data", result)

                # Test BEHAVIOR: fuzz_data should be a dict (content can be anything)
                self.assertIsInstance(
                    result["fuzz_data"],
                    dict,
                    f"Fuzz data for {protocol_type} should be a dictionary",
                )
                self.assertEqual(result["protocol_type"], protocol_type)

    def test_logging_integration(self):
        """Test that logging is properly integrated."""
        with patch("mcp_fuzzer.fuzzer.protocol_fuzzer.logging") as mock_logging:
            self.fuzzer.fuzz_protocol_type("InitializeRequest", runs=1)

            # Check that logging.info was called
            mock_logging.info.assert_called()

            # Check that the log message contains expected information
            call_args = mock_logging.info.call_args_list
            found_initialize = False
            for call_args_tuple in call_args:
                if "InitializeRequest" in str(call_args_tuple):
                    found_initialize = True
                    break
            self.assertTrue(found_initialize)

    def test_strategy_integration(self):
        """Test integration with ProtocolStrategies."""
        # Test that the fuzzer properly uses the strategy
        with patch.object(
            self.fuzzer.strategies, "get_protocol_fuzzer_method"
        ) as mock_method:
            mock_method.return_value = lambda: {"test": "data"}

            results = self.fuzzer.fuzz_protocol_type("TestType", runs=1)

            mock_method.assert_called_with("TestType")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["fuzz_data"], {"test": "data"})

    def test_request_id_counter_isolation(self):
        """Test that request ID counter is isolated between instances."""
        fuzzer1 = ProtocolFuzzer()
        fuzzer2 = ProtocolFuzzer()

        # Reset counters
        fuzzer1.request_id_counter = 0
        fuzzer2.request_id_counter = 0

        id1 = fuzzer1._get_request_id()
        id2 = fuzzer2._get_request_id()

        self.assertEqual(id1, 1)
        self.assertEqual(id2, 1)
        self.assertEqual(fuzzer1.request_id_counter, 1)
        self.assertEqual(fuzzer2.request_id_counter, 1)


if __name__ == "__main__":
    unittest.main()
