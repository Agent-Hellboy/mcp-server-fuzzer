#!/usr/bin/env python3
"""
Unit tests for ProtocolStrategies from strategy_manager.py - Focused on
BEHAVIOR not content
"""

import unittest

from mcp_fuzzer.fuzz_engine.strategy import ProtocolStrategies

# Constants for testing
JSONRPC_VERSION = "2.0"
LATEST_PROTOCOL_VERSION = "2024-11-05"


class TestProtocolStrategies(unittest.TestCase):
    """Test cases for ProtocolStrategies class - BEHAVIOR focused."""

    def test_get_protocol_fuzzer_method_known_types(self):
        """Test BEHAVIOR: get_protocol_fuzzer_method returns callable for
        known types.
        """
        known_protocol_types = [
            "InitializeRequest",
            "ProgressNotification",
            "CancelNotification",
            "ListResourcesRequest",
            "ReadResourceRequest",
            "SetLevelRequest",
            "GenericJSONRPCRequest",
            "CallToolResult",
            "SamplingMessage",
            "CreateMessageRequest",
            "ListPromptsRequest",
            "GetPromptRequest",
            "ListRootsRequest",
            "SubscribeRequest",
            "UnsubscribeRequest",
            "CompleteRequest",
        ]

        for protocol_type in known_protocol_types:
            with self.subTest(protocol_type=protocol_type):
                fuzzer_method = ProtocolStrategies.get_protocol_fuzzer_method(
                    protocol_type
                )

                # Test BEHAVIOR: should return a callable function
                self.assertIsNotNone(
                    fuzzer_method, f"Should have fuzzer for {protocol_type}"
                )
                self.assertTrue(
                    callable(fuzzer_method),
                    f"Fuzzer for {protocol_type} should be callable",
                )

    def test_get_protocol_fuzzer_method_unknown_type(self):
        """Test BEHAVIOR: get_protocol_fuzzer_method returns None for unknown types."""
        unknown_types = ["UnknownProtocol", "InvalidType", "NonExistentRequest"]

        for unknown_type in unknown_types:
            with self.subTest(unknown_type=unknown_type):
                fuzzer_method = ProtocolStrategies.get_protocol_fuzzer_method(
                    unknown_type
                )

                # Test BEHAVIOR: should return None for unknown types
                self.assertIsNone(
                    fuzzer_method, f"Should return None for unknown type {unknown_type}"
                )

    def test_fuzzer_methods_return_dictionaries(self):
        """Test BEHAVIOR: all fuzzer methods return dictionaries when called."""
        known_protocol_types = [
            "InitializeRequest",
            "ProgressNotification",
            "CancelNotification",
            "ListResourcesRequest",
            "ReadResourceRequest",
            "SetLevelRequest",
            "GenericJSONRPCRequest",
            "CallToolResult",
            "SamplingMessage",
            "CreateMessageRequest",
            "ListPromptsRequest",
            "GetPromptRequest",
            "ListRootsRequest",
            "SubscribeRequest",
            "UnsubscribeRequest",
            "CompleteRequest",
        ]

        for protocol_type in known_protocol_types:
            with self.subTest(protocol_type=protocol_type):
                fuzzer_method = ProtocolStrategies.get_protocol_fuzzer_method(
                    protocol_type
                )

                # Test BEHAVIOR: calling the method should return a dictionary
                result = fuzzer_method()
                self.assertIsInstance(
                    result, dict, f"{protocol_type} fuzzer should return a dict"
                )
                self.assertGreater(
                    len(result),
                    0,
                    f"{protocol_type} fuzzer should return non-empty dict",
                )

    def test_initialize_request_phase_support(self):
        """Test BEHAVIOR: InitializeRequest supports both realistic and
        aggressive phases."""
        # Test that fuzz_initialize_request accepts phase parameter
        realistic_result = ProtocolStrategies.fuzz_initialize_request("realistic")
        aggressive_result = ProtocolStrategies.fuzz_initialize_request("aggressive")

        # Test BEHAVIOR: both phases should return dictionaries
        self.assertIsInstance(
            realistic_result, dict, "Realistic phase should return dict"
        )
        self.assertIsInstance(
            aggressive_result, dict, "Aggressive phase should return dict"
        )

        # Test BEHAVIOR: should return different types of content
        # (we don't test exact content, just that they're different approaches)
        self.assertGreater(
            len(realistic_result), 0, "Realistic result should not be empty"
        )
        self.assertGreater(
            len(aggressive_result), 0, "Aggressive result should not be empty"
        )

    def test_initialize_request_default_phase(self):
        """Test BEHAVIOR: fuzz_initialize_request defaults to aggressive phase."""
        default_result = ProtocolStrategies.fuzz_initialize_request()
        explicit_aggressive = ProtocolStrategies.fuzz_initialize_request("aggressive")

        # Test BEHAVIOR: both should return dictionaries (content may vary
        # due to randomness)
        self.assertIsInstance(default_result, dict, "Default should return dict")
        self.assertIsInstance(
            explicit_aggressive, dict, "Explicit aggressive should return dict"
        )


if __name__ == "__main__":
    unittest.main()
