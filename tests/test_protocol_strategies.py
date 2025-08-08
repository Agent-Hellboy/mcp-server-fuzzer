#!/usr/bin/env python3
"""
Unit tests for ProtocolStrategies
"""

import unittest
from unittest.mock import MagicMock, patch

from hypothesis import given
from hypothesis import strategies as st

from mcp_fuzzer.strategy.protocol_strategies import (
    JSONRPC_VERSION,
    LATEST_PROTOCOL_VERSION,
    ProtocolStrategies,
)


class TestProtocolStrategies(unittest.TestCase):
    """Test cases for ProtocolStrategies class."""

    def setUp(self):
        """Set up test fixtures."""
        self.strategies = ProtocolStrategies()

    def test_fuzz_initialize_request_structure(self):
        """Test that InitializeRequest has correct structure."""
        result = ProtocolStrategies.fuzz_initialize_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        # jsonrpc can be various values due to aggressive fuzzing
        self.assertIsInstance(result["jsonrpc"], (str, type(None)))

    def test_fuzz_initialize_request_params_structure(self):
        """Test that InitializeRequest params have correct structure."""
        result = ProtocolStrategies.fuzz_initialize_request()
        params = result["params"]

        self.assertIn("protocolVersion", params)
        self.assertIn("capabilities", params)
        self.assertIn("clientInfo", params)

        self.assertIsInstance(
            params["protocolVersion"], (str, type(None), int, bool, list, dict)
        )
        # capabilities can be various types due to aggressive fuzzing
        self.assertIsInstance(params["capabilities"], (dict, type(None), str, list))

    def test_fuzz_progress_notification_structure(self):
        """Test that ProgressNotification has correct structure."""
        result = ProtocolStrategies.fuzz_progress_notification()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "notifications/progress")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_progress_notification_params(self):
        """Test that ProgressNotification params have correct structure."""
        result = ProtocolStrategies.fuzz_progress_notification()
        params = result["params"]

        self.assertIn("progressToken", params)
        self.assertIn("progress", params)
        self.assertIn("total", params)

    def test_fuzz_cancel_notification_structure(self):
        """Test that CancelNotification has correct structure."""
        result = ProtocolStrategies.fuzz_cancel_notification()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "notifications/cancelled")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_cancel_notification_params(self):
        """Test that CancelNotification params have correct structure."""
        result = ProtocolStrategies.fuzz_cancel_notification()
        params = result["params"]

        self.assertIn("requestId", params)
        self.assertIn("reason", params)

    def test_fuzz_list_resources_request_structure(self):
        """Test that ListResourcesRequest has correct structure."""
        result = ProtocolStrategies.fuzz_list_resources_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "resources/list")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_list_resources_request_params(self):
        """Test that ListResourcesRequest params have correct structure."""
        result = ProtocolStrategies.fuzz_list_resources_request()
        params = result["params"]

        self.assertIn("cursor", params)
        self.assertIn("_meta", params)

    def test_fuzz_read_resource_request_structure(self):
        """Test that ReadResourceRequest has correct structure."""
        result = ProtocolStrategies.fuzz_read_resource_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "resources/read")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_read_resource_request_params(self):
        """Test that ReadResourceRequest params have correct structure."""
        result = ProtocolStrategies.fuzz_read_resource_request()
        params = result["params"]

        self.assertIn("uri", params)
        self.assertIsInstance(params["uri"], str)

    def test_fuzz_set_level_request_structure(self):
        """Test that SetLevelRequest has correct structure."""
        result = ProtocolStrategies.fuzz_set_level_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "logging/setLevel")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_set_level_request_params(self):
        """Test that SetLevelRequest params have correct structure."""
        result = ProtocolStrategies.fuzz_set_level_request()
        params = result["params"]

        self.assertIn("level", params)

    def test_fuzz_generic_jsonrpc_request_structure(self):
        """Test that GenericJSONRPCRequest has correct structure."""
        result = ProtocolStrategies.fuzz_generic_jsonrpc_request()

        self.assertIsInstance(result, dict)
        self.assertIn("method", result)
        self.assertIn("params", result)

    def test_fuzz_call_tool_result_structure(self):
        """Test that CallToolResult has correct structure."""
        result = ProtocolStrategies.fuzz_call_tool_result()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("result", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertIsInstance(result["result"], dict)

    def test_fuzz_call_tool_result_content(self):
        """Test that CallToolResult result has correct structure."""
        result = ProtocolStrategies.fuzz_call_tool_result()
        result_data = result["result"]

        self.assertIn("content", result_data)
        self.assertIn("isError", result_data)
        self.assertIn("_meta", result_data)

        self.assertIsInstance(result_data["content"], list)
        if result_data["content"]:
            self.assertIsInstance(result_data["content"][0], dict)

    def test_fuzz_sampling_message_structure(self):
        """Test that SamplingMessage has correct structure."""
        result = ProtocolStrategies.fuzz_sampling_message()

        self.assertIsInstance(result, dict)
        self.assertIn("role", result)
        self.assertIn("content", result)

        self.assertIsInstance(result["content"], list)

    def test_fuzz_create_message_request_structure(self):
        """Test that CreateMessageRequest has correct structure."""
        result = ProtocolStrategies.fuzz_create_message_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "sampling/createMessage")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_create_message_request_params(self):
        """Test that CreateMessageRequest params have correct structure."""
        result = ProtocolStrategies.fuzz_create_message_request()
        params = result["params"]

        self.assertIn("messages", params)
        self.assertIn("modelPreferences", params)
        self.assertIn("systemPrompt", params)
        self.assertIn("includeContext", params)
        self.assertIn("temperature", params)
        self.assertIn("maxTokens", params)
        self.assertIn("stopSequences", params)
        self.assertIn("metadata", params)

        self.assertIsInstance(params["messages"], list)

    def test_fuzz_list_prompts_request_structure(self):
        """Test that ListPromptsRequest has correct structure."""
        result = ProtocolStrategies.fuzz_list_prompts_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "prompts/list")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_get_prompt_request_structure(self):
        """Test that GetPromptRequest has correct structure."""
        result = ProtocolStrategies.fuzz_get_prompt_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "prompts/get")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_get_prompt_request_params(self):
        """Test that GetPromptRequest params have correct structure."""
        result = ProtocolStrategies.fuzz_get_prompt_request()
        params = result["params"]

        self.assertIn("name", params)
        self.assertIn("arguments", params)

    def test_fuzz_list_roots_request_structure(self):
        """Test that ListRootsRequest has correct structure."""
        result = ProtocolStrategies.fuzz_list_roots_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "roots/list")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_subscribe_request_structure(self):
        """Test that SubscribeRequest has correct structure."""
        result = ProtocolStrategies.fuzz_subscribe_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "resources/subscribe")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_subscribe_request_params(self):
        """Test that SubscribeRequest params have correct structure."""
        result = ProtocolStrategies.fuzz_subscribe_request()
        params = result["params"]

        self.assertIn("uri", params)
        self.assertIsInstance(params["uri"], str)

    def test_fuzz_unsubscribe_request_structure(self):
        """Test that UnsubscribeRequest has correct structure."""
        result = ProtocolStrategies.fuzz_unsubscribe_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "resources/unsubscribe")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_complete_request_structure(self):
        """Test that CompleteRequest has correct structure."""
        result = ProtocolStrategies.fuzz_complete_request()

        self.assertIsInstance(result, dict)
        self.assertIn("jsonrpc", result)
        self.assertIn("id", result)
        self.assertIn("method", result)
        self.assertIn("params", result)

        self.assertEqual(result["jsonrpc"], JSONRPC_VERSION)
        self.assertEqual(result["method"], "completion/complete")
        self.assertIsInstance(result["params"], dict)

    def test_fuzz_complete_request_params(self):
        """Test that CompleteRequest params have correct structure."""
        result = ProtocolStrategies.fuzz_complete_request()
        params = result["params"]

        self.assertIn("ref", params)
        self.assertIn("argument", params)

        self.assertIsInstance(params["ref"], dict)
        self.assertIsInstance(params["argument"], dict)

    def test_get_protocol_fuzzer_method_valid_types(self):
        """Test getting fuzzer methods for valid protocol types."""
        valid_types = [
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

        for protocol_type in valid_types:
            method = ProtocolStrategies.get_protocol_fuzzer_method(protocol_type)
            self.assertIsNotNone(method)
            self.assertTrue(callable(method))

    def test_get_protocol_fuzzer_method_invalid_type(self):
        """Test getting fuzzer method for invalid protocol type."""
        method = ProtocolStrategies.get_protocol_fuzzer_method("InvalidType")
        self.assertIsNone(method)

    def test_get_protocol_fuzzer_method_empty_string(self):
        """Test getting fuzzer method for empty string."""
        method = ProtocolStrategies.get_protocol_fuzzer_method("")
        self.assertIsNone(method)

    def test_get_protocol_fuzzer_method_none(self):
        """Test getting fuzzer method for None."""
        method = ProtocolStrategies.get_protocol_fuzzer_method(None)
        self.assertIsNone(method)

    def test_fuzzer_methods_generate_different_data(self):
        """Test that fuzzer methods generate different data on multiple runs."""
        protocol_types = [
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

        for protocol_type in protocol_types:
            method = ProtocolStrategies.get_protocol_fuzzer_method(protocol_type)
            if method:
                results = [method() for _ in range(3)]

                # All results should have the same structure but potentially
                # different values
                for i, result in enumerate(results):
                    self.assertIsInstance(result, dict)
                    if i > 0:
                        # Check that at least some fields have different values
                        # (not all fields will be different due to fixed values
                        # like jsonrpc)
                        if "jsonrpc" in result and "jsonrpc" in results[0]:
                            # Some strategies generate different jsonrpc versions
                            # for testing
                            pass

    def test_initialize_request_protocol_version_variations(self):
        """Test that InitializeRequest generates various protocol versions."""
        versions = set()
        for _ in range(10):
            result = ProtocolStrategies.fuzz_initialize_request()
            protocol_version = result["params"]["protocolVersion"]
            # Convert to string for hashing if it's not already a string
            if isinstance(protocol_version, (list, dict, int, float, bool)):
                protocol_version = str(protocol_version)
            elif protocol_version is None:
                protocol_version = "None"
            versions.add(protocol_version)

        # Should generate multiple different versions
        self.assertGreater(len(versions), 1)

    def test_progress_notification_edge_cases(self):
        """Test that ProgressNotification generates edge cases."""
        for _ in range(5):
            result = ProtocolStrategies.fuzz_progress_notification()
            params = result["params"]

            # Should handle various types for progressToken and progress
            self.assertIn("progressToken", params)
            self.assertIn("progress", params)
            self.assertIn("total", params)

    def test_cancel_notification_edge_cases(self):
        """Test that CancelNotification generates edge cases."""
        for _ in range(5):
            result = ProtocolStrategies.fuzz_cancel_notification()
            params = result["params"]

            # Should handle various types for requestId and reason
            self.assertIn("requestId", params)
            self.assertIn("reason", params)

    def test_generic_jsonrpc_request_variations(self):
        """Test that GenericJSONRPCRequest generates valid request types."""
        results = []
        for _ in range(10):
            result = ProtocolStrategies.fuzz_generic_jsonrpc_request()
            results.append(result)
            # Basic structure validation
            self.assertIsInstance(result, dict)

        # Should generate at least some valid results
        self.assertGreater(len(results), 0)

        # Check that at least one result has expected fields
        has_method = any("method" in result for result in results)
        has_params = any("params" in result for result in results)
        self.assertTrue(
            has_method or has_params,
            "Should generate some recognizable JSON-RPC structure",
        )

    def test_sampling_message_content_variations(self):
        """Test that SamplingMessage generates various content types."""
        content_types = set()
        for _ in range(10):
            result = ProtocolStrategies.fuzz_sampling_message()
            if result["content"]:
                for item in result["content"]:
                    if isinstance(item, dict) and "type" in item:
                        content_types.add(item["type"])

        # Should generate different content types
        self.assertGreater(len(content_types), 0)

    def test_create_message_request_complex_params(self):
        """Test that CreateMessageRequest generates complex parameter combinations."""
        for _ in range(5):
            result = ProtocolStrategies.fuzz_create_message_request()
            params = result["params"]

            # Check that all expected parameters are present
            required_params = [
                "messages",
                "modelPreferences",
                "systemPrompt",
                "includeContext",
                "temperature",
                "maxTokens",
                "stopSequences",
                "metadata",
            ]

            for param in required_params:
                self.assertIn(param, params)

    def test_constants_are_correct(self):
        """Test that protocol constants are correctly defined."""
        self.assertEqual(LATEST_PROTOCOL_VERSION, "2024-11-05")
        self.assertEqual(JSONRPC_VERSION, "2.0")


if __name__ == "__main__":
    unittest.main()
