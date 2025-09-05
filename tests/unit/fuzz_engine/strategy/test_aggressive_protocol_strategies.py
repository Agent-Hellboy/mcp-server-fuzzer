#!/usr/bin/env python3
"""
Unit tests for aggressive protocol type strategies.
Tests the aggressive strategies from mcp_fuzzer.fuzz_engine.strategy.aggressive.
protocol_type_strategy
"""

import pytest

from mcp_fuzzer.fuzz_engine.strategy.aggressive.protocol_type_strategy import (
    fuzz_list_resource_templates_request,
    fuzz_elicit_request,
    fuzz_ping_request,
    get_protocol_fuzzer_method,
    _generate_malicious_string,
    _generate_malicious_value,
)


pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.strategy]


class TestAggressiveProtocolStrategies:
    """Test cases for aggressive protocol type strategies."""

    def test_fuzz_list_resource_templates_request(self):
        """Test ListResourceTemplatesRequest fuzzing generates valid structure."""
        result = fuzz_list_resource_templates_request()

        # Verify basic JSON-RPC structure
        assert "jsonrpc" in result
        assert "id" in result
        assert "method" in result
        assert "params" in result

        # Verify method name
        assert result["method"] == "resources/templates/list"

        # Verify params structure
        params = result["params"]
        assert isinstance(params, dict)
        assert "cursor" in params
        assert "_meta" in params

    def test_fuzz_elicit_request(self):
        """Test ElicitRequest fuzzing generates valid structure."""
        result = fuzz_elicit_request()

        # Verify basic JSON-RPC structure
        assert "jsonrpc" in result
        assert "id" in result
        assert "method" in result
        assert "params" in result

        # Verify method name
        assert result["method"] == "elicitation/create"

        # Verify params structure
        params = result["params"]
        assert isinstance(params, dict)
        assert "message" in params
        assert "requestedSchema" in params

    def test_fuzz_ping_request(self):
        """Test PingRequest fuzzing generates valid structure."""
        result = fuzz_ping_request()

        # Verify basic JSON-RPC structure
        assert "jsonrpc" in result
        assert "id" in result
        assert "method" in result
        assert "params" in result

        # Verify method name
        assert result["method"] == "ping"

    def test_get_protocol_fuzzer_method_new_types(self):
        """Test that new protocol types are properly mapped."""
        # Test new protocol types
        assert (
            get_protocol_fuzzer_method("ListResourceTemplatesRequest")
            == fuzz_list_resource_templates_request
        )
        assert get_protocol_fuzzer_method("ElicitRequest") == fuzz_elicit_request
        assert get_protocol_fuzzer_method("PingRequest") == fuzz_ping_request

        # Test that unknown types return None
        assert get_protocol_fuzzer_method("UnknownType") is None

    def test_generate_malicious_string(self):
        """Test malicious string generation."""
        # Test multiple calls to ensure variety
        strings = [_generate_malicious_string() for _ in range(10)]

        # All should be strings
        for s in strings:
            assert isinstance(s, str)

        # Should have some variety (not all the same)
        unique_strings = set(strings)
        assert len(unique_strings) > 1, "Should generate different malicious strings"

    def test_generate_malicious_value(self):
        """Test malicious value generation."""
        # Test multiple calls to ensure variety
        values = [_generate_malicious_value() for _ in range(20)]

        # Should have some variety in types
        types = {type(v) for v in values}
        assert len(types) > 1, "Should generate different types of malicious values"

        # Should include some common malicious types
        assert any(v is None for v in values), "Should include None values"
        assert any(isinstance(v, str) for v in values), "Should include string values"
        assert any(isinstance(v, (int, float)) for v in values), (
            "Should include numeric values"
        )
        assert any(isinstance(v, (list, dict)) for v in values), (
            "Should include collection values"
        )

    def test_fuzz_functions_generate_different_data(self):
        """Test that fuzzing functions generate different data on multiple calls."""
        # Test each new fuzzing function
        functions = [
            fuzz_list_resource_templates_request,
            fuzz_elicit_request,
            fuzz_ping_request,
        ]

        for func in functions:
            results = [func() for _ in range(5)]

            # All results should have the same structure but different values
            for i, result in enumerate(results):
                assert isinstance(result, dict)
                assert "jsonrpc" in result
                assert "id" in result
                assert "method" in result
                assert "params" in result

            # IDs should be different (malicious values should vary)
            ids = [r["id"] for r in results]
            unique_ids = set(str(id_val) for id_val in ids)
            assert len(unique_ids) > 1, f"{func.__name__} should generate different IDs"

    def test_fuzz_functions_malicious_content(self):
        """Test that fuzzing functions include malicious content."""
        # Test that the functions generate potentially malicious data
        result = fuzz_list_resource_templates_request()

        # Check that malicious values are used
        params = result["params"]
        assert params["cursor"] is not None  # Should be some value
        assert params["_meta"] is not None  # Should be some value

        # Test elicit request
        result = fuzz_elicit_request()
        params = result["params"]
        assert params["message"] is not None
        assert params["requestedSchema"] is not None

        # Test ping request
        result = fuzz_ping_request()
        assert result["params"] is not None

    def test_all_protocol_types_in_fuzzer_method_map(self):
        """Test that all expected protocol types are in the fuzzer method map."""
        expected_types = [
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
            "ListResourceTemplatesRequest",  # New
            "ElicitRequest",  # New
            "PingRequest",  # New
        ]

        for protocol_type in expected_types:
            method = get_protocol_fuzzer_method(protocol_type)
            assert method is not None, f"Missing fuzzer method for {protocol_type}"
            assert callable(method), (
                f"Fuzzer method for {protocol_type} should be callable"
            )

    def test_fuzzer_methods_return_dict(self):
        """Test that all fuzzer methods return dictionaries."""
        protocol_types = [
            "ListResourceTemplatesRequest",
            "ElicitRequest",
            "PingRequest",
        ]

        for protocol_type in protocol_types:
            method = get_protocol_fuzzer_method(protocol_type)
            result = method()
            assert isinstance(result, dict), (
                f"{protocol_type} fuzzer should return dict"
            )
            assert "jsonrpc" in result, (
                f"{protocol_type} result should have jsonrpc field"
            )
            assert "method" in result, (
                f"{protocol_type} result should have method field"
            )
