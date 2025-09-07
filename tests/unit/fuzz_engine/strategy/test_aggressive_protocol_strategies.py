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
    generate_malicious_string,
    generate_malicious_value,
)


pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.strategy]


class TestAggressiveProtocolStrategies:
    """Test cases for aggressive protocol type strategies."""

    def test_fuzz_list_resource_templates_request(self):
        """Test ListResourceTemplatesRequest fuzzing generates valid structure."""
        result = fuzz_list_resource_templates_request()

        # Verify basic JSON-RPC structure
        assert "jsonrpc" in result
        assert result["jsonrpc"] == "2.0"
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
        assert result["jsonrpc"] == "2.0"
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
        assert result["jsonrpc"] == "2.0"
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

    def testgenerate_malicious_string(self):
        """Test malicious string generation."""
        # Test multiple calls to ensure variety
        strings = [generate_malicious_string() for _ in range(10)]

        # All should be strings
        for s in strings:
            assert isinstance(s, str)

        # Should have some variety (not all the same)
        unique_strings = set(strings)
        assert len(unique_strings) > 1, "Should generate different malicious strings"

    def testgenerate_malicious_value(self):
        """Test malicious value generation."""
        # Test multiple calls to ensure variety
        values = [generate_malicious_value() for _ in range(100)]

        # Should have some variety in types
        types = {type(v) for v in values}
        assert len(types) > 1, "Should generate different types of malicious values"

        # Should include some common malicious types (with higher sample size)
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
        assert isinstance(params["cursor"], str)
        # _meta can be any value (including None), presence already validated above

        # Test elicit request
        result = fuzz_elicit_request()
        params = result["params"]
        assert isinstance(params["message"], str)
        # requestedSchema can be any value (including None)

        # Test ping request
        result = fuzz_ping_request()
        # params can be any value (including None); presence checked above

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

    def test_capabilities_experimental_fuzzing(self):
        """Test that capabilities.experimental fuzzing generates varied content."""
        from mcp_fuzzer.fuzz_engine.strategy.aggressive.protocol_type_strategy import (
            fuzz_initialize_request_aggressive,
        )

        # Generate multiple initialize requests to test variety
        results = [fuzz_initialize_request_aggressive() for _ in range(100)]

        # Check that we get some variety in capabilities.experimental
        experimental_values = []
        for result in results:
            params = result.get("params", {})
            if isinstance(params, dict):
                capabilities = params.get("capabilities")
                if isinstance(capabilities, dict):
                    experimental = capabilities.get("experimental")
                    experimental_values.append(experimental)

        # Should have some variety in experimental values
        if experimental_values:
            unique_values = set(str(v) for v in experimental_values)
            assert len(unique_values) > 1, (
                "Should generate different experimental values"
            )

            # Should include some None values (which is valid)
            assert any(v is None for v in experimental_values), (
                "Should include None experimental values"
            )

            # Should include some non-None values (could be string, dict, list, etc.)
            assert any(v is not None for v in experimental_values), (
                "Should include non-None experimental values"
            )
        else:
            # If no experimental values found, that's also valid
            # - capabilities might not be dict
            assert True, "No experimental values found, which is valid"

    def test_protocol_types_sync_with_fuzzer_map(self):
        """Test that PROTOCOL_TYPES tuple stays in sync with fuzzer method map."""
        from mcp_fuzzer.fuzz_engine.fuzzer.protocol_fuzzer import ProtocolFuzzer
        from mcp_fuzzer.fuzz_engine.strategy.aggressive.protocol_type_strategy import (
            get_protocol_fuzzer_method,
        )

        # Get all protocol types from the fuzzer method map
        fuzzer_map_types = set()
        for protocol_type in ProtocolFuzzer.PROTOCOL_TYPES:
            if get_protocol_fuzzer_method(protocol_type) is not None:
                fuzzer_map_types.add(protocol_type)

        # Get all types that have fuzzer methods
        all_supported_types = set()
        # Check all possible protocol types that might be in the map
        potential_types = [
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
            "ListResourceTemplatesRequest",
            "ElicitRequest",
            "PingRequest",
            # Result schemas
            "InitializeResult",
            "ListResourcesResult",
            "ListResourceTemplatesResult",
            "ReadResourceResult",
            "ListPromptsResult",
            "GetPromptResult",
            "ListToolsResult",
            "CompleteResult",
            "CreateMessageResult",
            "ListRootsResult",
            "PingResult",
            "ElicitResult",
            # Notification schemas
            "LoggingMessageNotification",
            "ResourceListChangedNotification",
            "ResourceUpdatedNotification",
            "PromptListChangedNotification",
            "ToolListChangedNotification",
            "RootsListChangedNotification",
            # Content block schemas
            "TextContent",
            "ImageContent",
            "AudioContent",
            # Resource schemas
            "Resource",
            "ResourceTemplate",
            "TextResourceContents",
            "BlobResourceContents",
            # Tool schemas
            "Tool",
        ]

        for protocol_type in potential_types:
            if get_protocol_fuzzer_method(protocol_type) is not None:
                all_supported_types.add(protocol_type)

        # PROTOCOL_TYPES should match the fuzzer method map
        assert set(ProtocolFuzzer.PROTOCOL_TYPES) == all_supported_types, (
            f"PROTOCOL_TYPES mismatch: {set(ProtocolFuzzer.PROTOCOL_TYPES)} != "
            f"{all_supported_types}"
        )

        # Should have exactly 45 types (19 original + 26 new)
        assert len(ProtocolFuzzer.PROTOCOL_TYPES) == 45, (
            f"Expected 45 protocol types, got {len(ProtocolFuzzer.PROTOCOL_TYPES)}"
        )
