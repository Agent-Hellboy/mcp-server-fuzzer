"""
Unit tests for aggressive protocol type strategies.
"""

import pytest
from mcp_fuzzer.fuzz_engine.mutators.strategies.aggressive.protocol_type_strategy import (  # noqa: E501
    generate_malicious_string,
    generate_malicious_value,
    choice_lazy,
    generate_experimental_payload,
)  # noqa: E501
from mcp_fuzzer.fuzz_engine.mutators.strategies import get_spec_protocol_fuzzer_method


def get_protocol_fuzzer_method(protocol_type: str):
    """Helper to get aggressive protocol fuzzer method."""
    return get_spec_protocol_fuzzer_method(protocol_type, "aggressive")


pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.strategy]


class TestAggressiveProtocolStrategies:
    """Test cases for aggressive protocol type strategies."""

    @pytest.mark.parametrize("protocol_type", [
        "ListResourceTemplatesRequest",
        "ElicitRequest",
        "PingRequest",
        "InitializeRequest",
    ])
    def test_protocol_fuzzer_generates_valid_structure(self, protocol_type):
        """Test that protocol fuzzers generate valid JSON-RPC structure."""
        method = get_protocol_fuzzer_method(protocol_type)
        if method is None:
            pytest.skip(f"spec_protocol doesn't have {protocol_type} definition")
        
        result = method()
        if result is None:
            pytest.skip(f"spec_protocol doesn't have {protocol_type} definition")
        
        assert isinstance(result, dict)
        assert result.get("jsonrpc") == "2.0"
        assert "method" in result

    def test_get_protocol_fuzzer_method_returns_callable(self):
        """Test that get_protocol_fuzzer_method returns callable or None."""
        assert get_protocol_fuzzer_method("InitializeRequest") is not None
        assert callable(get_protocol_fuzzer_method("InitializeRequest"))
        assert get_protocol_fuzzer_method("UnknownType") is None

    def test_fuzzer_generates_varied_data(self):
        """Test that fuzzers generate different data on multiple calls."""
        method = get_protocol_fuzzer_method("InitializeRequest")
        if method is None:
            pytest.skip("spec_protocol doesn't have InitializeRequest definition")
        
        results = [method() for _ in range(5)]
        results = [r for r in results if r is not None]
        
        if not results:
            pytest.skip("No results generated")
        
        # Should have variety in IDs
        ids = [r.get("id") for r in results if "id" in r]
        if ids:
            unique_ids = set(str(id_val) for id_val in ids)
            assert len(unique_ids) > 1, "Should generate different IDs"

    def test_capabilities_experimental_fuzzing(self):
        """Test that capabilities.experimental fuzzing generates varied content."""
        method = get_protocol_fuzzer_method("InitializeRequest")
        if method is None:
            pytest.skip("spec_protocol doesn't have InitializeRequest definition")
        
        results = [method() for _ in range(100)]
        results = [r for r in results if r is not None]
        
        experimental_values = []
        for result in results:
            params = result.get("params", {})
            if isinstance(params, dict):
                capabilities = params.get("capabilities")
                if isinstance(capabilities, dict):
                    experimental = capabilities.get("experimental")
                    experimental_values.append(experimental)
        
        if experimental_values:
            unique_values = set(str(v) for v in experimental_values)
            assert len(unique_values) > 1, (
                "Should generate different experimental values"
            )
            assert any(v is None for v in experimental_values), (
                "Should include None values"
            )
            assert any(v is not None for v in experimental_values), (
                "Should include non-None values"
            )

    def test_all_protocol_types_supported(self):
        """Test that all expected protocol types are supported."""
        from mcp_fuzzer.fuzz_engine.executor import ProtocolExecutor
        
        expected_types = [
            "InitializeRequest", "ProgressNotification", "CancelNotification",
            "ListResourcesRequest", "ReadResourceRequest", "SetLevelRequest",
            "GenericJSONRPCRequest", "CreateMessageRequest", "ListPromptsRequest",
            "GetPromptRequest", "ListRootsRequest", "SubscribeRequest",
            "UnsubscribeRequest", "CompleteRequest", "ListResourceTemplatesRequest",
            "ElicitRequest", "PingRequest",
        ]
        
        for protocol_type in expected_types:
            method = get_protocol_fuzzer_method(protocol_type)
            assert method is not None, f"Missing fuzzer method for {protocol_type}"
            assert callable(method), (
                f"Fuzzer method for {protocol_type} should be callable"
            )


class TestAggressiveHelperFunctions:
    """Test cases for aggressive helper functions."""

    def test_generate_malicious_string(self):
        """Test malicious string generation."""
        strings = [generate_malicious_string() for _ in range(10)]
        assert all(isinstance(s, str) for s in strings)
        assert len(set(strings)) > 1, "Should generate different malicious strings"

    def test_generate_malicious_value(self):
        """Test malicious value generation."""
        values = [generate_malicious_value() for _ in range(100)]
        types = {type(v) for v in values}
        assert len(types) > 1, "Should generate different types"
        assert any(v is None for v in values), "Should include None values"
        assert any(isinstance(v, str) for v in values), "Should include string values"
        assert any(isinstance(v, (int, float)) for v in values), (
            "Should include numeric values"
        )
        assert any(isinstance(v, (list, dict)) for v in values), (
            "Should include collection values"
        )

    def test_choice_lazy(self):
        """Test choice_lazy handles callable and non-callable options."""
        # Non-callable options
        result = choice_lazy([1, 2, 3, "test", None, True])
        assert result in [1, 2, 3, "test", None, True]
        
        # Callable options
        result = choice_lazy([
            lambda: "generated_string",
            lambda: {"key": "value"},
            lambda: [1, 2, 3],
        ])
        assert isinstance(result, (str, dict, list))
        
        # Mixed options
        result = choice_lazy([
            "static_value",
            lambda: "dynamic_value",
            None,
            lambda: {"dynamic": "object"},
        ])
        assert result in ["static_value", None] or isinstance(result, (str, dict))

    def test_generate_experimental_payload(self):
        """Test experimental payload generation."""
        payloads = [generate_experimental_payload() for _ in range(50)]
        unique_payloads = set(str(p) for p in payloads)
        assert len(unique_payloads) > 1, (
            "Should generate different experimental payloads"
        )
        assert any(p is None for p in payloads), (
            "Should include None experimental payloads"
        )
        assert any(p is not None for p in payloads), (
            "Should include non-None experimental payloads"
        )
        
        types = {type(p) for p in payloads}
        assert len(types) > 1, "Should generate different experimental payload types"
