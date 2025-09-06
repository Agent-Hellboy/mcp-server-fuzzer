"""Tests for custom transport mechanisms."""

import pytest
from unittest.mock import Mock
from typing import Any, Dict, Optional, AsyncIterator

from mcp_fuzzer.transport.base import TransportProtocol
from mcp_fuzzer.transport.custom import (
    CustomTransportRegistry,
    register_custom_transport,
    create_custom_transport,
    list_custom_transports,
)
from mcp_fuzzer.transport.factory import create_transport


class MockTransport(TransportProtocol):
    """Mock transport for testing."""

    def __init__(self, endpoint: str, **kwargs):
        self.endpoint = endpoint
        self.kwargs = kwargs

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return {"result": f"mock_response_{method}"}

    async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"result": "raw_response"}

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        pass

    async def _stream_request(
        self, payload: Dict[str, Any]
    ) -> AsyncIterator[Dict[str, Any]]:
        yield {"result": "stream_response"}


class TestCustomTransportRegistry:
    """Test the custom transport registry functionality."""

    def test_registry_initialization(self):
        """Test that registry initializes correctly."""
        registry = CustomTransportRegistry()
        assert registry.list_transports() == {}

    def test_register_transport(self):
        """Test registering a custom transport."""
        registry = CustomTransportRegistry()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        transports = registry.list_transports()
        assert "mock_transport" in transports
        assert transports["mock_transport"]["class"] == MockTransport
        assert (
            transports["mock_transport"]["description"] == "Mock transport for testing"
        )

    def test_register_duplicate_transport(self):
        """Test that registering a duplicate transport raises an error."""
        registry = CustomTransportRegistry()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        with pytest.raises(
            ValueError, match="Transport 'mock_transport' is already registered"
        ):
            registry.register(
                name="mock_transport",
                transport_class=MockTransport,
                description="Duplicate transport",
            )

    def test_register_invalid_transport_class(self):
        """Test that registering an invalid transport class raises an error."""
        registry = CustomTransportRegistry()

        class InvalidTransport:
            pass

        with pytest.raises(
            ValueError, match="Transport class .* must inherit from TransportProtocol"
        ):
            registry.register(
                name="invalid_transport",
                transport_class=InvalidTransport,
                description="Invalid transport",
            )

    def test_unregister_transport(self):
        """Test unregistering a custom transport."""
        registry = CustomTransportRegistry()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        registry.unregister("mock_transport")
        assert registry.list_transports() == {}

    def test_unregister_nonexistent_transport(self):
        """Test that unregistering a non-existent transport raises an error."""
        registry = CustomTransportRegistry()

        with pytest.raises(KeyError, match="Transport 'nonexistent' is not registered"):
            registry.unregister("nonexistent")

    def test_get_transport_class(self):
        """Test getting transport class from registry."""
        registry = CustomTransportRegistry()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        transport_class = registry.get_transport_class("mock_transport")
        assert transport_class == MockTransport

    def test_get_transport_info(self):
        """Test getting transport info from registry."""
        registry = CustomTransportRegistry()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        info = registry.get_transport_info("mock_transport")
        assert info["class"] == MockTransport
        assert info["description"] == "Mock transport for testing"

    def test_create_transport(self):
        """Test creating transport instance from registry."""
        registry = CustomTransportRegistry()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        transport = registry.create_transport(
            "mock_transport", "test-endpoint", timeout=30
        )
        assert isinstance(transport, MockTransport)
        assert transport.endpoint == "test-endpoint"
        assert transport.kwargs == {"timeout": 30}


class TestCustomTransportFunctions:
    """Test the global custom transport functions."""

    def setup_method(self):
        """Clear the global registry before each test."""
        from mcp_fuzzer.transport.custom import registry

        registry.clear()

    def test_register_custom_transport(self):
        """Test the global register_custom_transport function."""
        register_custom_transport(
            name="global_mock",
            transport_class=MockTransport,
            description="Global mock transport",
        )

        transports = list_custom_transports()
        assert "global_mock" in transports

    def test_create_custom_transport(self):
        """Test the global create_custom_transport function."""
        register_custom_transport(
            name="global_mock",
            transport_class=MockTransport,
            description="Global mock transport",
        )

        transport = create_custom_transport("global_mock", "test-endpoint")
        assert isinstance(transport, MockTransport)
        assert transport.endpoint == "test-endpoint"


class TestTransportFactoryIntegration:
    """Test integration with the transport factory."""

    def setup_method(self):
        """Clear the global registry before each test."""
        from mcp_fuzzer.transport.custom import registry

        registry.clear()

    def test_custom_transport_via_factory(self):
        """Test creating custom transport via factory."""
        register_custom_transport(
            name="factory_mock",
            transport_class=MockTransport,
            description="Factory mock transport",
        )

        transport = create_transport("factory_mock://test-endpoint")
        assert isinstance(transport, MockTransport)
        assert transport.endpoint == "test-endpoint"

    def test_custom_transport_via_factory_two_args(self):
        """Back-compat: (protocol, endpoint) for custom transports."""
        register_custom_transport(
            name="factory_mock",
            transport_class=MockTransport,
            description="Factory mock transport",
        )
        transport = create_transport("factory_mock", "test-endpoint")
        assert isinstance(transport, MockTransport)
        assert transport.endpoint == "test-endpoint"

    def test_unknown_custom_transport(self):
        """Test that unknown custom transport raises error."""
        with pytest.raises(ValueError, match="Unsupported URL scheme: unknown"):
            create_transport("unknown://test-endpoint")

    def test_custom_transport_with_config_schema(self):
        """Test custom transport with configuration schema."""
        schema = {
            "type": "object",
            "properties": {
                "timeout": {"type": "number"},
            },
        }

        register_custom_transport(
            name="schema_mock",
            transport_class=MockTransport,
            description="Schema mock transport",
            config_schema=schema,
        )

        transports = list_custom_transports()
        assert "schema_mock" in transports
        assert transports["schema_mock"]["config_schema"] == schema


class TestTransportProtocolCompliance:
    """Test that custom transports comply with TransportProtocol."""

    async def test_mock_transport_compliance(self):
        """Test that MockTransport implements all required methods."""
        transport = MockTransport("test-endpoint")

        # Test send_request
        result = await transport.send_request("test_method")
        assert result == {"result": "mock_response_test_method"}

        # Test send_raw
        result = await transport.send_raw({"test": "payload"})
        assert result == {"result": "raw_response"}

        # Test send_notification
        await transport.send_notification("test_method")  # Should not raise

        # Test streaming
        async for response in transport.stream_request({"test": "payload"}):
            assert response == {"result": "stream_response"}
            break  # Only test first response

    async def test_tools_methods(self):
        """Test that inherited tools methods work."""
        transport = MockTransport("test-endpoint")

        # Mock the send_request method to return tools
        original_send_request = transport.send_request

        async def mock_send_request(method, params=None):
            if method == "tools/list":
                return {"tools": [{"name": "test_tool"}]}
            return await original_send_request(method, params)

        transport.send_request = mock_send_request

        tools = await transport.get_tools()
        assert tools == [{"name": "test_tool"}]
