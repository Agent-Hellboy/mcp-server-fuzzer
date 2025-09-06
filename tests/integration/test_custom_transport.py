"""Integration tests for custom transport mechanisms."""

import pytest
import tempfile
import os
from pathlib import Path

from mcp_fuzzer.config_loader import apply_config_file, load_custom_transports
from mcp_fuzzer.transport import create_transport, register_custom_transport
from mcp_fuzzer.transport.base import TransportProtocol
from typing import Any, Dict, Optional, AsyncIterator


class IntegrationTestTransport(TransportProtocol):
    """Test transport for integration testing."""

    def __init__(self, endpoint: str, **kwargs):
        self.endpoint = endpoint
        self.kwargs = kwargs
        self.connected = False

    async def connect(self) -> None:
        """Establish connection."""
        self.connected = True

    async def disconnect(self) -> None:
        """Close connection."""
        self.connected = False

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Send JSON-RPC request."""
        if not self.connected:
            await self.connect()

        return {
            "jsonrpc": "2.0",
            "result": {
                "method": method,
                "params": params,
                "endpoint": self.endpoint,
                "transport_type": "integration_test",
            },
            "id": 1,
        }

    async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send raw payload."""
        return {"result": "raw_response", "original_payload": payload}

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        """Send JSON-RPC notification."""
        pass

    async def _stream_request(
        self, payload: Dict[str, Any]
    ) -> AsyncIterator[Dict[str, Any]]:
        """Stream request implementation."""
        yield {
            "jsonrpc": "2.0",
            "result": {"streamed": True, "payload": payload},
            "id": 1,
        }


class TestCustomTransportConfiguration:
    """Test custom transport configuration loading."""

    def setup_method(self):
        """Clear any existing custom transports."""
        from mcp_fuzzer.transport.custom import registry

        for name in list(registry.list_transports().keys()):
            registry.unregister(name)

    def test_config_file_custom_transport_loading(self):
        """Test loading custom transports from configuration file."""
        config_content = """
custom_transports:
  integration_test:
    module: "tests.integration.test_custom_transport"
    class: "IntegrationTestTransport"
    description: "Integration test transport"
    config_schema:
      timeout: 30
      retries: 3
"""

        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            # Load config and custom transports from the file we wrote
            assert apply_config_file(config_path=config_path) is True

            # Test that transport was loaded
            from mcp_fuzzer.transport import list_custom_transports

            transports = list_custom_transports()
            assert "integration_test" in transports

            # Test creating transport instance
            transport = create_transport("integration_test://test-endpoint")
            assert isinstance(transport, IntegrationTestTransport)
            assert transport.endpoint == "test-endpoint"

        finally:
            # Clean up
            os.unlink(config_path)

    def test_config_file_with_invalid_transport(self):
        """Test handling of invalid transport configuration."""
        config_data = {
            "custom_transports": {
                "invalid_test": {
                    "module": "nonexistent.module",
                    "class": "NonExistentTransport",
                }
            }
        }

        from mcp_fuzzer.config_loader import ConfigFileError

        with pytest.raises(ConfigFileError):
            load_custom_transports(config_data)


class TestCustomTransportLifecycle:
    """Test the complete lifecycle of custom transports."""

    def setup_method(self):
        """Clear any existing custom transports."""
        from mcp_fuzzer.transport.custom import registry

        for name in list(registry.list_transports().keys()):
            registry.unregister(name)

    async def test_full_transport_lifecycle(self):
        """Test complete transport lifecycle from registration to usage."""
        # Register custom transport
        register_custom_transport(
            name="lifecycle_test",
            transport_class=IntegrationTestTransport,
            description="Lifecycle test transport",
        )

        # Create transport instance
        transport = create_transport("lifecycle_test://test-server")

        # Test connection
        await transport.connect()
        assert transport.connected

        # Test request
        result = await transport.send_request("test_method", {"param": "value"})
        assert result["jsonrpc"] == "2.0"
        assert result["result"]["method"] == "test_method"
        assert result["result"]["params"] == {"param": "value"}
        assert result["result"]["transport_type"] == "integration_test"

        # Test raw payload
        raw_result = await transport.send_raw({"test": "data"})
        assert raw_result["result"] == "raw_response"
        assert raw_result["original_payload"] == {"test": "data"}

        # Test notification
        await transport.send_notification("test_notification")  # Should not raise

        # Test streaming
        async for response in transport.stream_request({"stream": "test"}):
            assert response["jsonrpc"] == "2.0"
            assert response["result"]["streamed"] is True
            assert response["result"]["payload"] == {"stream": "test"}
            break  # Only test first response

        # Test tools listing (inherited method)
        # Mock the send_request for tools/list
        original_send_request = transport.send_request

        async def mock_tools_request(method, params=None):
            if method == "tools/list":
                return {"tools": [{"name": "integration_tool"}]}
            return await original_send_request(method, params)

        transport.send_request = mock_tools_request
        try:
            tools = await transport.get_tools()
            assert tools == [{"name": "integration_tool"}]
        finally:
            transport.send_request = original_send_request

        # Test disconnection
        await transport.disconnect()
        assert not transport.connected


class TestCustomTransportErrorHandling:
    """Test error handling in custom transports."""

    def setup_method(self):
        """Clear any existing custom transports."""
        from mcp_fuzzer.transport.custom import registry

        for name in list(registry.list_transports().keys()):
            registry.unregister(name)

    def test_invalid_registration(self):
        """Test error handling for invalid transport registration."""

        class InvalidTransport:
            pass

        with pytest.raises(ValueError, match="must inherit from TransportProtocol"):
            register_custom_transport(name="invalid", transport_class=InvalidTransport)

    def test_duplicate_registration(self):
        """Test error handling for duplicate transport registration."""
        register_custom_transport(
            name="duplicate_test", transport_class=IntegrationTestTransport
        )

        with pytest.raises(ValueError, match="already registered"):
            register_custom_transport(
                name="duplicate_test", transport_class=IntegrationTestTransport
            )

    def test_unknown_transport_creation(self):
        """Test error handling for unknown transport creation."""
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            create_transport("unknown_transport://endpoint")


class TestCustomTransportWithClient:
    """Test custom transports with MCP client integration."""

    def setup_method(self):
        """Clear any existing custom transports."""
        from mcp_fuzzer.transport.custom import registry

        for name in list(registry.list_transports().keys()):
            registry.unregister(name)

    async def test_transport_with_mcp_client(self):
        """Test using custom transport with MCP client."""
        # Register custom transport
        register_custom_transport(
            name="client_test", transport_class=IntegrationTestTransport
        )

        # Create transport
        transport = create_transport("client_test://mcp-server")

        # Import and create MCP client (this would normally be done)
        # This is a simplified test - in real usage, you'd use the full client
        from mcp_fuzzer.client.tool_client import ToolClient

        # Test that the client can be created with custom transport
        client = ToolClient(transport)
        assert client.transport == transport

        # Test basic functionality
        await transport.connect()

        # Test tool calling through transport
        result = await transport.call_tool("test_tool", {"arg": "value"})
        assert "result" in result
