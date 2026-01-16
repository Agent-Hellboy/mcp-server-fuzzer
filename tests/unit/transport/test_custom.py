"""Tests for custom transport mechanisms."""

import pytest
from unittest.mock import Mock
from typing import Any, Dict, Optional, AsyncIterator

from mcp_fuzzer.transport.interfaces import TransportDriver, JsonRpcAdapter
from mcp_fuzzer.transport.catalog import (
    DriverCatalog,
    build_driver,
    driver_catalog,
    register_custom_driver,
    build_custom_driver,
    list_custom_drivers,
    clear_custom_drivers,
)
from mcp_fuzzer.exceptions import ConnectionError, TransportRegistrationError


class MockTransport(TransportDriver):
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


class TestDriverCatalog:
    """Test the driver catalog registry functionality."""

    def setup_method(self):
        clear_custom_drivers()

    def test_registry_initialization(self):
        """Test that registry initializes correctly."""
        registry = DriverCatalog()
        assert registry.list_transports() == {}

    def test_register_transport(self):
        """Test registering a custom transport."""
        registry = DriverCatalog()

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
        registry = DriverCatalog()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        with pytest.raises(
            TransportRegistrationError,
            match="Transport 'mock_transport' is already registered",
        ):
            registry.register(
                name="mock_transport",
                transport_class=MockTransport,
                description="Duplicate transport",
            )

    def test_register_invalid_transport_class(self):
        """Test that registering an invalid transport class raises an error."""
        registry = DriverCatalog()

        class InvalidTransport:
            pass

        with pytest.raises(
            TransportRegistrationError,
            match="Transport class .* must inherit from TransportDriver",
        ):
            registry.register(
                name="invalid_transport",
                transport_class=InvalidTransport,
                description="Invalid transport",
            )

    def test_unregister_transport(self):
        """Test unregistering a custom transport."""
        registry = DriverCatalog()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        registry.unregister("mock_transport")
        assert registry.list_transports() == {}

    def test_unregister_nonexistent_transport(self):
        """Test that unregistering a non-existent transport raises an error."""
        registry = DriverCatalog()

        with pytest.raises(
            TransportRegistrationError,
            match="Transport 'nonexistent' is not registered",
        ):
            registry.unregister("nonexistent")

    def test_get_transport_class(self):
        """Test getting transport class from registry."""
        registry = DriverCatalog()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        transport_class = registry.get_transport_class("mock_transport")
        assert transport_class == MockTransport

    def test_get_transport_info(self):
        """Test getting transport info from registry."""
        registry = DriverCatalog()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        info = registry.get_transport_info("mock_transport")
        assert info["class"] == MockTransport
        assert info["description"] == "Mock transport for testing"

    def test_build_driver(self):
        """Test creating transport instance from registry."""
        registry = DriverCatalog()

        registry.register(
            name="mock_transport",
            transport_class=MockTransport,
            description="Mock transport for testing",
        )

        transport = registry.build_driver("mock_transport", "test-endpoint", timeout=30)
        assert isinstance(transport, MockTransport)
        assert transport.endpoint == "test-endpoint"
        assert transport.kwargs == {"timeout": 30}


class TestCustomTransportFunctions:
    """Test the global custom transport functions."""

    def setup_method(self):
        """Clear the global registry before each test."""
        clear_custom_drivers()

    def test_register_custom_driver(self):
        """Test the global register_custom_driver function."""
        register_custom_driver(
            name="global_mock",
            transport_class=MockTransport,
            description="Global mock transport",
        )

        transports = list_custom_drivers()
        assert "global_mock" in transports

    def test_build_custom_driver(self):
        """Test the global build_custom_driver function."""
        register_custom_driver(
            name="global_mock",
            transport_class=MockTransport,
            description="Global mock transport",
        )

        transport = build_custom_driver("global_mock", "test-endpoint")
        assert isinstance(transport, MockTransport)
        assert transport.endpoint == "test-endpoint"


class TestTransportFactoryIntegration:
    """Test integration with the transport factory."""

    def setup_method(self):
        """Clear the global registry before each test."""
        clear_custom_drivers()

    def test_custom_transport_via_factory(self):
        """Test creating custom transport via factory."""
        register_custom_driver(
            name="factory_mock",
            transport_class=MockTransport,
            description="Factory mock transport",
        )

        transport = build_driver("factory_mock://test-endpoint")
        assert isinstance(transport, MockTransport)
        assert transport.endpoint == "test-endpoint"

    def test_custom_transport_via_factory_two_args(self):
        """Back-compat: (protocol, endpoint) for custom transports."""
        register_custom_driver(
            name="factory_mock",
            transport_class=MockTransport,
            description="Factory mock transport",
        )
        transport = build_driver("factory_mock", "test-endpoint")
        assert isinstance(transport, MockTransport)
        assert transport.endpoint == "test-endpoint"

    def test_unknown_custom_transport(self):
        """Test that unknown custom transport raises error."""
        with pytest.raises(
            TransportRegistrationError, match="Unsupported transport scheme"
        ):
            build_driver("unknown://test-endpoint")

    def test_custom_transport_with_config_schema(self):
        """Test custom transport with configuration schema."""
        schema = {
            "type": "object",
            "properties": {
                "timeout": {"type": "number"},
            },
        }

        register_custom_driver(
            name="schema_mock",
            transport_class=MockTransport,
            description="Schema mock transport",
            config_schema=schema,
        )

        transports = list_custom_drivers()
        assert "schema_mock" in transports
        assert transports["schema_mock"]["config_schema"] == schema


class TestTransportDriverCompliance:
    """Test that custom transports comply with TransportDriver."""

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
        rpc_helper = JsonRpcAdapter(transport)

        try:
            tools = await rpc_helper.get_tools()
            assert tools == [{"name": "test_tool"}]
        finally:
            transport.send_request = original_send_request


class TestCustomTransportCloseMethod:
    """Test that custom transports can implement and have their close method invoked."""

    class CloseableTransport(TransportDriver):
        """Mock transport that tracks close() calls."""

        def __init__(self, endpoint: str, **kwargs):
            self.endpoint = endpoint
            self.kwargs = kwargs
            self.close_called = False
            self.connection_active = True

        async def send_request(
            self, method: str, params: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
            if not self.connection_active:
                raise ConnectionError("Transport is closed")
            return {"result": f"response_{method}"}

        async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
            if not self.connection_active:
                raise ConnectionError("Transport is closed")
            return {"result": "raw_response"}

        async def send_notification(
            self, method: str, params: Optional[Dict[str, Any]] = None
        ) -> None:
            if not self.connection_active:
                raise ConnectionError("Transport is closed")

        async def _stream_request(
            self, payload: Dict[str, Any]
        ) -> AsyncIterator[Dict[str, Any]]:
            if not self.connection_active:
                raise ConnectionError("Transport is closed")
            yield {"result": "stream_response"}

        async def close(self) -> None:
            """Custom close implementation that tracks invocation."""
            self.close_called = True
            self.connection_active = False

    async def test_custom_transport_close_method_invoked(self):
        """Test that custom transport's close method is correctly invoked."""
        transport = self.CloseableTransport("test-endpoint")

        # Verify transport is initially active
        assert transport.connection_active is True
        assert transport.close_called is False

        # Test that transport works before close
        result = await transport.send_request("test_method")
        assert result == {"result": "response_test_method"}

        # Close the transport
        await transport.close()

        # Verify close was called and state changed
        assert transport.close_called is True
        assert transport.connection_active is False

        # Verify transport raises error after close
        with pytest.raises(ConnectionError, match="Transport is closed"):
            await transport.send_request("test_method")

    async def test_custom_transport_close_with_resources(self):
        """Test that custom transport can clean up resources in close method."""

        class ResourceManagedTransport(TransportDriver):
            """Transport that manages resources."""

            def __init__(self, endpoint: str):
                self.endpoint = endpoint
                self.resources = ["resource1", "resource2", "resource3"]
                self.closed = False

            async def send_request(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> Dict[str, Any]:
                return {"result": "ok"}

            async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
                return {"result": "ok"}

            async def send_notification(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> None:
                pass

            async def _stream_request(
                self, payload: Dict[str, Any]
            ) -> AsyncIterator[Dict[str, Any]]:
                yield {"result": "ok"}

            async def close(self) -> None:
                """Clean up resources on close."""
                self.resources.clear()
                self.closed = True

        transport = ResourceManagedTransport("test-endpoint")

        # Verify resources exist initially
        assert len(transport.resources) == 3
        assert transport.closed is False

        # Close transport
        await transport.close()

        # Verify resources were cleaned up
        assert len(transport.resources) == 0
        assert transport.closed is True


class TestCustomTransportSelfRegistration:
    """Test that custom transports can self-register using registry.register."""

    def setup_method(self):
        """Clear the global registry before each test."""
        clear_custom_drivers()

    def test_self_registration_with_registry(self):
        """Test that custom transport can self-register using registry.register."""
        registry = driver_catalog

        class SelfRegisteringTransport(TransportDriver):
            """Transport that self-registers on import."""

            def __init__(self, endpoint: str, **kwargs):
                self.endpoint = endpoint
                self.kwargs = kwargs

            async def send_request(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> Dict[str, Any]:
                return {"result": f"self_registered_{method}"}

            async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
                return {"result": "self_registered_raw"}

            async def send_notification(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> None:
                pass

            async def _stream_request(
                self, payload: Dict[str, Any]
            ) -> AsyncIterator[Dict[str, Any]]:
                yield {"result": "self_registered_stream"}

        # Self-register the transport
        registry.register(
            "self_registered",
            SelfRegisteringTransport,
            description="Self-registered transport",
            is_custom=True,
        )

        # Verify it was registered
        transports = registry.list_transports()
        assert "self_registered" in transports
        assert transports["self_registered"]["class"] == SelfRegisteringTransport
        assert (
            transports["self_registered"]["description"] == "Self-registered transport"
        )

    def test_self_registration_at_module_level(self):
        """Test self-registration pattern at module level."""
        registry = driver_catalog

        # Simulate module-level registration
        class ModuleLevelTransport(TransportDriver):
            """Transport registered at module level."""

            def __init__(self, endpoint: str):
                self.endpoint = endpoint

            async def send_request(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> Dict[str, Any]:
                return {"result": "module_level"}

            async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
                return {"result": "module_level"}

            async def send_notification(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> None:
                pass

            async def _stream_request(
                self, payload: Dict[str, Any]
            ) -> AsyncIterator[Dict[str, Any]]:
                yield {"result": "module_level"}

        # This would typically happen at module import time
        registry.register("module_level", ModuleLevelTransport, is_custom=True)

        # Verify registration succeeded
        transport_class = registry.get_transport_class("module_level")
        assert transport_class == ModuleLevelTransport

    def test_self_registration_with_schema(self):
        """Test self-registration with configuration schema."""
        registry = driver_catalog

        class ConfigurableTransport(TransportDriver):
            """Transport with configuration schema."""

            def __init__(self, endpoint: str, timeout: float = 30.0):
                self.endpoint = endpoint
                self.timeout = timeout

            async def send_request(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> Dict[str, Any]:
                return {"result": "configured"}

            async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
                return {"result": "configured"}

            async def send_notification(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> None:
                pass

            async def _stream_request(
                self, payload: Dict[str, Any]
            ) -> AsyncIterator[Dict[str, Any]]:
                yield {"result": "configured"}

        # Self-register with schema
        config_schema = {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "timeout": {"type": "number", "default": 30.0},
            },
            "required": ["endpoint"],
        }

        registry.register(
            "configurable",
            ConfigurableTransport,
            description="Transport with configuration",
            config_schema=config_schema,
            is_custom=True,
        )

        # Verify registration with schema
        info = registry.get_transport_info("configurable")
        assert info["config_schema"] == config_schema


class TestSelfRegisteredTransportInstantiation:
    """Test that self-registered custom transports can be instantiated and used."""

    def setup_method(self):
        """Clear the global registry before each test."""
        clear_custom_drivers()

    async def test_instantiate_self_registered_transport(self):
        """Test that self-registered transport can be instantiated and used."""
        registry = driver_catalog

        class UsableTransport(TransportDriver):
            """Fully functional self-registered transport."""

            def __init__(self, endpoint: str, **kwargs):
                self.endpoint = endpoint
                self.kwargs = kwargs
                self.request_count = 0

            async def send_request(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> Dict[str, Any]:
                self.request_count += 1
                return {
                    "result": {
                        "method": method,
                        "params": params,
                        "endpoint": self.endpoint,
                        "count": self.request_count,
                    }
                }

            async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
                return {"result": "raw", "payload": payload}

            async def send_notification(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> None:
                self.request_count += 1

            async def _stream_request(
                self, payload: Dict[str, Any]
            ) -> AsyncIterator[Dict[str, Any]]:
                for i in range(3):
                    yield {"chunk": i, "payload": payload}

        # Self-register
        registry.register(
            "usable", UsableTransport, description="Usable transport", is_custom=True
        )

        # Instantiate via registry
        transport = registry.build_driver("usable", "test-server", timeout=60)

        # Verify instantiation
        assert isinstance(transport, UsableTransport)
        assert transport.endpoint == "test-server"
        assert transport.kwargs == {"timeout": 60}

        # Use the transport
        result = await transport.send_request("test_method", {"arg": "value"})
        assert result["result"]["method"] == "test_method"
        assert result["result"]["params"] == {"arg": "value"}
        assert result["result"]["endpoint"] == "test-server"
        assert result["result"]["count"] == 1

        # Test raw request
        raw_result = await transport.send_raw({"raw": "data"})
        assert raw_result["result"] == "raw"
        assert raw_result["payload"] == {"raw": "data"}

        # Test notification
        await transport.send_notification("notify")
        assert transport.request_count == 2

        # Test streaming
        chunks = []
        async for chunk in transport.stream_request({"stream": "test"}):
            chunks.append(chunk)
        assert len(chunks) == 3
        assert chunks[0]["chunk"] == 0
        assert chunks[2]["chunk"] == 2

    async def test_instantiate_via_factory(self):
        """Test that self-registered transport can be instantiated via factory."""
        registry = driver_catalog

        class FactoryUsableTransport(TransportDriver):
            """Transport usable via factory."""

            def __init__(self, endpoint: str):
                self.endpoint = endpoint

            async def send_request(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> Dict[str, Any]:
                return {"result": f"factory_{method}"}

            async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
                return {"result": "factory_raw"}

            async def send_notification(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> None:
                pass

            async def _stream_request(
                self, payload: Dict[str, Any]
            ) -> AsyncIterator[Dict[str, Any]]:
                yield {"result": "factory_stream"}

        # Self-register
        registry.register(
            "factory_usable",
            FactoryUsableTransport,
            description="Factory usable",
            is_custom=True,
        )

        # Instantiate via factory using URL format
        transport = build_driver("factory_usable://my-endpoint")

        # Verify it works
        assert isinstance(transport, FactoryUsableTransport)
        assert transport.endpoint == "my-endpoint"

        # Test functionality
        result = await transport.send_request("ping")
        assert result == {"result": "factory_ping"}

    async def test_instantiate_with_custom_factory(self):
        """Test instantiation with custom factory function."""
        registry = driver_catalog

        class FactoryManagedTransport(TransportDriver):
            """Transport created via factory function."""

            def __init__(self, endpoint: str, custom_arg: str):
                self.endpoint = endpoint
                self.custom_arg = custom_arg

            async def send_request(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> Dict[str, Any]:
                return {"result": self.custom_arg}

            async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
                return {"result": self.custom_arg}

            async def send_notification(
                self, method: str, params: Optional[Dict[str, Any]] = None
            ) -> None:
                pass

            async def _stream_request(
                self, payload: Dict[str, Any]
            ) -> AsyncIterator[Dict[str, Any]]:
                yield {"result": self.custom_arg}

        # Custom factory function
        def custom_factory(url_or_endpoint: str, **kwargs):
            # Parse URL or use as-is
            if "://" in url_or_endpoint:
                endpoint = url_or_endpoint.split("://", 1)[1]
            else:
                endpoint = url_or_endpoint
            return FactoryManagedTransport(
                endpoint, custom_arg=kwargs.get("custom_arg", "default")
            )

        # Register with factory
        registry.register(
            "factory_managed",
            FactoryManagedTransport,
            factory_function=custom_factory,
            is_custom=True,
        )

        # Instantiate via registry with factory
        transport = registry.build_driver(
            "factory_managed", "test-endpoint", custom_arg="custom_value"
        )

        assert isinstance(transport, FactoryManagedTransport)
        assert transport.endpoint == "test-endpoint"
        assert transport.custom_arg == "custom_value"

        # Test functionality
        result = await transport.send_request("test")
        assert result == {"result": "custom_value"}
