# Custom Transport Mechanisms

This document describes how to implement and use custom transport mechanisms in MCP Server Fuzzer, addressing [GitHub Issue #9](https://github.com/Agent-Hellboy/mcp-server-fuzzer/issues/9).

## Overview

MCP Server Fuzzer now supports custom transport mechanisms that can be registered and used alongside built-in transports (HTTP, SSE, STDIO, StreamableHTTP). This allows users to implement support for proprietary protocols, specialized communication patterns, or integration with specific MCP server implementations.

## Architecture

The custom transport system consists of:

1. **Transport Registry**: A centralized registry for managing custom transport implementations.
2. **Factory Integration**: Automatic discovery and instantiation of custom transports.
3. **Configuration Support**: Declarative configuration of custom transports via YAML.
4. **Type Safety**: Full type checking and validation for custom transport implementations.

## Implementing a Custom Transport

### 1. Create a Transport Class

Your custom transport must inherit from `TransportProtocol` and implement all required abstract methods:

```python
from mcp_fuzzer.transport.base import TransportProtocol
from typing import Any, Dict, Optional, AsyncIterator
import asyncio

class MyCustomTransport(TransportProtocol):
    def __init__(self, endpoint: str, **kwargs):
        self.endpoint = endpoint
        # Initialize your transport-specific configuration

    async def connect(self) -> None:
        """Establish connection to the transport."""
        # Implement connection logic
        pass

    async def disconnect(self) -> None:
        """Close connection to the transport."""
        # Implement disconnection logic
        pass

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Send a JSON-RPC request and return the result object."""
        # Implement request sending logic
        # Must return the JSON-RPC result (not the full envelope)
        pass

    async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send a raw payload and return the response."""
        # Implement raw payload sending logic
        pass

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        """Send a JSON-RPC notification (fire-and-forget)."""
        # Implement notification sending logic
        pass

    async def close(self) -> None:
        """Close the transport connection."""
        # Cleanup logic
        pass

    async def _stream_request(
        self, payload: Dict[str, Any]
    ) -> AsyncIterator[Dict[str, Any]]:
        """Implement streaming request functionality."""
        # Implement streaming logic
        # Yield response chunks as they arrive
        if False:  # Replace with actual streaming logic
            yield {}
```

### 2. Register Your Transport

Add your custom transport to the configuration file:

```yaml
# config.yaml
custom_transports:
  my-custom:
    module: "my_package.transports"
    class: "MyCustomTransport"
    # Optional: additional init kwargs
    extra_arg: "value"
```

### 3. Use in CLI

Now you can use your custom transport via the CLI:

```bash
mcp-fuzzer --protocol my-custom --config config.yaml --endpoint my-endpoint
```

## Advanced: Self-Registration with Registry

The transport factory now uses a `TransportRegistry` for built-in transports. For custom transports, you can optionally self-register in your module for even easier extension:

```python
# In my_package/transports.py
from mcp_fuzzer.transport.factory import registry

class MyCustomTransport(TransportProtocol):
    # ... implementation ...

# Self-register (runs when module is imported)
registry.register("my-custom", MyCustomTransport)
```

This makes extension simpler – no factory changes needed. The registry is backward-compatible and doesn't affect CLI usage.

Note: Self-registration is optional; config-based registration (step 2) still works and is recommended for most cases.

## Example: WebSocket Transport

Here's a complete example of a WebSocket-based transport implementation:

```python
import asyncio
import json
import websockets
from typing import Any, Dict, Optional, AsyncIterator

from mcp_fuzzer.transport.base import TransportProtocol

class WebSocketTransport(TransportProtocol):
    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
        self.websocket = None
        self._request_id = 1

    async def connect(self) -> None:
        """Establish WebSocket connection."""
        try:
            self.websocket = await websockets.connect(
                self.url,
                extra_headers={"Content-Type": "application/json"}
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.url}: {e}")

    async def disconnect(self) -> None:
        """Close WebSocket connection."""
        if self.websocket:
            await self.websocket.close()
            self.websocket = None

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Send JSON-RPC request over WebSocket."""
        if not self.websocket:
            await self.connect()

        request_id = self._request_id
        self._request_id += 1

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": request_id
        }

        await self.websocket.send(json.dumps(payload))

        # Wait for response
        response_text = await asyncio.wait_for(
            self.websocket.recv(), timeout=self.timeout
        )
        response = json.loads(response_text)

        if "error" in response:
            raise Exception(f"Server error: {response['error']}")

        return response.get("result", {})

    async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send raw payload over WebSocket."""
        if not self.websocket:
            await self.connect()

        await self.websocket.send(json.dumps(payload))

        response_text = await asyncio.wait_for(
            self.websocket.recv(), timeout=self.timeout
        )
        return json.loads(response_text)

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        """Send JSON-RPC notification over WebSocket."""
        if not self.websocket:
            await self.connect()

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {}
        }

        await self.websocket.send(json.dumps(payload))

    async def _stream_request(
        self, payload: Dict[str, Any]
    ) -> AsyncIterator[Dict[str, Any]]:
        """Stream responses over WebSocket."""
        if not self.websocket:
            await self.connect()

        await self.websocket.send(json.dumps(payload))

        try:
            while True:
                response_text = await asyncio.wait_for(
                    self.websocket.recv(), timeout=self.timeout
                )
                response = json.loads(response_text)
                yield response
        except asyncio.TimeoutError:
            return
```

## Configuration Schema

Custom transports can define their own configuration schemas for validation:

```python
config_schema = {
    "type": "object",
    "properties": {
        "url": {"type": "string"},
        "timeout": {"type": "number", "default": 30.0},
        "retries": {"type": "integer", "default": 3},
        "headers": {
            "type": "object",
            "additionalProperties": {"type": "string"}
        }
    },
    "required": ["url"]
}
```

## Error Handling

Custom transports should follow these error handling patterns:

1. **Connection Errors**: Raise `ConnectionError` for connectivity issues
2. **Protocol Errors**: Raise `ValueError` for invalid protocol usage
3. **Server Errors**: Include server error details in raised exceptions
4. **Timeouts**: Use appropriate timeout handling for operations

## Testing Custom Transports

Create unit tests for your custom transport:

```python
import pytest
from mcp_fuzzer.transport import register_custom_transport

def test_custom_transport_registration():
    """Test that custom transport can be registered and used."""
    register_custom_transport(
        name="test_transport",
        transport_class=MyCustomTransport,
        description="Test transport"
    )

    from mcp_fuzzer.transport import create_transport
    transport = create_transport("test_transport://test-endpoint")
    assert isinstance(transport, MyCustomTransport)
```

## Integration with MCP Fuzzer

Custom transports integrate seamlessly with the fuzzing framework:

```python
from mcp_fuzzer.transport import create_transport
from mcp_fuzzer.client import MCPClient

# Create custom transport
transport = create_transport("mytransport://server-endpoint")

# Use with MCP client
client = MCPClient(transport)
tools = await client.list_tools()
```

## Best Practices

1. **Inherit from TransportProtocol**: Ensure your transport implements all required methods
2. **Handle Connections Properly**: Implement connect/disconnect methods for resource management
3. **Use Timeouts**: Always implement appropriate timeouts for operations
4. **Validate Input**: Validate method names, parameters, and payloads
5. **Log Operations**: Use logging to track transport operations for debugging
6. **Handle Errors Gracefully**: Provide meaningful error messages and proper exception handling
7. **Document Configuration**: Clearly document any configuration options your transport accepts

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure your transport module is on the Python path.
2. **Registration Failures**: Check that your transport class inherits from `TransportProtocol`.
3. **Connection Issues**: Verify endpoint URLs and network connectivity.
4. **Configuration Errors**: Validate your YAML configuration against the schema

### Debug Logging

Enable debug logging to troubleshoot transport issues:

```bash
export MCP_FUZZER_LOG_LEVEL=DEBUG
```

This will show detailed logs of transport operations, including custom transport registration and usage.
