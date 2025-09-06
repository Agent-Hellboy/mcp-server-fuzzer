# MCP Server Fuzzer Examples

This directory contains runnable examples to try the MCP fuzzer against simple local servers and custom transport implementations.

## Basic Test Server Examples

Run the basic test server
-------------------------

The server listens on http://localhost:8000 and exposes three tools:

- public `test_tool`
- public `echo_tool`
- protected `secure_tool` (requires Authorization: Bearer secret123)

Start the server:

```
python3 examples/test_server.py
```

You should see log lines like:

```
INFO:__main__:Test server started on http://localhost:8000
INFO:__main__:Available tools: test_tool, echo_tool
Press Ctrl+C to stop
```

Fuzz the server (no auth)
------------------------

Call the fuzzer in tools mode:

```
python3 -m mcp_fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 3 --timeout 5
```

This will fuzz all tools. Public tools succeed; `secure_tool` may return Unauthorized unless you provide auth headers.

Fuzz the protected tool with auth (config file)
----------------------------------------------

Use the provided `examples/auth_config.json` which maps `secure_tool` to an API key provider using the token `secret123`.

```
python3 -m mcp_fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 2 --timeout 5 --auth-config examples/auth_config.json
```

Fuzz the protected tool with auth (environment)
-----------------------------------------------

Set environment variables and run the fuzzer:

```
export MCP_API_KEY=secret123
export MCP_TOOL_AUTH_MAPPING='{"secure_tool":"api_key"}'
python3 -m mcp_fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 2 --timeout 5 --auth-env
```

Fuzz protocol types
-------------------

To fuzz protocol types instead of tools:

```
python3 -m mcp_fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 2 --timeout 5
```

Notes
-----

- The example server is intentionally minimal and stateless.
- `secure_tool` requires `Authorization: Bearer secret123`. Use config file or env auth to hit it successfully.
- Stop the server with Ctrl+C.

Streamable HTTP example (no SDK checkout required)
-------------------------------------------------

Install dependencies (one-time):

```
pip install mcp uvicorn anyio starlette
```

Start the example StreamableHTTP server on port 3000:

```
python3 examples/streamable_http_server.py --host 127.0.0.1 --port 3000
```

Then fuzz it with the StreamableHTTP transport:

```
python3 -m mcp_fuzzer --mode tools --protocol streamablehttp --endpoint http://127.0.0.1:3000/mcp --runs 3 --timeout 10 --verbose
```

## Custom Transport Examples

### Overview

Custom transports allow you to extend MCP Server Fuzzer to work with MCP servers that use proprietary protocols, specialized communication patterns, or integration requirements not covered by the built-in transports (HTTP, SSE, STDIO, StreamableHTTP).

### Files in This Directory

- `custom_websocket_transport.py` - Complete WebSocket transport implementation
- `config/custom-transport-config.yaml` - Configuration example showing how to set up custom transports

### Quick Start

#### 1. Implement Your Transport

Create a transport class that inherits from `TransportProtocol`:

```python
from mcp_fuzzer.transport.base import TransportProtocol

class MyCustomTransport(TransportProtocol):
    def __init__(self, endpoint: str, **kwargs):
        # Initialize your transport
        pass

    async def send_request(self, method: str, params=None):
        # Implement JSON-RPC request sending
        pass

    async def send_raw(self, payload):
        # Implement raw payload sending
        pass

    async def send_notification(self, method: str, params=None):
        # Implement notification sending
        pass

    async def _stream_request(self, payload):
        # Implement streaming (yield responses)
        pass
```

#### 2. Register Your Transport

```python
from mcp_fuzzer.transport import register_custom_transport

register_custom_transport(
    name="mytransport",
    transport_class=MyCustomTransport,
    description="My custom transport"
)
```

#### 3. Use Your Transport

```python
from mcp_fuzzer.transport import create_transport

transport = create_transport("mytransport://endpoint")
```

### WebSocket Transport Example

The `custom_websocket_transport.py` file contains a complete WebSocket transport implementation that demonstrates:

- Connection management.
- JSON-RPC request/response handling.
- Error handling and timeouts.
- Streaming support.
- Configuration schema definition.
- Registration with MCP Fuzzer.

#### Running the WebSocket Example

```bash
# Install dependencies
pip install websockets

# Register in your app's process (import triggers registration) then use it
from examples import custom_websocket_transport  # noqa: F401 – ensures registration
from mcp_fuzzer.transport import create_transport
transport = create_transport("websocket://localhost:8080/mcp")
```

### Configuration

See `config/custom-transport-config.yaml` for an example of how to configure custom transports in your MCP Fuzzer configuration files.

### Best Practices

1. **Inherit from TransportProtocol**: Ensure all abstract methods are implemented
2. **Handle Connections Properly**: Implement connect/disconnect for resource management
3. **Use Timeouts**: Always implement appropriate timeouts
4. **Validate Input**: Check method names, parameters, and payloads
5. **Log Operations**: Use logging for debugging and monitoring
6. **Handle Errors**: Provide meaningful error messages
7. **Document Configuration**: Clearly document any configuration options

### Integration with MCP Fuzzer

Custom transports integrate seamlessly with the MCP Fuzzer framework:

- **CLI Support**: Use custom transports with command-line interface
- **Configuration Files**: Configure custom transports via YAML
- **Programmatic API**: Create and use custom transports in Python code
- **Safety System**: Custom transports respect MCP Fuzzer's safety policies
- **Logging**: Integrated with MCP Fuzzer's logging system

### Testing Custom Transports

Test your custom transport thoroughly:

```python
import pytest
from mcp_fuzzer.transport import create_transport

def test_custom_transport():
    transport = create_transport("mytransport://test")
    # Test your transport implementation
```

### Troubleshooting

#### Common Issues

1. **Import Errors**: Ensure your transport module is on the Python path.
2. **Registration Failures**: Verify your class inherits from `TransportProtocol`.
3. **Connection Issues**: Check endpoints and network connectivity.
4. **Configuration Errors**: Validate YAML configuration syntax

#### Debug Logging

Enable debug logging to troubleshoot issues (avoid hardcoding secrets; prefer environment variables):

```bash
export MCP_FUZZER_LOG_LEVEL=DEBUG
```

### Contributing Custom Transports

When contributing custom transport implementations:

1. Follow the established patterns in the codebase
2. Include comprehensive tests
3. Provide clear documentation
4. Handle edge cases and errors gracefully
5. Ensure compatibility with the safety system

### Support

For questions about custom transports:

1. Check the main documentation at `docs/custom-transports.md`
2. Review the WebSocket example for implementation patterns
3. Test with the provided configuration examples
4. Check logs with debug level for detailed information
