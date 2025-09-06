#!/usr/bin/env python3
"""
Example custom WebSocket transport for MCP Server Fuzzer.

This example demonstrates how to implement a custom transport mechanism
that communicates with MCP servers over WebSocket connections.

Usage:
    python custom_websocket_transport.py

Or integrate with MCP Fuzzer:
    from mcp_fuzzer.transport import register_custom_transport
    from custom_websocket_transport import WebSocketTransport

    register_custom_transport(
        name="websocket",
        transport_class=WebSocketTransport,
        description="WebSocket-based MCP transport"
    )
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional, AsyncIterator

try:
    import websockets
except ImportError as e:
    raise ImportError(
        "websockets package is required. Install with: pip install websockets"
    ) from e

from mcp_fuzzer.transport.base import TransportProtocol
from mcp_fuzzer.exceptions import ConnectionError

logger = logging.getLogger(__name__)


class WebSocketTransport(TransportProtocol):
    """
    WebSocket-based transport for MCP communication.

    This transport enables MCP Server Fuzzer to communicate with MCP servers
    over WebSocket connections, useful for real-time applications or
    servers that prefer WebSocket over HTTP.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        """
        Initialize WebSocket transport.

        Args:
            url: WebSocket URL (ws:// or wss://) or a bare endpoint (host[:port]/path)
            timeout: Connection and operation timeout in seconds
            headers: Additional headers to send during WebSocket handshake
            **kwargs: Additional configuration options
        """
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}
        self.websocket = None
        self._request_id = 1
        self._connected = False
        self._lock = asyncio.Lock()

        # Normalize to a valid WebSocket URL:
        # accept ws://, wss://, or a bare endpoint (e.g., "host:port/path").
        if "://" not in self.url:
            self.url = f"ws://{self.url.lstrip('/')}"

        # Set default headers
        if "User-Agent" not in self.headers:
            self.headers["User-Agent"] = "MCP-Fuzzer-WebSocket/1.0"

        logger.info(f"Initialized WebSocket transport for {url}")

    async def connect(self) -> None:
        """Establish WebSocket connection."""
        if self._connected:
            return

        try:
            logger.debug(f"Connecting to WebSocket: {self.url}")
            self.websocket = await asyncio.wait_for(
                websockets.connect(
                    self.url,
                    extra_headers=self.headers,
                    ping_interval=30,  # Keep connection alive
                    ping_timeout=10,
                    close_timeout=5
                ),
                timeout=self.timeout
            )
            self._connected = True
            logger.info(f"Connected to WebSocket: {self.url}")
        except Exception as e:
            logger.error(f"Failed to connect to WebSocket {self.url}: {e}")
            raise ConnectionError(f"WebSocket connection failed: {e}")

    async def disconnect(self) -> None:
        """Close WebSocket connection."""
        if self.websocket and self._connected:
            try:
                await self.websocket.close()
                logger.info(f"Disconnected from WebSocket: {self.url}")
            except Exception as e:
                logger.warning(f"Error during WebSocket disconnect: {e}")
            finally:
                self.websocket = None
                self._connected = False

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Send JSON-RPC request over WebSocket.

        Args:
            method: RPC method name
            params: Method parameters

        Returns:
            JSON-RPC response
        """
        async with self._lock:
            if not self._connected:
                await self.connect()

            request_id = self._request_id
            self._request_id += 1

            payload = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {},
                "id": request_id
            }

            try:
                logger.debug(f"Sending WebSocket request: {method} (id={request_id})")
                await asyncio.wait_for(
                    self.websocket.send(json.dumps(payload)),
                    timeout=self.timeout
                )

                # Receive until matching id; ignore notifications and unrelated messages
                while True:
                    response_text = await asyncio.wait_for(
                        self.websocket.recv(),
                        timeout=self.timeout
                    )
                    response = json.loads(response_text)
                    if isinstance(response, dict) and response.get("id") == request_id:
                        logger.debug(f"Received WebSocket response for {method} (id={request_id})")
                        if "error" in response:
                            error_msg = f"Server error: {response['error']}"
                            logger.error(error_msg)
                            raise Exception(error_msg)
                        return response
                    logger.debug("Ignoring out-of-band WebSocket message: %s", response)

            except asyncio.TimeoutError:
                logger.error(f"WebSocket request timeout for method: {method}")
                raise TimeoutError(f"Request timeout: {method}")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON response: {e}")
                raise ValueError(f"Invalid JSON response: {e}")
            except Exception as e:
                logger.error(f"WebSocket request failed: {e}")
                raise

    async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send raw payload over WebSocket.

        Args:
            payload: Raw payload to send

        Returns:
            Response from server
        """
        async with self._lock:
            if not self._connected:
                await self.connect()

            try:
                logger.debug("Sending raw WebSocket payload")
                await asyncio.wait_for(
                    self.websocket.send(json.dumps(payload)),
                    timeout=self.timeout
                )

                # If this is a notification (no id), do not wait for a response
                req_id = payload.get("id") if isinstance(payload, dict) else None
                if req_id is None:
                    return {}

                # Otherwise, wait for the matching response
                while True:
                    response_text = await asyncio.wait_for(
                        self.websocket.recv(),
                        timeout=self.timeout
                    )
                    response = json.loads(response_text)
                    if isinstance(response, dict) and response.get("id") == req_id:
                        return response
                    logger.debug("Ignoring out-of-band WebSocket message: %s", response)

            except Exception as e:
                logger.error(f"Raw WebSocket send failed: {e}")
                raise

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Send JSON-RPC notification over WebSocket.

        Args:
            method: Notification method name
            params: Notification parameters
        """
        async with self._lock:
            if not self._connected:
                await self.connect()

            payload = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {}
            }

            try:
                logger.debug(f"Sending WebSocket notification: {method}")
                await asyncio.wait_for(
                    self.websocket.send(json.dumps(payload)),
                    timeout=self.timeout
                )
            except Exception as e:
                logger.error(f"WebSocket notification failed: {e}")
                raise

    async def _stream_request(
        self, payload: Dict[str, Any]
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Stream request implementation for WebSocket.

        Args:
            payload: Request payload

        Yields:
            Response chunks
        """
        async with self._lock:
            if not self._connected:
                await self.connect()

            try:
                await asyncio.wait_for(
                    self.websocket.send(json.dumps(payload)),
                    timeout=self.timeout
                )

                while True:
                    try:
                        response_text = await asyncio.wait_for(
                            self.websocket.recv(),
                            timeout=self.timeout
                        )
                        response = json.loads(response_text)
                        req_id = payload.get("id") if isinstance(payload, dict) else None
                        if req_id is None or (isinstance(response, dict) and response.get("id") == req_id):
                            yield response
                        else:
                            logger.debug("Ignoring out-of-band WebSocket message during stream: %s", response)
                    except asyncio.TimeoutError:
                        logger.debug("WebSocket stream timeout")
                        break

            except Exception as e:
                logger.error(f"WebSocket streaming failed: {e}")
                raise


async def demo_websocket_transport():
    """Demonstrate WebSocket transport usage."""
    # Example usage (requires a WebSocket MCP server)
    transport = WebSocketTransport("ws://localhost:8080/mcp")

    try:
        # Connect
        await transport.connect()
        print("Connected to WebSocket MCP server")

        # List tools
        tools = await transport.get_tools()
        print(f"Available tools: {len(tools)}")

        # Call a tool (example)
        if tools:
            tool_name = tools[0]["name"]
            result = await transport.call_tool(tool_name, {})
            print(f"Tool result: {result}")

    except Exception as e:
        print(f"Demo failed: {e}")
    finally:
        await transport.disconnect()


def register_for_mcp_fuzzer():
    """Register this transport with MCP Fuzzer."""
    from mcp_fuzzer.transport import register_custom_transport

    def _factory(first_arg: str, **kwargs):
        s = (first_arg or "").strip()
        # Accept websocket://…, ws://…, wss://…, or bare endpoint
        if s.startswith("websocket://"):
            s = f"ws://{s[len('websocket://'):]}"
        url = s if s.startswith(("ws://", "wss://")) else f"ws://{s.lstrip('/')}"
        return WebSocketTransport(url, **kwargs)

    register_custom_transport(
        name="websocket",
        transport_class=WebSocketTransport,
        description="WebSocket-based MCP transport for real-time communication",
        factory_function=_factory,
        config_schema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "WebSocket URL (ws:// or wss://)"
                },
                "timeout": {
                    "type": "number",
                    "default": 30.0,
                    "description": "Connection timeout in seconds"
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Additional headers for WebSocket handshake"
                }
            },
            "required": ["url"]
        }
    )

    print("WebSocket transport registered with MCP Fuzzer")


if __name__ == "__main__":
    # Register transport
    register_for_mcp_fuzzer()

    # Run demo (uncomment to test with actual WebSocket server)
    # asyncio.run(demo_websocket_transport())

    print("WebSocket transport example loaded successfully!")
    print("Usage in MCP Fuzzer:")
    print("  transport = create_transport('websocket://localhost:8080/mcp')  # custom scheme")
    print("  transport = create_transport('ws://localhost:8080/mcp')        # direct ws URL")
