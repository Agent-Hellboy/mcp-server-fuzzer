#!/usr/bin/env python3
"""
Simple MCP Test Server for CLI Testing

This server provides basic MCP functionality for testing the fuzzer CLI.
"""

import asyncio
import json
import logging
from typing import Any, Dict, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


REQUIRED_AUTH_SCHEME = "Bearer"
REQUIRED_TOKEN = "secret123"


def parse_http_request(raw: str) -> Tuple[Dict[str, str], str]:
    """Parse minimal HTTP request headers and body from raw request text."""
    header_section, _, body = raw.partition("\r\n\r\n")
    if not body:
        header_section, _, body = raw.partition("\n\n")

    header_lines = header_section.splitlines()
    headers: Dict[str, str] = {}
    # Skip request line
    for line in header_lines[1:]:
        if not line.strip():
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers, body


class SimpleMCPServer:
    """Simple MCP server for testing."""

    def __init__(self):
        self.tools = [
            {
                "name": "test_tool",
                "description": "A simple test tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string"},
                        "count": {"type": "integer"}
                    }
                }
            },
            {
                "name": "echo_tool",
                "description": "Echoes back the input",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"}
                    }
                }
            },
            {
                "name": "secure_tool",
                "description": "Requires Authorization header",
                "inputSchema": {
                    "type": "object",
                    "properties": {"msg": {"type": "string"}},
                },
            }
        ]

    def _is_authorized(self, headers: Dict[str, str]) -> bool:
        auth = headers.get("Authorization") or headers.get("authorization")
        if not auth:
            return False
        try:
            scheme, token = auth.split(" ", 1)
        except ValueError:
            return False
        return scheme == REQUIRED_AUTH_SCHEME and token == REQUIRED_TOKEN

    async def handle_request(
        self, request: Dict[str, Any], headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """Handle incoming JSON-RPC requests."""
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")

        logger.info(f"Handling request: {method}")

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": self.tools
                }
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if tool_name == "test_tool":
                message = arguments.get("message", "default")
                count = arguments.get("count", 1)
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"Test tool called with message: {message}, "
                                    f"count: {count}"
                                ),
                            }
                        ]
                    }
                }

            elif tool_name == "echo_tool":
                text = arguments.get("text", "default")
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Echo: {text}"
                            }
                        ]
                    }
                }

            elif tool_name == "secure_tool":
                if not self._is_authorized(headers):
                    return {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32001, "message": "Unauthorized"},
                    }
                msg = arguments.get("msg", "")
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": f"Secure OK: {msg}"}
                        ]
                    },
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method '{tool_name}' not found"
                    }
                }

        elif method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True}
                    },
                    "serverInfo": {
                        "name": "Simple Test Server",
                        "version": "1.0.0"
                    }
                }
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found"
                }
            }


async def handle_http_request(reader, writer):
    """Handle HTTP requests."""
    try:
        data = await reader.read(1 << 20)
        request_text = data.decode(errors="ignore")
        headers, body = parse_http_request(request_text)

        # Extract JSON payload from body or default to tools/list
        try:
            request = (
                json.loads(body.strip())
                if body.strip()
                else {
                    "method": "tools/list",
                    "id": 1,
                }
            )
        except json.JSONDecodeError:
            request = {"method": "tools/list", "id": 1}

        # Handle request
        server = SimpleMCPServer()
        response = await server.handle_request(request, headers)

        # Send response
        response_text = json.dumps(response)
        http_response = f"""HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: {len(response_text)}

{response_text}"""

        writer.write(http_response.encode())
        await writer.drain()

    except Exception as e:
        logger.error(f"Error handling request: {e}")
        error_response = f"""HTTP/1.1 500 Internal Server Error
Content-Type: application/json
Content-Length: 50

{{"error": "Internal server error: {str(e)}"}}"""

        writer.write(error_response.encode())
        await writer.drain()

    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    """Start the test server."""
    server = await asyncio.start_server(
        handle_http_request,
        'localhost',
        8000
    )

    logger.info("Test server started on http://localhost:8000")
    logger.info("Available tools: test_tool, echo_tool")
    logger.info("Press Ctrl+C to stop")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped")
