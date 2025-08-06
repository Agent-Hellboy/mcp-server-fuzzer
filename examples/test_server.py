#!/usr/bin/env python3
"""
Simple MCP Test Server for CLI Testing

This server provides basic MCP functionality for testing the fuzzer CLI.
"""

import asyncio
import json
import logging
from typing import Any, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
            }
        ]

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
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
                                "text": f"Test tool called with message: {message}, count: {count}"
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
        # Read request
        data = await reader.read(8192)
        request_text = data.decode()

        # Parse JSON-RPC request
        lines = request_text.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('POST') and not line.startswith('GET'):
                try:
                    request = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        else:
            request = {"method": "tools/list", "id": 1}

        # Handle request
        server = SimpleMCPServer()
        response = await server.handle_request(request)

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
