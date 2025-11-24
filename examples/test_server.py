#!/usr/bin/env python3
"""
Simple MCP Test Server for CLI Testing

This server provides basic MCP functionality for testing the fuzzer CLI.
"""

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


REQUIRED_AUTH_SCHEME = "Bearer"
REQUIRED_TOKEN = "xxx"


class SimpleMCPServer:
    """Simple MCP server for testing."""

    def __init__(self):
        pass

    def _is_authorized(self, headers: Dict[str, str]) -> bool:
        auth = headers.get("Authorization") or headers.get("authorization")
        if not auth:
            return False
        try:
            scheme, token = auth.split(" ", 1)
        except ValueError:
            return False
        return scheme == REQUIRED_AUTH_SCHEME and token == REQUIRED_TOKEN

    def handle_request(
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
                    "tools": [
                        {
                            "name": "test_tool",
                            "description": "A simple test tool",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "message": {"type": "string"},
                                    "count": {"type": "integer"},
                                },
                            },
                        },
                        {
                            "name": "echo_tool",
                            "description": "Echoes back the input",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"text": {"type": "string"}},
                            },
                        },
                        {
                            "name": "secure_tool",
                            "description": "Requires Authorization header",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"msg": {"type": "string"}},
                            },
                        },
                    ]
                },
            }

        elif method == "roots/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "roots": [
                        {
                            "uri": "file:///tmp",
                            "name": "temp"
                        }
                    ]
                }
            }

        elif method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "prompts": []
                }
            }

        elif method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "resources": []
                }
            }

        elif method == "sampling/create":
            messages = params.get("messages", [])
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": {
                        "type": "text",
                        "text": f"Sampling request received with {len(messages)} messages"
                    },
                    "model": "test-model",
                    "stopReason": "endTurn"
                }
            }

        elif method == "logging/setLevel":
            level = params.get("level", "info")
            logger.info(f"Logging level set to: {level}")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {}
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
                    },
                }

            elif tool_name == "echo_tool":
                text = arguments.get("text", "default")
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": f"Echo: {text}"}]},
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
                        "content": [{"type": "text", "text": f"Secure OK: {msg}"}]
                    },
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool '{tool_name}' not found",
                    },
                }

        elif method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "listChanged": True
                        }
                    },
                    "serverInfo": {
                        "name": "Simple Test Server",
                        "version": "1.0.0",
                    },
                },
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found",
                },
            }

class MCPProtocolHandler:
    """Handles MCP protocol communication over HTTP"""

    def __init__(self):
        self.server = SimpleMCPServer()
        self.request_id = 0

    def handle_message(self, message: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Handle incoming MCP messages"""
        try:
            method = message.get("method")
            params = message.get("params", {})
            msg_id = message.get("id")

            # Don't respond to notifications (messages without id)
            if msg_id is None:
                return None

            if method == "initialize":
                return self.handle_initialize(msg_id)
            elif method == "tools/list":
                return self.handle_list_tools(msg_id)
            elif method == "roots/list":
                return self.handle_list_roots(msg_id)
            elif method == "prompts/list":
                return self.handle_list_prompts(msg_id)
            elif method == "resources/list":
                return self.handle_list_resources(msg_id)
            elif method == "sampling/create":
                return self.handle_sampling_create(msg_id, params)
            elif method == "logging/setLevel":
                return self.handle_logging_set_level(msg_id, params)
            elif method == "tools/call":
                return self.handle_call_tool(msg_id, params, headers)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }

        except Exception as e:
            msg_id = message.get("id")
            if msg_id is None:
                return None  # Don't respond to notifications
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }

    def handle_initialize(self, msg_id: Any) -> Dict[str, Any]:
        """Handle initialization request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "tools": {
                        "listChanged": True
                    },
                    "logging": {},
                    "prompts": {},
                    "resources": {
                        "subscribe": False,
                        "listChanged": False
                    },
                    "sampling": {},
                    "roots": {
                        "listChanged": False
                    },
                    "experimental": {
                        "elicitation": {}
                    }
                },
                "serverInfo": {
                    "name": "Simple Test Server",
                    "version": "1.0.0"
                }
            }
        }

    def handle_list_tools(self, msg_id: Any) -> Dict[str, Any]:
        """Handle list tools request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "test_tool",
                        "description": "A simple test tool",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "message": {"type": "string"},
                                "count": {"type": "integer"},
                            },
                        },
                    },
                    {
                        "name": "echo_tool",
                        "description": "Echoes back the input",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                        },
                    },
                    {
                        "name": "secure_tool",
                        "description": "Requires Authorization header",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"msg": {"type": "string"}},
                        },
                    },
                ]
            }
        }

    def handle_call_tool(self, msg_id: Any, params: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Handle tool call request"""
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        if tool_name == "test_tool":
            message = tool_args.get("message", "default")
            count = tool_args.get("count", 1)
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": f"Test tool called with message: {message}, count: {count}"
                    }
                ]
            }

        elif tool_name == "echo_tool":
            text = tool_args.get("text", "default")
            result = {"content": [{"type": "text", "text": f"Echo: {text}"}]}

        elif tool_name == "secure_tool":
            if not self.server._is_authorized(headers):
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32001,
                        "message": "Unauthorized"
                    }
                }
            msg = tool_args.get("msg", "")
            result = {"content": [{"type": "text", "text": f"Secure OK: {msg}"}]}

        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Tool not found: {tool_name}"
                }
            }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result
        }

    def handle_list_roots(self, msg_id: Any) -> Dict[str, Any]:
        """Handle list roots request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "roots": [
                    {
                        "uri": "file:///tmp",
                        "name": "temp"
                    }
                ]
            }
        }

    def handle_list_prompts(self, msg_id: Any) -> Dict[str, Any]:
        """Handle list prompts request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "prompts": []
            }
        }

    def handle_list_resources(self, msg_id: Any) -> Dict[str, Any]:
        """Handle list resources request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "resources": []
            }
        }

    def handle_sampling_create(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle sampling create request"""
        # For a test server, just echo back the messages
        messages = params.get("messages", [])
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": {
                    "type": "text",
                    "text": f"Sampling request received with {len(messages)} messages"
                },
                "model": "test-model",
                "stopReason": "endTurn"
            }
        }

    def handle_logging_set_level(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle logging set level request"""
        level = params.get("level", "info")
        logger.info(f"Logging level set to: {level}")
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {}
        }


class MCPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for MCP server."""

    def __init__(self, *args, **kwargs):
        self.mcp_handler = MCPProtocolHandler()
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Handle GET requests with a simple health check."""
        try:
            if self.path in ['/', '/mcp', '/health', '/mcp/health']:
                health_response = json.dumps({
                    "status": "healthy",
                    "server": "Simple Test Server",
                    "version": "1.0.0",
                    "capabilities": ["tools", "roots", "prompts", "resources", "sampling"]
                })
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Length', len(health_response))
                self.end_headers()
                self.wfile.write(health_response.encode())
            else:
                self.send_error(404, "Not found")
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self.send_error(500, "Internal server error")

    def do_POST(self):
        """Handle POST requests."""
        try:
            # Check if request is to /mcp path (some MCP clients expect this)
            if self.path not in ['/', '/mcp']:
                self.send_error(404, "Not found")
                return

            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length).decode('utf-8')
                try:
                    request = json.loads(body)
                    logger.debug(f"Received request: {request}")
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON: {body}")
                    request = {"method": "tools/list", "id": 1}
            else:
                request = {"method": "tools/list", "id": 1}

            # Get headers as dict
            headers = dict(self.headers)

            # Handle request
            response = self.mcp_handler.handle_message(request, headers)
            if response is not None:
                logger.debug(f"Sending response: {response}")
                response_text = json.dumps(response)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS, GET')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
                self.send_header('Content-Length', len(response_text))
                self.end_headers()
                self.wfile.write(response_text.encode())
            else:
                # Notification or intentionally silent JSON-RPC message: still close HTTP exchange
                self.send_response(204)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS, GET')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
                self.end_headers()

        except Exception as e:
            logger.error(f"Error handling request: {e}")
            msg_id = None
            if 'request' in locals():
                msg_id = request.get("id")

            if msg_id is not None:
                error_content = json.dumps({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": f"Internal error: {str(e)}"
                    }
                })
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS, GET')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
                self.send_header('Content-Length', len(error_content))
                self.end_headers()
                self.wfile.write(error_content.encode())
            else:
                # No JSON-RPC id available (e.g., malformed message): still return HTTP 500
                self.send_response(500)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS, GET')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
                self.end_headers()

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS, GET')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info(f"{self.address_string()} - {format % args}")


def run_server():
    """Start the HTTP server."""
    server_address = ('localhost', 8003)
    httpd = HTTPServer(server_address, MCPRequestHandler)

    logger.info("Test server started on http://localhost:8003")
    logger.info("Available tools: test_tool, echo_tool, secure_tool")
    logger.info("Note: secure_tool requires Bearer token authentication")
    logger.info("Press Ctrl+C to stop")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped")
        httpd.shutdown()


if __name__ == "__main__":
    run_server()
