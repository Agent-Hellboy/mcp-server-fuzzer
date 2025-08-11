#!/usr/bin/env python3
"""
Unit tests for Transport module
"""

import asyncio
import json
import os
import unittest
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, call, patch

import httpx

from mcp_fuzzer.transport import (
    HTTPTransport,
    SSETransport,
    StdioTransport,
    TransportProtocol,
    create_transport,
)


# Safety check - prevent dangerous tests on production systems
def is_safe_test_environment():
    """Check if we're in a safe environment for running potentially dangerous tests."""
    # Don't run dangerous tests on production systems
    if (
        os.getenv("CI")
        or os.getenv("PRODUCTION")
        or os.getenv("DANGEROUS_TESTS_DISABLED")
    ):
        return False

    # Don't run on systems with critical processes
    try:
        with open("/proc/1/comm", "r") as f:
            init_process = f.read().strip()
            if init_process in ["systemd", "init"]:
                return False
    except (OSError, IOError):
        pass

    # Don't run on systems with systemd
    if os.path.exists("/run/systemd/system"):
        return False

    # Don't run on systems with init
    if os.path.exists("/etc/inittab"):
        return False

    return True


# Skip dangerous tests if not in safe environment
SAFE_ENV = is_safe_test_environment()


# Add safety decorator for dangerous tests
def safe_test_only(func):
    """Decorator to skip dangerous tests on production systems."""

    def wrapper(*args, **kwargs):
        if not SAFE_ENV:
            pytest.skip("Dangerous test skipped on production system")
        return func(*args, **kwargs)

    return wrapper


class TestTransportProtocol(unittest.IsolatedAsyncioTestCase):
    """Test cases for TransportProtocol base class."""

    def setUp(self):
        """Set up test fixtures."""

        # Create a concrete implementation for testing
        class TestTransport(TransportProtocol):
            async def send_request(self, method, params=None):
                return {"result": "test_response"}

            async def send_raw(self, payload):
                return {"result": "test_response"}

            async def send_notification(self, method, params=None):
                return None

        self.transport = TestTransport()

    async def test_get_tools_success(self):
        """Test getting tools successfully."""
        with patch.object(self.transport, "send_request") as mock_send:
            mock_send.return_value = {
                "tools": [
                    {"name": "tool1", "description": "Test tool 1"},
                    {"name": "tool2", "description": "Test tool 2"},
                ]
            }

            tools = await self.transport.get_tools()

            self.assertEqual(len(tools), 2)
            self.assertEqual(tools[0]["name"], "tool1")
            self.assertEqual(tools[1]["name"], "tool2")
            mock_send.assert_called_with("tools/list")

    async def test_get_tools_no_tools_key(self):
        """Test getting tools when response doesn't have tools key."""
        with patch.object(self.transport, "send_request") as mock_send:
            mock_send.return_value = {"result": "success"}

            tools = await self.transport.get_tools()

            self.assertEqual(tools, [])

    async def test_get_tools_non_dict_response(self):
        """Test getting tools when response is not a dictionary."""
        with patch.object(self.transport, "send_request") as mock_send:
            mock_send.return_value = "not_a_dict"

            tools = await self.transport.get_tools()

            self.assertEqual(tools, [])

    async def test_get_tools_exception(self):
        """Test getting tools with exception."""
        with patch.object(self.transport, "send_request") as mock_send:
            mock_send.side_effect = Exception("Test exception")

            tools = await self.transport.get_tools()

            self.assertEqual(tools, [])

    async def test_call_tool(self):
        """Test calling a tool."""
        with patch.object(self.transport, "send_request") as mock_send:
            mock_send.return_value = {"result": "tool_result"}

            result = await self.transport.call_tool("test_tool", {"param1": "value1"})

            self.assertEqual(result, {"result": "tool_result"})
            mock_send.assert_called_with(
                "tools/call", {"name": "test_tool", "arguments": {"param1": "value1"}}
            )


class TestHTTPTransport(unittest.IsolatedAsyncioTestCase):
    """Test cases for HTTPTransport class."""

    def setUp(self):
        """Set up test fixtures."""
        self.transport = HTTPTransport("http://localhost:8000", timeout=30.0)

    def test_init(self):
        """Test HTTPTransport initialization."""
        self.assertEqual(self.transport.url, "http://localhost:8000")
        self.assertEqual(self.transport.timeout, 30.0)
        self.assertIn("Accept", self.transport.headers)
        self.assertIn("Content-Type", self.transport.headers)

    def test_init_with_auth_headers(self):
        """Test HTTPTransport initialization with auth headers."""
        auth_headers = {"Authorization": "Bearer token"}
        transport = HTTPTransport("http://localhost:8000", auth_headers=auth_headers)

        self.assertIn("Authorization", transport.headers)
        self.assertEqual(transport.headers["Authorization"], "Bearer token")

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_success(self, mock_client_class):
        """Test successful HTTP request."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = None

        mock_response = MagicMock()
        mock_response.json.return_value = {"result": "success", "id": "test_id"}
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response

        result = await self.transport.send_request("test_method", {"param": "value"})

        self.assertEqual(result, "success")

        # Verify the request was made correctly
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        self.assertEqual(call_args[0][0], "http://localhost:8000")

        # Check the JSON payload
        json_data = call_args[1]["json"]
        self.assertEqual(json_data["jsonrpc"], "2.0")
        self.assertEqual(json_data["method"], "test_method")
        self.assertEqual(json_data["params"], {"param": "value"})
        self.assertIn("id", json_data)

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_sse_response(self, mock_client_class):
        """Test HTTP request with SSE response."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = None

        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.text = 'data: {"result": "sse_success"}\n\n'
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response

        result = await self.transport.send_request("test_method")

        # Should return the SSE data
        self.assertEqual(result, "sse_success")

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_http_error(self, mock_client_class):
        """Test HTTP request with HTTP error."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = None

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found", request=MagicMock(), response=mock_response
        )
        mock_client.post.return_value = mock_response

        with self.assertRaises(httpx.HTTPStatusError):
            await self.transport.send_request("test_method")

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_connection_error(self, mock_client_class):
        """Test HTTP request with connection error."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client

        mock_client.post.side_effect = httpx.ConnectError("Connection failed")

        with self.assertRaises(httpx.ConnectError):
            await self.transport.send_request("test_method")

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_json_decode_error(self, mock_client_class):
        """Test send_request with JSON decode error."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.text = 'data: {"result": "success"}\n'
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client

        result = await self.transport.send_request("test_method")

        self.assertEqual(result, "success")

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_sse_no_data_line(self, mock_client_class):
        """Test send_request with SSE response but no data line."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.text = "event: message\n\n"  # No data line
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client

        with self.assertRaises(Exception):
            await self.transport.send_request("test_method")

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_sse_invalid_data(self, mock_client_class):
        """Test send_request with SSE response but invalid data."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.text = "data: invalid json\n"
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client

        with self.assertRaises(Exception):
            await self.transport.send_request("test_method")

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_server_error(self, mock_client_class):
        """Test send_request with server error response."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "error": {"code": -32603, "message": "Internal error"}
        }
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client

        with self.assertRaises(Exception):
            await self.transport.send_request("test_method")

    @patch("mcp_fuzzer.transport.http.httpx.AsyncClient")
    async def test_send_request_no_result_key(self, mock_client_class):
        """Test send_request with response that has no result key."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": "test_data"}
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client

        result = await self.transport.send_request("test_method")

        self.assertEqual(result, {"data": "test_data"})


class TestSSETransport(unittest.IsolatedAsyncioTestCase):
    """Test cases for SSETransport class."""

    def setUp(self):
        """Set up test fixtures."""
        self.transport = SSETransport("http://localhost:8000", timeout=30.0)

    def test_init(self):
        """Test SSETransport initialization."""
        self.assertEqual(self.transport.url, "http://localhost:8000")
        self.assertEqual(self.transport.timeout, 30.0)

    @patch("mcp_fuzzer.transport.sse.httpx.AsyncClient")
    async def test_send_request_sse(self, mock_client_class):
        """Test SSE request."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = None

        mock_response = MagicMock()
        mock_response.text = 'data: {"result": "sse_success"}\n\n'
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response

        result = await self.transport.send_request("test_method", {"param": "value"})

        # Should return the result value from SSE data
        self.assertEqual(result, "sse_success")

    @patch("mcp_fuzzer.transport.sse.httpx.AsyncClient")
    async def test_send_request_sse_error_response(self, mock_client_class):
        """Test SSE request with error response."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = None

        mock_response = MagicMock()
        mock_response.text = (
            'data: {"error": {"code": -32603, "message": "Internal error"}}\n\n'
        )
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response

        with self.assertRaises(Exception) as context:
            await self.transport.send_request("test_method")

        self.assertIn("Server error", str(context.exception))

    @patch("mcp_fuzzer.transport.sse.httpx.AsyncClient")
    async def test_send_request_sse_no_valid_response(self, mock_client_class):
        """Test SSE request with no valid response."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = None

        mock_response = MagicMock()
        mock_response.text = "event: message\n\n"  # No data line
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response

        with self.assertRaises(Exception) as context:
            await self.transport.send_request("test_method")

        self.assertIn("No valid SSE response", str(context.exception))


class TestStdioTransport(unittest.IsolatedAsyncioTestCase):
    """Test cases for StdioTransport class."""

    def setUp(self):
        """Set up test fixtures."""
        self.transport = StdioTransport("python test_server.py", timeout=30.0)

    def test_init(self):
        """Test StdioTransport initialization."""
        self.assertEqual(self.transport.command, "python test_server.py")
        self.assertEqual(self.transport.timeout, 30.0)

    @safe_test_only
    @patch("mcp_fuzzer.transport.stdio.asyncio.create_subprocess_exec")
    @patch("mcp_fuzzer.transport.stdio.asyncio.wait_for")
    async def test_send_request_stdio(self, mock_wait_for, mock_create_subprocess):
        """Test stdio request."""
        mock_process = AsyncMock()
        mock_process.returncode = 0

        mock_create_subprocess.return_value = mock_process
        mock_wait_for.return_value = (b'{"result": "stdio_success"}', b"")

        result = await self.transport.send_request("test_method", {"param": "value"})

        self.assertEqual(result, "stdio_success")
        mock_create_subprocess.assert_called()
        mock_wait_for.assert_called()

    @safe_test_only
    @patch("mcp_fuzzer.transport.stdio.asyncio.create_subprocess_exec")
    @patch("mcp_fuzzer.transport.stdio.asyncio.wait_for")
    async def test_send_request_stdio_timeout(
        self, mock_wait_for, mock_create_subprocess
    ):
        """Test stdio request with timeout."""
        mock_process = AsyncMock()
        mock_create_subprocess.return_value = mock_process
        mock_wait_for.side_effect = asyncio.TimeoutError()

        with self.assertRaises(asyncio.TimeoutError):
            await self.transport.send_request("test_method")

    @safe_test_only
    @patch("mcp_fuzzer.transport.stdio.asyncio.create_subprocess_exec")
    @patch("mcp_fuzzer.transport.stdio.asyncio.wait_for")
    async def test_send_request_stdio_process_failure(
        self, mock_wait_for, mock_create_subprocess
    ):
        """Test stdio request with process failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1

        mock_create_subprocess.return_value = mock_process
        mock_wait_for.return_value = (b"", b"Process failed")

        with self.assertRaises(Exception) as context:
            await self.transport.send_request("test_method")

        self.assertIn("Process failed", str(context.exception))

    @safe_test_only
    @patch("mcp_fuzzer.transport.stdio.asyncio.create_subprocess_exec")
    @patch("mcp_fuzzer.transport.stdio.asyncio.wait_for")
    async def test_send_request_stdio_error_response(
        self, mock_wait_for, mock_create_subprocess
    ):
        """Test stdio request with error response."""
        mock_process = AsyncMock()
        mock_process.returncode = 0

        mock_create_subprocess.return_value = mock_process
        response_data = b'{"error": {"code": -32603, "message": "Internal error"}}\n'
        mock_wait_for.return_value = (response_data, b"")

        with self.assertRaises(Exception) as context:
            await self.transport.send_request("test_method")

        self.assertIn("Server error", str(context.exception))


class TestCreateTransport(unittest.TestCase):
    """Test cases for create_transport function."""

    def test_create_transport_http(self):
        """Test creating HTTP transport."""
        transport = create_transport("http", "http://localhost:8000", timeout=30.0)

        self.assertIsInstance(transport, HTTPTransport)
        self.assertEqual(transport.url, "http://localhost:8000")
        self.assertEqual(transport.timeout, 30.0)

    def test_create_transport_sse(self):
        """Test creating SSE transport."""
        transport = create_transport("sse", "http://localhost:8000", timeout=30.0)

        self.assertIsInstance(transport, SSETransport)
        self.assertEqual(transport.url, "http://localhost:8000")
        self.assertEqual(transport.timeout, 30.0)

    def test_create_transport_stdio(self):
        """Test creating stdio transport."""
        transport = create_transport("stdio", "python test_server.py", timeout=30.0)

        self.assertIsInstance(transport, StdioTransport)
        self.assertEqual(transport.command, "python test_server.py")
        self.assertEqual(transport.timeout, 30.0)

    def test_create_transport_invalid_protocol(self):
        """Test creating transport with invalid protocol."""
        with self.assertRaises(ValueError) as context:
            create_transport("invalid", "http://localhost:8000")

        self.assertIn("Unsupported protocol", str(context.exception))

    def test_create_transport_with_auth_headers(self):
        """Test creating transport with auth headers."""
        auth_headers = {"Authorization": "Bearer token"}
        transport = create_transport(
            "http", "http://localhost:8000", auth_headers=auth_headers
        )

        self.assertIsInstance(transport, HTTPTransport)
        self.assertIn("Authorization", transport.headers)
        self.assertEqual(transport.headers["Authorization"], "Bearer token")


class TestTransportIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration tests for transport modules."""

    async def test_transport_protocol_interface(self):
        """Test that all transport classes implement the protocol interface."""
        transports = [
            HTTPTransport("http://localhost:8000"),
            SSETransport("http://localhost:8000"),
            StdioTransport("python test_server.py"),
        ]

        for transport in transports:
            # Test that they have the required methods
            self.assertTrue(hasattr(transport, "send_request"))
            self.assertTrue(hasattr(transport, "get_tools"))
            self.assertTrue(hasattr(transport, "call_tool"))

            # Test that send_request is callable
            self.assertTrue(callable(transport.send_request))

    def test_transport_protocol_abstract_methods(self):
        """Test that TransportProtocol is properly abstract."""
        # Should not be able to instantiate TransportProtocol directly
        with self.assertRaises(TypeError):
            TransportProtocol()


if __name__ == "__main__":
    unittest.main()
