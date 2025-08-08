#!/usr/bin/env python3
"""
Unit tests for Client module
"""

import asyncio
import json
import traceback
import unittest
from unittest.mock import AsyncMock, MagicMock, call, patch

from mcp_fuzzer.auth import AuthManager
from mcp_fuzzer.client import UnifiedMCPFuzzerClient


class TestUnifiedMCPFuzzerClient(unittest.IsolatedAsyncioTestCase):
    """Test cases for UnifiedMCPFuzzerClient class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_transport = MagicMock()
        # Ensure awaited calls are awaitable
        self.mock_transport.call_tool = AsyncMock()
        self.mock_transport.send_request = AsyncMock()
        self.mock_transport.get_tools = AsyncMock()
        self.mock_auth_manager = MagicMock()
        self.client = UnifiedMCPFuzzerClient(
            self.mock_transport, self.mock_auth_manager
        )

    def test_init(self):
        """Test client initialization."""
        self.assertEqual(self.client.transport, self.mock_transport)
        self.assertEqual(self.client.auth_manager, self.mock_auth_manager)
        self.assertIsNotNone(self.client.tool_fuzzer)
        self.assertIsNotNone(self.client.protocol_fuzzer)
        self.assertIsNotNone(self.client.console)

    def test_init_default_auth_manager(self):
        """Test client initialization with default auth manager."""
        client = UnifiedMCPFuzzerClient(self.mock_transport)
        self.assertIsInstance(client.auth_manager, AuthManager)

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_tool_success(self, mock_logging):
        """Test successful tool fuzzing."""
        tool = {
            "name": "test_tool",
            "inputSchema": {
                "properties": {
                    "param1": {"type": "string"},
                    "param2": {"type": "integer"},
                }
            },
        }

        # Mock tool fuzzer result
        mock_fuzz_result = {
            "args": {"param1": "test_value", "param2": 42},
            "success": True,
        }
        with patch.object(
            self.client.tool_fuzzer, "fuzz_tool", return_value=[mock_fuzz_result]
        ) as mock_fuzz:
            # Mock auth manager
            self.mock_auth_manager.get_auth_headers_for_tool.return_value = {
                "Authorization": "Bearer token"
            }
            self.mock_auth_manager.get_auth_params_for_tool.return_value = {}

            # Mock transport response
            mock_response = {"result": "success", "data": "test_data"}
            self.mock_transport.call_tool.return_value = mock_response

            results = await self.client.fuzz_tool(tool, runs=2)

        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn("args", result)
            self.assertIn("result", result)
            self.assertEqual(result["result"], mock_response)

        # Verify tool fuzzer was called
        mock_fuzz.assert_called()

        # Verify transport was called
        self.assertEqual(self.mock_transport.call_tool.call_count, 2)

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_tool_exception_handling(self, mock_logging):
        """Test tool fuzzing with exception handling."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"param1": {"type": "string"}}},
        }

        # Mock tool fuzzer result
        mock_fuzz_result = {"args": {"param1": "test_value"}, "success": True}
        with patch.object(
            self.client.tool_fuzzer, "fuzz_tool", return_value=[mock_fuzz_result]
        ):
            # Mock auth manager
            self.mock_auth_manager.get_auth_headers_for_tool.return_value = {}
            self.mock_auth_manager.get_auth_params_for_tool.return_value = {}

            # Mock transport to raise exception
            self.mock_transport.call_tool.side_effect = Exception("Test exception")

            results = await self.client.fuzz_tool(tool, runs=1)

        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertIn("args", result)
        self.assertIn("exception", result)
        self.assertEqual(result["exception"], "Test exception")
        self.assertIn("traceback", result)

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_tool_with_auth_params(self, mock_logging):
        """Test tool fuzzing with authentication parameters."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"param1": {"type": "string"}}},
        }

        # Mock tool fuzzer result
        mock_fuzz_result = {"args": {"param1": "test_value"}, "success": True}
        with patch.object(
            self.client.tool_fuzzer, "fuzz_tool", return_value=[mock_fuzz_result]
        ):
            # Mock auth manager with auth params
            self.mock_auth_manager.get_auth_headers_for_tool.return_value = {
                "Authorization": "Bearer token"
            }
            self.mock_auth_manager.get_auth_params_for_tool.return_value = {
                "api_key": "secret_key"
            }

            # Mock transport response
            mock_response = {"result": "success"}
            self.mock_transport.call_tool.return_value = mock_response

            results = await self.client.fuzz_tool(tool, runs=1)

        # Verify that auth params were merged with tool args
        expected_args = {"param1": "test_value", "api_key": "secret_key"}
        self.mock_transport.call_tool.assert_called_with("test_tool", expected_args)

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_all_tools_success(self, mock_logging):
        """Test fuzzing all tools successfully."""
        # Mock transport to return tools
        mock_tools = [
            {
                "name": "tool1",
                "inputSchema": {"properties": {"param1": {"type": "string"}}},
            },
            {
                "name": "tool2",
                "inputSchema": {"properties": {"param2": {"type": "integer"}}},
            },
        ]
        self.mock_transport.get_tools.return_value = mock_tools

        # Mock tool fuzzer results
        mock_fuzz_result = {"args": {"param": "value"}, "success": True}
        with patch.object(
            self.client.tool_fuzzer, "fuzz_tool", return_value=[mock_fuzz_result]
        ):
            # Mock transport responses
            self.mock_transport.call_tool.return_value = {"result": "success"}

            # Mock auth manager
            self.mock_auth_manager.get_auth_headers_for_tool.return_value = {}
            self.mock_auth_manager.get_auth_params_for_tool.return_value = {}

            results = await self.client.fuzz_all_tools(runs_per_tool=2)

        self.assertEqual(len(results), 2)
        self.assertIn("tool1", results)
        self.assertIn("tool2", results)

        # Verify transport was called for each tool
        self.assertEqual(
            self.mock_transport.call_tool.call_count, 4
        )  # 2 tools * 2 runs

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_all_tools_empty_list(self, mock_logging):
        """Test fuzzing all tools with empty tool list."""
        self.mock_transport.get_tools.return_value = []

        results = await self.client.fuzz_all_tools()

        self.assertEqual(results, {})
        mock_logging.warning.assert_called_with(
            "Server returned an empty list of tools."
        )

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_all_tools_transport_error(self, mock_logging):
        """Test fuzzing all tools with transport error."""
        self.mock_transport.get_tools.side_effect = Exception("Transport error")

        results = await self.client.fuzz_all_tools()

        self.assertEqual(results, {})
        mock_logging.error.assert_called_with(
            "Failed to get tools from server: Transport error"
        )

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_protocol_type_success(self, mock_logging):
        """Test successful protocol type fuzzing."""
        protocol_type = "InitializeRequest"

        # Mock protocol fuzzer result
        mock_fuzz_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        with patch.object(
            self.client.protocol_fuzzer,
            "fuzz_protocol_type",
            return_value=[{"fuzz_data": mock_fuzz_data, "success": True}],
        ) as mock_fuzz_type:
            # Mock transport response
            mock_response = {"result": "success"}
            self.mock_transport.send_request.return_value = mock_response

            results = await self.client.fuzz_protocol_type(protocol_type, runs=2)

        self.assertEqual(len(results), 2)
        for result in results:
            self.assertIn("fuzz_data", result)
            self.assertIn("result", result)
            self.assertEqual(result["result"], mock_response)

        # Verify protocol fuzzer was called
        mock_fuzz_type.assert_called_with(protocol_type, 1)

        # Verify transport was called
        self.assertEqual(self.mock_transport.send_request.call_count, 2)

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_protocol_type_exception_handling(self, mock_logging):
        """Test protocol type fuzzing with exception handling."""
        protocol_type = "InitializeRequest"

        # Mock protocol fuzzer result
        mock_fuzz_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        with patch.object(
            self.client.protocol_fuzzer,
            "fuzz_protocol_type",
            return_value=[{"fuzz_data": mock_fuzz_data, "success": True}],
        ):
            # Mock transport to raise exception
            self.mock_transport.send_request.side_effect = Exception("Test exception")

            results = await self.client.fuzz_protocol_type(protocol_type, runs=1)

        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertIn("fuzz_data", result)
        self.assertIn("exception", result)
        self.assertEqual(result["exception"], "Test exception")
        self.assertIn("traceback", result)

    async def test_send_protocol_request_success(self):
        """Test sending protocol request successfully."""
        protocol_type = "InitializeRequest"
        data = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }

        mock_response = {"result": "success"}
        self.mock_transport.send_request.return_value = mock_response

        result = await self.client._send_protocol_request(protocol_type, data)

        self.assertEqual(result, mock_response)
        self.mock_transport.send_request.assert_called_with(
            "initialize", {"protocolVersion": "2024-11-05"}
        )

    async def test_send_protocol_request_unknown_type(self):
        """Test sending protocol request with unknown type."""
        protocol_type = "UnknownType"
        data = {"jsonrpc": "2.0", "method": "unknown"}

        mock_response = {"result": "success"}
        self.mock_transport.send_request.return_value = mock_response

        result = await self.client._send_protocol_request(protocol_type, data)

        self.assertEqual(result, mock_response)
        self.mock_transport.send_request.assert_called_with("unknown", {})

    async def test_send_initialize_request(self):
        """Test sending initialize request."""
        data = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }

        mock_response = {"result": "success"}
        self.mock_transport.send_request.return_value = mock_response

        result = await self.client._send_initialize_request(data)

        self.assertEqual(result, mock_response)
        self.mock_transport.send_request.assert_called_with(
            "initialize", {"protocolVersion": "2024-11-05"}
        )

    async def test_send_progress_notification(self):
        """Test sending progress notification."""
        data = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progress": 50},
        }

        mock_response = {"result": "success"}
        self.mock_transport.send_request.return_value = mock_response

        result = await self.client._send_progress_notification(data)

        self.assertEqual(result, {"status": "notification_sent"})
        self.mock_transport.send_request.assert_called_with(
            "notifications/progress", {"progress": 50}
        )

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_all_protocol_types_success(self, mock_logging):
        """Test fuzzing all protocol types successfully."""
        # Mock protocol fuzzer results
        mock_fuzz_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        with patch.object(
            self.client.protocol_fuzzer,
            "fuzz_all_protocol_types",
            return_value=[
                {
                    "protocol_type": "InitializeRequest",
                    "fuzz_data": mock_fuzz_data,
                    "success": True,
                }
            ],
        ) as mock_fuzz_all:
            # Mock transport response
            mock_response = {"result": "success"}
            self.mock_transport.send_request.return_value = mock_response

            results = await self.client.fuzz_all_protocol_types(runs_per_type=2)

        self.assertIsInstance(results, dict)
        self.assertGreater(len(results), 0)

        # Verify protocol fuzzer was called
        mock_fuzz_all.assert_called_with(2)

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_all_protocol_types_exception_handling(self, mock_logging):
        """Test fuzzing all protocol types with exception handling."""
        # Mock protocol fuzzer to raise exception
        with patch.object(
            self.client.protocol_fuzzer,
            "fuzz_all_protocol_types",
            side_effect=Exception("Test exception"),
        ):
            results = await self.client.fuzz_all_protocol_types()

        self.assertEqual(results, {})
        mock_logging.error.assert_called_with(
            "Failed to fuzz all protocol types: Test exception"
        )

    @patch("mcp_fuzzer.client.Console")
    def test_print_tool_summary(self, mock_console_class):
        """Test printing tool summary."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        # Mock the console instance in the client
        self.client.console = mock_console

        results = {
            "tool1": [
                {"args": {"param1": "value1"}, "result": {"success": True}},
                {"args": {"param1": "value2"}, "exception": "Test exception"},
            ],
            "tool2": [{"args": {"param2": "value3"}, "result": {"success": True}}],
        }

        self.client.print_tool_summary(results)

        # Verify console.print was called
        mock_console.print.assert_called()

    @patch("mcp_fuzzer.client.Console")
    def test_print_protocol_summary(self, mock_console_class):
        """Test printing protocol summary."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        # Mock the console instance in the client
        self.client.console = mock_console

        results = {
            "InitializeRequest": [
                {"fuzz_data": {"method": "initialize"}, "result": {"success": True}},
                {"fuzz_data": {"method": "initialize"}, "exception": "Test exception"},
            ],
            "ProgressNotification": [
                {
                    "fuzz_data": {"method": "notifications/progress"},
                    "result": {"success": True},
                }
            ],
        }

        self.client.print_protocol_summary(results)

        # Verify console.print was called
        mock_console.print.assert_called()

    @patch("mcp_fuzzer.client.Console")
    def test_print_overall_summary(self, mock_console_class):
        """Test printing overall summary."""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        # Mock the console instance in the client
        self.client.console = mock_console

        tool_results = {
            "tool1": [{"args": {"param1": "value1"}, "result": {"success": True}}]
        }

        protocol_results = {
            "InitializeRequest": [
                {"fuzz_data": {"method": "initialize"}, "result": {"success": True}}
            ]
        }

        self.client.print_overall_summary(tool_results, protocol_results)

        # Verify console.print was called
        mock_console.print.assert_called()

    @patch("mcp_fuzzer.client.logging")
    async def test_main_function(self, mock_logging):
        """Test the main function."""
        # This is a basic test - in a real scenario you'd want to test the
        # actual main function
        # For now, we'll just test that the client can be created and used
        client = UnifiedMCPFuzzerClient(self.mock_transport)

        # Test that the client has the expected attributes
        self.assertIsNotNone(client.transport)
        self.assertIsNotNone(client.tool_fuzzer)
        self.assertIsNotNone(client.protocol_fuzzer)
        self.assertIsNotNone(client.console)
        self.assertIsNotNone(client.auth_manager)


if __name__ == "__main__":
    unittest.main()
