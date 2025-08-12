#!/usr/bin/env python3
"""
Unit tests for Client module
"""

import asyncio
import json
import traceback
import unittest
from unittest.mock import AsyncMock, MagicMock, call, patch
from pathlib import Path
import tempfile
import shutil

from mcp_fuzzer.auth import AuthManager
from mcp_fuzzer.client import UnifiedMCPFuzzerClient
from mcp_fuzzer.reports import FuzzerReporter


class TestUnifiedMCPFuzzerClient(unittest.IsolatedAsyncioTestCase):
    """Test cases for UnifiedMCPFuzzerClient class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test reports
        self.test_output_dir = tempfile.mkdtemp()

        self.mock_transport = MagicMock()
        # Ensure awaited calls are awaitable
        self.mock_transport.call_tool = AsyncMock()
        self.mock_transport.send_request = AsyncMock()
        self.mock_transport.send_notification = AsyncMock()
        self.mock_transport.get_tools = AsyncMock()
        self.mock_auth_manager = MagicMock()

        # Create a real reporter for testing
        self.reporter = FuzzerReporter(output_dir=self.test_output_dir)

        self.client = UnifiedMCPFuzzerClient(
            self.mock_transport, self.mock_auth_manager, reporter=self.reporter
        )

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary test directory
        if Path(self.test_output_dir).exists():
            shutil.rmtree(self.test_output_dir)

    def test_init(self):
        """Test client initialization."""
        self.assertEqual(self.client.transport, self.mock_transport)
        self.assertEqual(self.client.auth_manager, self.mock_auth_manager)
        self.assertIsNotNone(self.client.tool_fuzzer)
        self.assertIsNotNone(self.client.protocol_fuzzer)
        self.assertIsNotNone(self.client.reporter)

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
            new_callable=AsyncMock,
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
            new_callable=AsyncMock,
            return_value=[{"fuzz_data": mock_fuzz_data, "success": True}],
        ) as mock_fuzz:
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

        # Notification should not use send_request; ensure send_notification is called
        self.mock_transport.send_notification.return_value = None

        result = await self.client._send_progress_notification(data)

        self.assertEqual(result, {"status": "notification_sent"})
        # Ensure request path is not used for notifications
        self.mock_transport.send_request.assert_not_called()
        self.mock_transport.send_notification.assert_called_with(
            "notifications/progress", {"progress": 50}
        )

    async def test_send_cancel_notification(self):
        """Test sending cancel notification."""
        data = {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 123},
        }

        self.mock_transport.send_notification.return_value = None

        result = await self.client._send_cancel_notification(data)

        self.assertEqual(result, {"status": "notification_sent"})
        self.mock_transport.send_request.assert_not_called()
        self.mock_transport.send_notification.assert_called_with(
            "notifications/cancelled", {"requestId": 123}
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
            return_value={
                "InitializeRequest": [
                    {
                        "protocol_type": "InitializeRequest",
                        "fuzz_data": mock_fuzz_data,
                        "success": True,
                    }
                ]
            },
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

    def test_print_tool_summary(self):
        """Test printing tool summary."""
        results = {
            "tool1": [
                {"args": {"param1": "value1"}, "result": {"success": True}},
                {"args": {"param1": "value2"}, "exception": "Test exception"},
            ],
            "tool2": [{"args": {"param2": "value3"}, "result": {"success": True}}],
        }

        # Call the method
        self.client.print_tool_summary(results)

        # Verify that the reporter stored the results
        self.assertEqual(self.client.reporter.tool_results, results)

        # Verify that the reporter has the correct data
        self.assertIn("tool1", self.client.reporter.tool_results)
        self.assertIn("tool2", self.client.reporter.tool_results)

    def test_print_protocol_summary(self):
        """Test printing protocol summary."""
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

        # Call the method
        self.client.print_protocol_summary(results)

        # Verify that the reporter stored the results
        self.assertEqual(self.client.reporter.protocol_results, results)

        # Verify that the reporter has the correct data
        self.assertIn("InitializeRequest", self.client.reporter.protocol_results)
        self.assertIn("ProgressNotification", self.client.reporter.protocol_results)

    def test_print_overall_summary(self):
        """Test printing overall summary."""
        tool_results = {
            "tool1": [{"args": {"param1": "value1"}, "result": {"success": True}}]
        }

        protocol_results = {
            "InitializeRequest": [
                {"fuzz_data": {"method": "initialize"}, "result": {"success": True}}
            ]
        }

        # Use the methods that actually store results
        self.client.reporter.print_tool_summary(tool_results)
        self.client.reporter.print_protocol_summary(protocol_results)

        # Now call the overall summary
        self.client.print_overall_summary(tool_results, protocol_results)

        # Verify that the reporter stored the results
        self.assertEqual(self.client.reporter.tool_results, tool_results)
        self.assertEqual(self.client.reporter.protocol_results, protocol_results)

        # Verify that the reporter has the correct data
        self.assertIn("tool1", self.client.reporter.tool_results)
        self.assertIn("InitializeRequest", self.client.reporter.protocol_results)

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
        self.assertIsNotNone(client.reporter)
        self.assertIsNotNone(client.auth_manager)

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_tool_with_safety_metadata(self, mock_logging):
        """Test fuzz_tool with safety metadata in results."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"param1": {"type": "string"}}},
        }

        # Mock tool fuzzer result
        mock_fuzz_result = {"args": {"param1": "test_value"}, "success": True}
        with patch.object(
            self.client.tool_fuzzer, "fuzz_tool", return_value=[mock_fuzz_result]
        ):
            # Mock transport response with safety metadata
            mock_response = {
                "result": "success",
                "_meta": {"safety_blocked": True, "safety_sanitized": False},
            }
            self.mock_transport.call_tool.return_value = mock_response

            results = await self.client.fuzz_tool(tool, runs=1)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["safety_blocked"])
        self.assertFalse(results[0]["safety_sanitized"])

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_tool_with_content_blocking(self, mock_logging):
        """Test fuzz_tool with content-based blocking detection."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"param1": {"type": "string"}}},
        }

        # Mock tool fuzzer result
        mock_fuzz_result = {"args": {"param1": "test_value"}, "success": True}
        with patch.object(
            self.client.tool_fuzzer, "fuzz_tool", return_value=[mock_fuzz_result]
        ):
            # Mock transport response with blocked content
            mock_response = {
                "content": [
                    {"text": "This was [SAFETY BLOCKED] due to dangerous content"}
                ]
            }
            self.mock_transport.call_tool.return_value = mock_response

            results = await self.client.fuzz_tool(tool, runs=1)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["safety_blocked"])

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_tool_with_blocked_content_variants(self, mock_logging):
        """Test fuzz_tool with different blocked content variants."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"param1": {"type": "string"}}},
        }

        # Mock tool fuzzer result
        mock_fuzz_result = {"args": {"param1": "test_value"}, "success": True}
        with patch.object(
            self.client.tool_fuzzer, "fuzz_tool", return_value=[mock_fuzz_result]
        ):
            # Test with [BLOCKED content
            mock_response = {
                "content": [{"text": "This was [BLOCKED due to dangerous content"}]
            }
            self.mock_transport.call_tool.return_value = mock_response

            results = await self.client.fuzz_tool(tool, runs=1)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["safety_blocked"])

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_all_tools_both_phases(self, mock_logging):
        """Test fuzz_all_tools_both_phases."""
        # Mock tools
        tools = [
            {"name": "test_tool1", "description": "Test tool 1"},
            {"name": "test_tool2", "description": "Test tool 2"},
        ]

        self.mock_transport.get_tools.return_value = tools

        # Mock the ToolFuzzer
        with patch("mcp_fuzzer.client.ToolFuzzer") as mock_tool_fuzzer_class:
            mock_tool_fuzzer = MagicMock()
            mock_tool_fuzzer.fuzz_tool_both_phases.return_value = {
                "realistic": [{"args": {}, "result": "success"}],
                "aggressive": [{"args": {}, "result": "success"}],
            }
            mock_tool_fuzzer_class.return_value = mock_tool_fuzzer

            results = await self.client.fuzz_all_tools_both_phases(runs_per_phase=1)

        self.assertIn("test_tool1", results)
        self.assertIn("test_tool2", results)

    @patch("mcp_fuzzer.client.logging")
    async def test_fuzz_all_tools_both_phases_empty_tools(self, mock_logging):
        """Test fuzz_all_tools_both_phases with empty tools list."""
        self.mock_transport.get_tools.return_value = []

        results = await self.client.fuzz_all_tools_both_phases()

        self.assertEqual(results, {})

    async def test_send_protocol_request_initialize(self):
        """Test _send_protocol_request with initialize type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_initialize_request") as mock_init:
            mock_init.return_value = {"result": "success"}

            result = await self.client._send_protocol_request("InitializeRequest", data)

            mock_init.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_progress(self):
        """Test _send_protocol_request with progress type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_progress_notification") as mock_progress:
            mock_progress.return_value = {"result": "success"}

            result = await self.client._send_protocol_request(
                "ProgressNotification", data
            )

            mock_progress.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_cancel(self):
        """Test _send_protocol_request with cancel type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_cancel_notification") as mock_cancel:
            mock_cancel.return_value = {"result": "success"}

            result = await self.client._send_protocol_request(
                "CancelNotification", data
            )

            mock_cancel.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_list_resources(self):
        """Test _send_protocol_request with list_resources type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_list_resources_request") as mock_list:
            mock_list.return_value = {"result": "success"}

            result = await self.client._send_protocol_request(
                "ListResourcesRequest", data
            )

            mock_list.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_read_resource(self):
        """Test _send_protocol_request with read_resource type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_read_resource_request") as mock_read:
            mock_read.return_value = {"result": "success"}

            result = await self.client._send_protocol_request(
                "ReadResourceRequest", data
            )

            mock_read.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_set_level(self):
        """Test _send_protocol_request with set_level type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_set_level_request") as mock_set:
            mock_set.return_value = {"result": "success"}

            result = await self.client._send_protocol_request("SetLevelRequest", data)

            mock_set.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_create_message(self):
        """Test _send_protocol_request with create_message type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_create_message_request") as mock_create:
            mock_create.return_value = {"result": "success"}

            result = await self.client._send_protocol_request(
                "CreateMessageRequest", data
            )

            mock_create.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_list_prompts(self):
        """Test _send_protocol_request with list_prompts type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_list_prompts_request") as mock_list:
            mock_list.return_value = {"result": "success"}

            result = await self.client._send_protocol_request(
                "ListPromptsRequest", data
            )

            mock_list.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_get_prompt(self):
        """Test _send_protocol_request with get_prompt type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_get_prompt_request") as mock_get:
            mock_get.return_value = {"result": "success"}

            result = await self.client._send_protocol_request("GetPromptRequest", data)

            mock_get.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_list_roots(self):
        """Test _send_protocol_request with list_roots type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_list_roots_request") as mock_list:
            mock_list.return_value = {"result": "success"}

            result = await self.client._send_protocol_request("ListRootsRequest", data)

            mock_list.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_subscribe(self):
        """Test _send_protocol_request with subscribe type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_subscribe_request") as mock_sub:
            mock_sub.return_value = {"result": "success"}

            result = await self.client._send_protocol_request("SubscribeRequest", data)

            mock_sub.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_unsubscribe(self):
        """Test _send_protocol_request with unsubscribe type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_unsubscribe_request") as mock_unsub:
            mock_unsub.return_value = {"result": "success"}

            result = await self.client._send_protocol_request(
                "UnsubscribeRequest", data
            )

            mock_unsub.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_complete(self):
        """Test _send_protocol_request with complete type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_complete_request") as mock_complete:
            mock_complete.return_value = {"result": "success"}

            result = await self.client._send_protocol_request("CompleteRequest", data)

            mock_complete.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    async def test_send_protocol_request_generic(self):
        """Test _send_protocol_request with generic type."""
        data = {"test": "data"}

        with patch.object(self.client, "_send_generic_request") as mock_generic:
            mock_generic.return_value = {"result": "success"}

            result = await self.client._send_protocol_request("unknown_type", data)

            mock_generic.assert_called_once_with(data)
            self.assertEqual(result, {"result": "success"})

    def test_print_blocked_operations_summary(self):
        """Test print_blocked_operations_summary."""
        # Call the method - it should work with the real reporter
        self.client.print_blocked_operations_summary()

        # The method should complete without error
        # We can't easily test the actual output without mocking the safety system,
        # but we can verify the method exists and can be called
        self.assertTrue(
            hasattr(self.client.reporter, "print_blocked_operations_summary")
        )

    def test_reporter_can_generate_final_report(self):
        """Test that the reporter can generate final reports."""
        # Add some test data to the reporter
        tool_results = {"test_tool": [{"args": {}, "result": "success"}]}
        protocol_results = {"test_protocol": [{"fuzz_data": {}, "result": "success"}]}

        self.client.reporter.add_tool_results("test_tool", tool_results["test_tool"])
        self.client.reporter.add_protocol_results(
            "test_protocol", protocol_results["test_protocol"]
        )

        # Set some metadata
        self.client.reporter.set_fuzzing_metadata(
            mode="tools", protocol="stdio", endpoint="test", runs=1
        )

        # Generate the final report
        report_path = self.client.reporter.generate_final_report(include_safety=False)

        # Verify the report was generated
        self.assertTrue(Path(report_path).exists())
        self.assertTrue(Path(report_path).suffix == ".json")

        # Verify the report contains our data
        with open(report_path, "r") as f:
            report_data = json.load(f)

        self.assertIn("test_tool", report_data["tool_results"])
        self.assertIn("test_protocol", report_data["protocol_results"])
        self.assertEqual(report_data["metadata"]["mode"], "tools")

    async def test_fuzz_all_tools_exception_handling(self):
        """Test fuzz_all_tools with exception during individual tool fuzzing."""
        tools = [
            {"name": "test_tool1", "description": "Test tool 1"},
            {"name": "test_tool2", "description": "Test tool 2"},
        ]

        self.mock_transport.get_tools.return_value = tools

        # Mock fuzz_tool to raise exception for second tool
        with patch.object(self.client, "fuzz_tool") as mock_fuzz:
            mock_fuzz.side_effect = [
                [{"args": {}, "result": "success"}],  # First tool succeeds
                Exception("Fuzzing failed"),  # Second tool fails
            ]

            results = await self.client.fuzz_all_tools(runs_per_tool=1)

        self.assertIn("test_tool1", results)
        self.assertIn("test_tool2", results)
        self.assertIn("error", results["test_tool2"][0])


if __name__ == "__main__":
    unittest.main()
