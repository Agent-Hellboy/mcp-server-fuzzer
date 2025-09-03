#!/usr/bin/env python3
"""
Integration tests for client and transport interactions
"""

import asyncio
import json
import unittest
from unittest.mock import MagicMock, patch

import httpx
import pytest
from mcp_fuzzer.client.protocol_client import ProtocolClient
from mcp_fuzzer.transport.streamable_http import StreamableHTTPTransport

pytestmark = [pytest.mark.integration, pytest.mark.client, pytest.mark.transport]


class TestClientTransportIntegration(unittest.TestCase):
    """Test the integration between client and transport layers."""

    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "http://localhost:8000"
        self.transport = StreamableHTTPTransport(self.base_url)
        self.client = ProtocolClient(self.transport)

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.transport.streamable_http.httpx.AsyncClient.post")
    async def test_client_send_request_through_transport(self, mock_post):
        """Test client sending requests through transport."""
        # Mock the HTTP response
        mock_post.return_value = httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=b'{"jsonrpc":"2.0","id":"1","result":"test"}',
        )

        # Test the client sending a request via generic request path
        result = await self.client._send_generic_request(
            {"method": "test_method", "params": {"param": "value"}}
        )

        # Verify the transport was used correctly
        mock_post.assert_called_once()
        self.assertEqual(result, {"result": "test"})


if __name__ == "__main__":
    unittest.main()
