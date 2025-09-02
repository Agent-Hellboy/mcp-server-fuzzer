#!/usr/bin/env python3
"""
Integration tests for client and transport interactions
"""

import asyncio
import unittest
from unittest.mock import MagicMock, patch

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

    @patch("mcp_fuzzer.transport.streamable_http.httpx.AsyncClient.stream")
    async def test_client_send_request_through_transport(self, mock_stream):
        """Test client sending requests through transport."""
        # Mock the response
        mock_response = MagicMock()
        mock_response.aiter_bytes.return_value = [b'{"id": 1, "result": "test"}']
        mock_stream.return_value.__aenter__.return_value = mock_response

        # Test the client sending a request
        result = await self.client.call_method("test_method", {"param": "value"})

        # Verify the transport was used correctly
        mock_stream.assert_called_once()
        self.assertEqual(result, {"id": 1, "result": "test"})


if __name__ == "__main__":
    unittest.main()
