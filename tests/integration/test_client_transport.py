"""
Integration tests for client and transport interactions
"""

from unittest.mock import patch

import httpx
import pytest
from mcp_fuzzer.client.protocol_client import ProtocolClient
from mcp_fuzzer.transport.streamable_http import StreamableHTTPTransport

pytestmark = [pytest.mark.integration, pytest.mark.client, pytest.mark.transport]


@pytest.fixture
def client_setup():
    """Fixture for client and transport setup."""
    base_url = "http://localhost:8000"
    transport = StreamableHTTPTransport(base_url)
    # Skip initialize handshake in tests to avoid mocking extra POSTs
    try:
        transport._initialized = True
    except Exception:
        pass
    client = ProtocolClient(transport)
    return {"base_url": base_url, "transport": transport, "client": client}


@pytest.mark.asyncio
async def test_client_transport_integration(client_setup):
    """Test client and transport integration."""
    # This is a basic test to verify the client and transport can be instantiated
    assert isinstance(client_setup["client"], ProtocolClient)
    assert isinstance(client_setup["transport"], StreamableHTTPTransport)
    # Verify the transport was created with the correct URL
    assert client_setup["transport"].url == "http://localhost:8000"
