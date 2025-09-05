#!/usr/bin/env python3
"""
Unit tests for Transport module
"""

import asyncio
import json
import os
import uuid
from unittest.mock import AsyncMock, MagicMock, call, patch

import httpx
import pytest

from mcp_fuzzer.transport import (
    HTTPTransport,
    SSETransport,
    StdioTransport,
    TransportProtocol,
    create_transport,
)
from mcp_fuzzer.transport.mixins import (
    BaseTransportMixin,
    NetworkTransportMixin,
    ResponseParsingMixin,
    JSONRPCRequest,
    JSONRPCNotification,
    TransportError,
    NetworkError,
    PayloadValidationError,
)

pytestmark = [pytest.mark.unit, pytest.mark.transport]


# Test cases for TransportProtocol class
@pytest.mark.asyncio
async def test_transport_protocol_abstract():
    """Test that TransportProtocol is properly abstract."""
    # Should not be able to instantiate TransportProtocol directly
    with pytest.raises(TypeError):
        TransportProtocol()


@pytest.mark.asyncio
async def test_transport_protocol_connection_methods():
    """Test TransportProtocol connection management methods."""

    # Create a concrete implementation
    class TestTransport(TransportProtocol):
        async def send_request(self, method, params=None):
            return {"test": "response"}

        async def send_raw(self, payload):
            return {"test": "raw_response"}

        async def send_notification(self, method, params=None):
            pass

        async def _send_request(self, payload):
            return {"test": "response"}

        async def _stream_request(self, payload):
            yield {"test": "stream"}

    transport = TestTransport()

    # Test connect (default implementation should do nothing)
    await transport.connect()

    # Test disconnect (default implementation should do nothing)
    await transport.disconnect()


@pytest.mark.asyncio
async def test_transport_protocol_send_request():
    """Test TransportProtocol send_request method."""

    # Create a concrete implementation with mocked _send_request
    class TestTransport(TransportProtocol):
        async def send_request(self, method, params=None):
            payload = {"method": method}
            if params:
                payload["params"] = params
            return await self._send_request(payload)

        async def send_raw(self, payload):
            return await self._send_request(payload)

        async def send_notification(self, method, params=None):
            pass

        async def _send_request(self, payload):
            self.last_payload = payload
            return {"result": "success"}

        async def _stream_request(self, payload):
            yield {"test": "stream"}

    transport = TestTransport()
    test_method = "test.method"
    test_params = {"key": "value"}

    # Test send_request
    result = await transport.send_request(test_method, test_params)

    assert result == {"result": "success"}
    expected_payload = {"method": test_method, "params": test_params}
    assert transport.last_payload == expected_payload


@pytest.mark.asyncio
async def test_transport_protocol_stream_request():
    """Test TransportProtocol stream_request method."""

    # Create a concrete implementation with mocked _stream_request
    class TestTransport(TransportProtocol):
        async def send_request(self, method, params=None):
            payload = {"method": method}
            if params:
                payload["params"] = params
            return await self._send_request(payload)

        async def send_raw(self, payload):
            return await self._send_request(payload)

        async def send_notification(self, method, params=None):
            pass

        async def _send_request(self, payload):
            return {"test": "response"}

        async def _stream_request(self, payload):
            self.last_payload = payload
            yield {"result": "streaming"}
            yield {"result": "complete"}

    transport = TestTransport()
    test_method = "test.method"
    test_params = {"key": "value"}

    # Create a payload for stream_request
    test_payload = {"method": test_method, "params": test_params}

    # Test stream_request
    responses = []
    async for response in transport.stream_request(test_payload):
        responses.append(response)

    assert len(responses) == 2
    assert responses[0] == {"result": "streaming"}
    assert responses[1] == {"result": "complete"}
    assert transport.last_payload == test_payload


# Test cases for HTTPTransport class
@pytest.fixture
def http_transport():
    """Fixture for HTTPTransport test cases."""
    return HTTPTransport("https://example.com/api")


@pytest.mark.asyncio
async def test_http_transport_init(http_transport):
    """Test HTTPTransport initialization."""
    assert http_transport.url == "https://example.com/api"
    assert http_transport.timeout == 30.0
    assert "Accept" in http_transport.headers
    assert "Content-Type" in http_transport.headers


@pytest.mark.asyncio
async def test_http_transport_send_request(http_transport):
    """Test HTTPTransport send_request method."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}
    test_response = {"result": "success"}

    with patch.object(httpx.AsyncClient, "post") as mock_post:
        mock_response = MagicMock()
        mock_response.json.return_value = test_response
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Test send_request
        result = await http_transport.send_raw(test_payload)

        # Check the result and that post was called with correct arguments
        assert result == "success"
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://example.com/api"
        assert "json" in call_args[1]
        assert call_args[1]["json"] == test_payload


@pytest.mark.asyncio
async def test_http_transport_send_request_error(http_transport):
    """Test HTTPTransport send_request with error response."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}

    with patch.object(httpx.AsyncClient, "post") as mock_post:
        mock_post.side_effect = httpx.RequestError("Connection error")

        # Test send_request with error
        with pytest.raises(httpx.RequestError):
            await http_transport.send_raw(test_payload)


@pytest.mark.asyncio
async def test_http_transport_stream_request(http_transport):
    """Test HTTPTransport stream_request method."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}
    test_responses = [
        {"id": 1, "result": "streaming"},
        {"id": 2, "result": "complete"},
    ]

    with patch.object(httpx.AsyncClient, "post") as mock_post:
        # Create a proper AsyncMock for the response
        mock_response = AsyncMock()

        # Create a simpler mock for the async iterator
        async def mock_aiter_lines():
            class AsyncIterator:
                def __init__(self, items):
                    self.items = items
                    self.index = 0

                def __aiter__(self):
                    return self

                async def __anext__(self):
                    if self.index < len(self.items):
                        item = self.items[self.index]
                        self.index += 1
                        return item
                    raise StopAsyncIteration

            return AsyncIterator(
                [json.dumps(test_responses[0]), json.dumps(test_responses[1])]
            )

        # Set up the mock to return our async iterator
        mock_response.aiter_lines = mock_aiter_lines

        # Add raise_for_status method
        mock_response.raise_for_status = AsyncMock()

        # Set up mock_post to return the mock_response
        mock_post.return_value = mock_response

        # Test stream_request
        responses = []
        async for response in http_transport.stream_request(test_payload):
            responses.append(response)

        # Verify the results
        assert len(responses) == 2
        assert responses == test_responses

        # Verify the mock was called correctly
        mock_post.assert_called_once()
        # raise_for_status in httpx is sync on Response; our code calls it sync
        # so assert it was called (not awaited)
        assert mock_response.raise_for_status.called
        # aclose is awaited in implementation
        mock_response.aclose.assert_awaited_once()
        # Note: Can't assert on aiter_lines; it's a custom function here


@pytest.mark.asyncio
async def test_http_transport_stream_request_error(http_transport):
    """Test HTTPTransport stream_request with error."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}

    with patch.object(httpx.AsyncClient, "post") as mock_post:
        mock_post.side_effect = httpx.RequestError("Connection error")

        # Test stream_request with error
        with pytest.raises(httpx.RequestError):
            async for _ in http_transport._stream_request(test_payload):
                pass


@pytest.mark.asyncio
async def test_http_transport_connect_disconnect(http_transport):
    """Test HTTPTransport connect and disconnect methods."""
    # These should not raise any exceptions
    await http_transport.connect()
    await http_transport.disconnect()


# Test cases for SSETransport class
@pytest.fixture
def sse_transport():
    """Fixture for SSETransport test cases."""
    return SSETransport("https://example.com/events")


@pytest.mark.asyncio
async def test_sse_transport_init(sse_transport):
    """Test SSETransport initialization."""
    assert sse_transport.url == "https://example.com/events"
    assert sse_transport.timeout == 30.0
    assert "Accept" in sse_transport.headers
    assert "Content-Type" in sse_transport.headers


@pytest.mark.asyncio
async def test_sse_transport_send_request_not_implemented(sse_transport):
    """Test SSETransport send_request is not implemented."""
    with pytest.raises(NotImplementedError):
        await sse_transport.send_request("test")


@pytest.mark.asyncio
async def test_sse_transport_stream_request(sse_transport):
    """Test SSETransport stream_request method."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}

    # Create mock SSE events - each event needs to end with a blank line
    sse_events = [
        (
            "event: message\ndata: "
            + json.dumps({"id": 1, "result": "streaming"})
            + "\n\n"
        ),
        (
            "event: message\ndata: "
            + json.dumps({"id": 2, "result": "complete"})
            + "\n\n"
        ),
    ]

    with patch.object(httpx.AsyncClient, "stream") as mock_stream:
        # Mock streaming response
        mock_response = MagicMock()
        mock_response.aiter_text.return_value = sse_events
        mock_stream.return_value.__aenter__.return_value = mock_response

        # Test stream_request
        responses = []
        async for response in sse_transport._stream_request(test_payload):
            responses.append(response)

        # Check the results
        assert len(responses) == 2
        assert responses[0] == {"id": 1, "result": "streaming"}
        assert responses[1] == {"id": 2, "result": "complete"}
        mock_stream.assert_called_once()


@pytest.mark.asyncio
async def test_sse_transport_stream_request_error(sse_transport):
    """Test SSETransport stream_request with error."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}

    with patch.object(httpx.AsyncClient, "stream") as mock_stream:
        mock_stream.side_effect = httpx.RequestError("Connection error")

        # Test stream_request with error
        with pytest.raises(httpx.RequestError):
            async for _ in sse_transport._stream_request(test_payload):
                pass


@pytest.mark.asyncio
async def test_sse_transport_parse_sse_event():
    """Test SSETransport _parse_sse_event method."""
    # Standard SSE event
    sse_event = 'event: message\ndata: {"id": 1, "result": "success"}'
    result = SSETransport._parse_sse_event(sse_event)
    assert result == {"id": 1, "result": "success"}

    # Multiline data
    sse_event = 'event: message\ndata: {"id": 1,\ndata: "result": "multiline"}'
    result = SSETransport._parse_sse_event(sse_event)
    assert result == {"id": 1, "result": "multiline"}

    # With retry field (should ignore)
    sse_event = 'retry: 3000\nevent: message\ndata: {"id": 1}'
    result = SSETransport._parse_sse_event(sse_event)
    assert result == {"id": 1}

    # Empty event
    assert SSETransport._parse_sse_event("") is None

    # Invalid JSON
    sse_event = "event: message\ndata: not_json"
    with pytest.raises(json.JSONDecodeError):
        SSETransport._parse_sse_event(sse_event)


# Test cases for StdioTransport class
@pytest.fixture
def stdio_transport():
    """Fixture for StdioTransport test cases."""
    with patch("mcp_fuzzer.transport.stdio.sys") as mock_sys:
        transport = StdioTransport("test_command")
        transport._sys = mock_sys  # Attach the mock to the transport
        yield transport


@pytest.mark.asyncio
async def test_stdio_transport_init(stdio_transport):
    """Test StdioTransport initialization."""
    assert stdio_transport.request_id == 1


@pytest.mark.asyncio
async def test_stdio_transport_send_request(stdio_transport):
    """Test StdioTransport send_request method."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}
    test_response = {"id": 1, "result": "success"}

    # Set up the mocks
    stdio_transport._sys.stdin.readline = AsyncMock(
        return_value=json.dumps(test_response)
    )

    # Test send_request
    result = await stdio_transport._send_request(test_payload)

    # Check the result and that stdout.write was called with correct arguments
    assert result == test_response
    stdio_transport._sys.stdout.write.assert_called_once()
    call_args = stdio_transport._sys.stdout.write.call_args
    written_data = call_args[0][0]
    assert json.loads(written_data) == {**test_payload, "id": 1, "jsonrpc": "2.0"}


@pytest.mark.asyncio
async def test_stdio_transport_send_request_error(stdio_transport):
    """Test StdioTransport send_request with error response."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}
    test_error = {"id": 1, "error": {"code": -32600, "message": "Invalid Request"}}

    # Set up the mocks
    stdio_transport._sys.stdin.readline = AsyncMock(return_value=json.dumps(test_error))

    # Test send_request with error response
    result = await stdio_transport._send_request(test_payload)

    # Check the result
    assert result == test_error


@pytest.mark.asyncio
async def test_stdio_transport_send_request_invalid_json(stdio_transport):
    """Test StdioTransport send_request with invalid JSON response."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}

    # Set up the mocks
    stdio_transport._sys.stdin.readline = AsyncMock(return_value="not_json")

    # Test send_request with invalid JSON
    with pytest.raises(json.JSONDecodeError):
        await stdio_transport._send_request(test_payload)


@pytest.mark.asyncio
async def test_stdio_transport_stream_request(stdio_transport):
    """Test StdioTransport stream_request method."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}
    test_responses = [
        {"id": 1, "result": "streaming"},
        {"id": 1, "result": "complete"},
    ]

    # Set up the mocks
    stdio_transport._sys.stdin.readline = AsyncMock(
        side_effect=[json.dumps(r) for r in test_responses]
    )

    # Test stream_request
    responses = []
    async for response in stdio_transport._stream_request(test_payload):
        responses.append(response)
        if len(responses) == len(test_responses):
            break

    # Check the results
    assert len(responses) == 2
    assert responses == test_responses
    assert stdio_transport._sys.stdout.write.call_count == 1


# Test cases for create_transport function
def test_create_transport_http():
    """Test create_transport with HTTP URL."""
    transport = create_transport("http://example.com/api")
    assert isinstance(transport, HTTPTransport)
    assert transport.url == "http://example.com/api"


def test_create_transport_https():
    """Test create_transport with HTTPS URL."""
    transport = create_transport("https://example.com/api")
    assert isinstance(transport, HTTPTransport)
    assert transport.url == "https://example.com/api"


def test_create_transport_sse():
    """Test create_transport with SSE URL."""
    transport = create_transport("sse://example.com/events")
    assert isinstance(transport, SSETransport)
    assert transport.url == "http://example.com/events"


def test_create_transport_stdio():
    """Test create_transport with stdio URL."""
    transport = create_transport("stdio:")
    assert isinstance(transport, StdioTransport)


def test_create_transport_invalid_scheme():
    """Test create_transport with invalid URL scheme."""
    with pytest.raises(ValueError):
        create_transport("invalid://example.com")
