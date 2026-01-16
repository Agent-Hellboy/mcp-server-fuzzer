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
    HttpDriver,
    SseDriver,
    StdioDriver,
    TransportDriver,
    build_driver,
)
from mcp_fuzzer.transport.interfaces.behaviors import (
    DriverBaseBehavior,
    HttpClientBehavior,
    ResponseParserBehavior,
    JSONRPCRequest,
    JSONRPCNotification,
    TransportError,
    NetworkError,
    PayloadValidationError,
)
from mcp_fuzzer.exceptions import TransportRegistrationError

pytestmark = [pytest.mark.unit, pytest.mark.transport]


class _DummySSELinesResponse:
    def __init__(self, lines):
        self.status_code = 200
        self.headers = {"content-type": "text/event-stream"}
        self._lines = lines

    def raise_for_status(self) -> None:  # pragma: no cover
        pass

    async def aiter_lines(self):
        for line in self._lines:
            await asyncio.sleep(0)
            yield line


# Test cases for TransportDriver class
@pytest.mark.asyncio
async def test_transport_protocol_abstract():
    """Test that TransportDriver is properly abstract."""
    # Should not be able to instantiate TransportDriver directly
    with pytest.raises(TypeError):
        TransportDriver()


@pytest.mark.asyncio
async def test_transport_protocol_connection_methods():
    """Test TransportDriver connection management methods."""

    # Create a concrete implementation
    class TestTransport(TransportDriver):
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
    """Test TransportDriver send_request method."""

    # Create a concrete implementation with mocked _send_request
    class TestTransport(TransportDriver):
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
    """Test TransportDriver stream_request method."""

    # Create a concrete implementation with mocked _stream_request
    class TestTransport(TransportDriver):
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


# Test cases for HttpDriver class
@pytest.fixture
def http_transport():
    """Fixture for HttpDriver test cases."""
    return HttpDriver("https://example.com/api")


@pytest.mark.asyncio
async def test_http_transport_init(http_transport):
    """Test HttpDriver initialization."""
    assert http_transport.url == "https://example.com/api"
    assert http_transport.timeout == 30.0
    assert "Accept" in http_transport.headers
    assert "Content-Type" in http_transport.headers


@pytest.mark.asyncio
async def test_http_transport_send_request(http_transport):
    """Test HttpDriver send_request method."""
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
    """Test HttpDriver send_request with error response."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}

    with patch.object(httpx.AsyncClient, "post") as mock_post:
        mock_post.side_effect = httpx.RequestError("Connection error")

        # Test send_request with error
        with pytest.raises(httpx.RequestError):
            await http_transport.send_raw(test_payload)


@pytest.mark.asyncio
async def test_http_transport_stream_request(http_transport):
    """Test HttpDriver stream_request method."""
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
    """Test HttpDriver stream_request with error."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}

    with patch.object(httpx.AsyncClient, "post") as mock_post:
        mock_post.side_effect = httpx.RequestError("Connection error")

        # Test stream_request with error
        with pytest.raises(httpx.RequestError):
            async for _ in http_transport._stream_request(test_payload):
                pass


@pytest.mark.asyncio
async def test_http_transport_connect_disconnect(http_transport):
    """Test HttpDriver connect and disconnect methods."""
    # These should not raise any exceptions
    await http_transport.connect()
    await http_transport.disconnect()


# Test cases for SseDriver class
@pytest.fixture
def sse_transport():
    """Fixture for SseDriver test cases."""
    return SseDriver("https://example.com/events")


@pytest.mark.asyncio
async def test_sse_transport_init(sse_transport):
    """Test SseDriver initialization."""
    assert sse_transport.url == "https://example.com/events"
    assert sse_transport.timeout == 30.0
    assert "Accept" in sse_transport.headers
    assert "Content-Type" in sse_transport.headers


@pytest.mark.asyncio
async def test_sse_transport_send_request_not_implemented(sse_transport):
    """Test SseDriver send_request is not implemented."""
    with pytest.raises(NotImplementedError):
        await sse_transport.send_request("test")


@pytest.mark.asyncio
async def test_sse_transport_stream_request(sse_transport):
    """Test SseDriver stream_request method."""
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
async def test_sse_transport_send_raw_handles_sampling_request():
    """SseDriver should reply to sampling/createMessage and continue."""
    sse_events = [
        "event: message",
        (
            'data: {"jsonrpc": "2.0", "id": "srv-1", '
            '"method": "sampling/createMessage", '
            '"params": {"messages": [], "maxTokens": 1}}'
        ),
        "",
        "event: message",
        'data: {"jsonrpc": "2.0", "id": "1", "result": {"ok": true}}',
        "",
    ]
    driver = SseDriver("http://test", timeout=1)

    with (
        patch.object(httpx.AsyncClient, "stream") as mock_stream,
        patch.object(driver, "_send_client_response", new=AsyncMock()) as mock_send,
    ):
        mock_response = _DummySSELinesResponse(sse_events)
        mock_stream.return_value.__aenter__.return_value = mock_response
        result = await driver.send_raw({"jsonrpc": "2.0", "id": "1"})

    assert result == {"ok": True}
    mock_send.assert_awaited_once()


@pytest.mark.asyncio
async def test_sse_transport_stream_request_error(sse_transport):
    """Test SseDriver stream_request with error."""
    test_payload = {"method": "test.method", "params": {"key": "value"}}

    with patch.object(httpx.AsyncClient, "stream") as mock_stream:
        mock_stream.side_effect = httpx.RequestError("Connection error")

        # Test stream_request with error
        with pytest.raises(httpx.RequestError):
            async for _ in sse_transport._stream_request(test_payload):
                pass


@pytest.mark.asyncio
async def test_sse_transport_parse_sse_event():
    """Test SseDriver parse_sse_event method."""
    driver = SseDriver("http://test", timeout=1)

    # Standard SSE event
    sse_event = 'event: message\ndata: {"id": 1, "result": "success"}'
    result = driver.parse_sse_event(sse_event)
    assert result == {"id": 1, "result": "success"}

    # Multiline data
    sse_event = 'event: message\ndata: {"id": 1,\ndata: "result": "multiline"}'
    result = driver.parse_sse_event(sse_event)
    assert result == {"id": 1, "result": "multiline"}

    # With retry field (should ignore)
    sse_event = 'retry: 3000\nevent: message\ndata: {"id": 1}'
    result = driver.parse_sse_event(sse_event)
    assert result == {"id": 1}

    # Empty event
    assert driver.parse_sse_event("") is None

    # Invalid JSON
    sse_event = "event: message\ndata: not_json"
    with pytest.raises(json.JSONDecodeError):
        driver.parse_sse_event(sse_event)


# Test cases for StdioDriver class
@pytest.fixture
def stdio_transport():
    """Fixture for StdioDriver test cases."""
    with patch("mcp_fuzzer.transport.drivers.stdio_driver.sys") as mock_sys:
        transport = StdioDriver("test_command")
        transport._sys = mock_sys  # Attach the mock to the transport
        yield transport


@pytest.mark.asyncio
async def test_stdio_transport_init(stdio_transport):
    """Test StdioDriver initialization."""
    assert stdio_transport.request_id == 1


@pytest.mark.skip(
        reason=(
            "Test isolation issue: send_request requires complex mocking of "
            "stdin/stdout that can interfere with pytest's capture system. "
            "This functionality is better covered by integration tests."
        )
    )
@pytest.mark.asyncio
async def test_stdio_transport_send_request(stdio_transport):
    """Test StdioDriver send_request method."""
    # This test is skipped - functionality is covered in integration tests
    pass


@pytest.mark.skip(
        reason=(
            "Test isolation issue: send_request error handling requires complex "
            "mocking of stdin/stdout that can interfere with pytest's capture "
            "system. This functionality is better covered by integration tests."
        )
    )
@pytest.mark.asyncio
async def test_stdio_transport_send_request_error(stdio_transport):
    """Test StdioDriver send_request with error response."""
    # This test is skipped - functionality is covered in integration tests
    pass


@pytest.mark.skip(
        reason=(
            "Test isolation issue: send_request invalid JSON handling requires "
            "complex mocking of stdin/stdout that can interfere with pytest's "
            "capture system. This functionality is better covered by integration "
            "tests."
        )
    )
@pytest.mark.asyncio
async def test_stdio_transport_send_request_invalid_json(stdio_transport):
    """Test StdioDriver send_request with invalid JSON response."""
    # This test is skipped - functionality is covered in integration tests
    pass


@pytest.mark.skip(
        reason=(
            "Test isolation issue: stream_request requires complex mocking of "
            "stdin/stdout that can interfere with pytest's capture system. "
            "This functionality is better covered by integration tests."
        )
    )
@pytest.mark.asyncio
async def test_stdio_transport_stream_request(stdio_transport):
    """Test StdioDriver stream_request method."""
    # This test is skipped - functionality is covered in integration tests
    pass


# Test cases for build_driver function
def test_build_driver_http():
    """Test build_driver with HTTP URL."""
    transport = build_driver("http://example.com/api")
    assert isinstance(transport, HttpDriver)
    assert transport.url == "http://example.com/api"


def test_build_driver_https():
    """Test build_driver with HTTPS URL."""
    transport = build_driver("https://example.com/api")
    assert isinstance(transport, HttpDriver)
    assert transport.url == "https://example.com/api"


def test_build_driver_sse():
    """Test build_driver with SSE URL."""
    transport = build_driver("sse://example.com/events")
    assert isinstance(transport, SseDriver)
    assert transport.url == "http://example.com/events"


def test_build_driver_stdio():
    """Test build_driver with stdio URL."""
    transport = build_driver("stdio:")
    assert isinstance(transport, StdioDriver)


def test_build_driver_protocol_and_endpoint_builtin():
    """Ensure built-in transports work with protocol+endpoint usage."""
    transport = build_driver("stdio", "node server.js")
    assert isinstance(transport, StdioDriver)
    assert transport.command == "node server.js"


def test_build_driver_invalid_scheme():
    """Test build_driver with invalid URL scheme."""
    with pytest.raises(TransportRegistrationError):
        build_driver("invalid://example.com")
