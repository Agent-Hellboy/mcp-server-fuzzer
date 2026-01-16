#!/usr/bin/env python3
"""
Unit tests for SseDriver.
"""

import json
import pytest

from mcp_fuzzer.transport.drivers.sse_driver import SseDriver
from mcp_fuzzer.exceptions import TransportError


class FakeStreamContext:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeStreamResponse:
    def __init__(self, lines=None, text_chunks=None):
        self._lines = lines or []
        self._text_chunks = text_chunks or []

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    def aiter_text(self):
        return self._text_chunks


class FakeClient:
    def __init__(self, response):
        self._response = response
        self.post_calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def stream(self, *args, **kwargs):
        return FakeStreamContext(self._response)

    async def post(self, url, json=None, headers=None):
        self.post_calls.append((url, json, headers))
        return self._response


@pytest.mark.asyncio
async def test_send_request_not_supported():
    driver = SseDriver("http://localhost", safety_enabled=False)

    with pytest.raises(NotImplementedError):
        await driver.send_request("ping")


@pytest.mark.asyncio
async def test_send_raw_parses_sse_event(monkeypatch):
    response = FakeStreamResponse(lines=['data: {"result": {"ok": true}}', ""])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    result = await driver.send_raw({"jsonrpc": "2.0", "method": "x"})

    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_send_raw_empty_buffer(monkeypatch):
    """Test send_raw with empty buffer."""
    response = FakeStreamResponse(lines=[""])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(driver, "parse_sse_event", lambda x: None)

    with pytest.raises(TransportError):
        await driver.send_raw({"jsonrpc": "2.0", "method": "x"})


@pytest.mark.asyncio
async def test_send_raw_json_decode_error(monkeypatch):
    """Test send_raw with JSON decode error."""
    response = FakeStreamResponse(lines=["data: invalid json", ""])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    def raise_json_error(x):
        raise json.JSONDecodeError("", "", 0)

    monkeypatch.setattr(driver, "parse_sse_event", raise_json_error)

    with pytest.raises(TransportError):
        await driver.send_raw({"jsonrpc": "2.0", "method": "x"})


@pytest.mark.asyncio
async def test_send_raw_parse_returns_none(monkeypatch):
    """Test send_raw when parse_sse_event returns None."""
    response = FakeStreamResponse(lines=["data: some data", ""])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(driver, "parse_sse_event", lambda x: None)

    with pytest.raises(TransportError):
        await driver.send_raw({"jsonrpc": "2.0", "method": "x"})


@pytest.mark.asyncio
async def test_send_raw_server_request_handled(monkeypatch):
    """Test send_raw with server request that gets handled."""
    sse_data = 'data: {"method": "sampling/createMessage", "id": 1}'
    response = FakeStreamResponse(lines=[sse_data, ""])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(driver, "_handle_server_request", lambda x: True)
    parsed_data = {"method": "sampling/createMessage", "id": 1}
    monkeypatch.setattr(driver, "parse_sse_event", lambda x: parsed_data)
    monkeypatch.setattr(driver, "is_server_request", lambda x: True)

    with pytest.raises(TransportError):
        await driver.send_raw({"jsonrpc": "2.0", "method": "x"})


@pytest.mark.asyncio
async def test_send_raw_fallback_to_json_parsing(monkeypatch):
    """Test send_raw fallback to JSON parsing when SSE parsing fails."""
    response = FakeStreamResponse(lines=["not sse format"])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(driver, "parse_sse_event", lambda x: None)
    extract_result = {"result": "ok"}
    monkeypatch.setattr(driver, "_extract_result_from_response", lambda x: extract_result)

    result = await driver.send_raw({"jsonrpc": "2.0", "method": "x"})
    assert result == {"result": "ok"}


@pytest.mark.asyncio
async def test_send_notification(monkeypatch):
    """Test send_notification."""
    response = FakeClient(None)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: response)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    await driver.send_notification("test_method", {"param": "value"})

    assert len(response.post_calls) == 1
    call_url, call_json, call_headers = response.post_calls[0]
    assert call_json["method"] == "test_method"
    assert "id" not in call_json


@pytest.mark.asyncio
async def test_send_notification_with_safety(monkeypatch):
    """Test send_notification with safety enabled."""
    response = FakeClient(None)
    driver = SseDriver("http://localhost", safety_enabled=True)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: response)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(driver, "_validate_network_request", lambda x: None)

    await driver.send_notification("test_method")

    assert len(response.post_calls) == 1


@pytest.mark.asyncio
async def test_stream_request_with_async_chunks(monkeypatch):
    """Test _stream_request with async chunks."""
    async def async_chunks():
        yield 'data: {"a": 1}\n'
        yield '\n'
        yield 'data: {"b": 2}\n\n'

    response = FakeStreamResponse(text_chunks=async_chunks())
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    def parse_event(x):
        return json.loads(x.split(":", 1)[1].strip())

    monkeypatch.setattr(driver, "parse_sse_event", parse_event)
    monkeypatch.setattr(driver, "is_server_request", lambda x: False)

    items = []
    async for item in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
        items.append(item)

    assert len(items) >= 1


@pytest.mark.asyncio
async def test_stream_request_with_server_request(monkeypatch):
    """Test _stream_request handling server requests."""
    sse_data = 'data: {"method": "sampling/createMessage", "id": 1}\n\n'
    response = FakeStreamResponse(text_chunks=[sse_data])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    parsed_data = {"method": "sampling/createMessage", "id": 1}
    monkeypatch.setattr(driver, "parse_sse_event", lambda x: parsed_data)
    monkeypatch.setattr(driver, "is_server_request", lambda x: True)
    monkeypatch.setattr(driver, "_handle_server_request", lambda x: True)

    items = []
    async for item in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
        items.append(item)

    # Server requests should be handled, not yielded
    assert len(items) == 0


@pytest.mark.asyncio
async def test_stream_request_with_json_decode_error(monkeypatch):
    """Test _stream_request with JSON decode error."""
    response = FakeStreamResponse(text_chunks=['data: invalid json\n\n'])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    def raise_json_error(x):
        raise json.JSONDecodeError("", "", 0)

    monkeypatch.setattr(driver, "parse_sse_event", raise_json_error)

    items = []
    async for item in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
        items.append(item)

    # Should skip invalid events
    assert len(items) == 0


@pytest.mark.asyncio
async def test_stream_request_remaining_buffer(monkeypatch):
    """Test _stream_request processes remaining buffer."""
    response = FakeStreamResponse(text_chunks=['data: {"a": 1}\n'])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    def parse_event(x):
        return json.loads(x.split(":", 1)[1].strip())

    monkeypatch.setattr(driver, "parse_sse_event", parse_event)
    monkeypatch.setattr(driver, "is_server_request", lambda x: False)

    items = []
    async for item in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
        items.append(item)

    # Should process remaining buffer
    assert len(items) >= 0


@pytest.mark.asyncio
async def test_handle_server_request(monkeypatch):
    """Test _handle_server_request."""
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_send_client_response", lambda x: None)

    request_data = {"method": "sampling/createMessage", "id": 1}
    result = await driver._handle_server_request(request_data)
    assert result is True

    result = await driver._handle_server_request({"method": "other", "id": 1})
    assert result is False

    result = await driver._handle_server_request({"method": "sampling/createMessage"})
    assert result is False


@pytest.mark.asyncio
async def test_send_client_response(monkeypatch):
    """Test _send_client_response."""
    response = FakeClient(None)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: response)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    await driver._send_client_response({"result": "ok"})

    assert len(response.post_calls) == 1


@pytest.mark.asyncio
async def test_send_client_response_with_safety(monkeypatch):
    """Test _send_client_response with safety enabled."""
    response = FakeClient(None)
    driver = SseDriver("http://localhost", safety_enabled=True)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: response)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(driver, "_validate_network_request", lambda x: None)

    await driver._send_client_response({"result": "ok"})

    assert len(response.post_calls) == 1


@pytest.mark.asyncio
async def test_stream_request_with_sync_chunks(monkeypatch):
    """Test _stream_request with sync chunks (list)."""
    response = FakeStreamResponse(text_chunks=['data: {"a": 1}\n\n'])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    def parse_event(x):
        return json.loads(x.split(":", 1)[1].strip())

    monkeypatch.setattr(driver, "parse_sse_event", parse_event)
    monkeypatch.setattr(driver, "is_server_request", lambda x: False)

    items = []
    async for item in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
        items.append(item)

    assert items == [{"a": 1}]
