#!/usr/bin/env python3
"""
Unit tests for SseDriver.
"""

from unittest.mock import MagicMock

import pytest

from mcp_fuzzer.transport.drivers.sse_driver import SseDriver


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
async def test_stream_request_with_sync_chunks(monkeypatch):
    response = FakeStreamResponse(text_chunks=['data: {"a": 1}\n\n'])
    client = FakeClient(response)
    driver = SseDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    items = []
    async for item in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
        items.append(item)

    assert items == [{"a": 1}]
