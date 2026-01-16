#!/usr/bin/env python3
"""
Unit tests for HttpDriver.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from mcp_fuzzer.transport.drivers.http_driver import HttpDriver


class FakeResponse:
    def __init__(self, payload, status_code=200, headers=None, lines=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.text = ""
        self._lines = lines or []

    def json(self):
        return self._payload

    async def aclose(self):
        return None

    async def aiter_lines(self):
        for line in self._lines:
            yield line


class FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.post_calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json=None, headers=None, stream=False):
        self.post_calls.append((url, json, headers, stream))
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_send_request_success(monkeypatch):
    response = FakeResponse({"result": {"ok": True}})
    client = FakeClient([response])
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=MagicMock(),
    )
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    result = await driver.send_request("ping", {"x": 1})

    assert result == {"ok": True}
    assert client.post_calls


@pytest.mark.asyncio
async def test_send_raw_with_redirect(monkeypatch):
    first = FakeResponse(
        {"result": {"ok": True}},
        status_code=307,
        headers={"location": "http://redirect"},
    )
    second = FakeResponse({"result": {"ok": True}})
    client = FakeClient([first, second])
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=MagicMock(),
    )
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    
    monkeypatch.setitem(
        driver._resolve_redirect_url.__globals__,
        "safety_policy",
        SimpleNamespace(resolve_redirect_safely=lambda base, location: location),
    )

    result = await driver.send_raw({"jsonrpc": "2.0", "method": "x"})

    assert result == {"ok": True}
    assert len(client.post_calls) == 2


@pytest.mark.asyncio
async def test_send_notification(monkeypatch):
    response = FakeResponse({"result": {"ok": True}})
    client = FakeClient([response])
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=MagicMock(),
    )
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(
        driver,
        "_validate_jsonrpc_payload",
        lambda payload, strict=False: None,
    )

    await driver.send_notification("notify", {"x": 1})

    assert client.post_calls


@pytest.mark.asyncio
async def test_stream_request_parses_lines(monkeypatch):
    lines = [json.dumps({"result": 1}), 'data: {"result": 2}']
    response = FakeResponse({}, lines=lines)
    client = FakeClient([response])
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=MagicMock(),
    )
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    chunks = []
    async for item in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
        chunks.append(item)

    assert chunks == [{"result": 1}, {"result": 2}]
