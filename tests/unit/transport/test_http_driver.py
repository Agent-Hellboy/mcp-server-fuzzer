#!/usr/bin/env python3
"""
Unit tests for HttpDriver.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

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


def test_prepare_headers_with_auth(monkeypatch):
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=True,
        auth_headers={"Authorization": "token"},
        process_manager=MagicMock(),
    )
    monkeypatch.setitem(
        driver._prepare_safe_headers.__globals__,
        "safety_policy",
        SimpleNamespace(sanitize_headers=lambda headers: {"X-Test": "1"}),
    )
    headers = driver._prepare_headers_with_auth({"Accept": "json"})
    assert headers["X-Test"] == "1"
    assert headers["Authorization"] == "token"


def test_resolve_redirect_url_denied(monkeypatch):
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=MagicMock(),
    )
    response = FakeResponse({}, status_code=307, headers={})
    assert driver._resolve_redirect_url(response) is None

    response = FakeResponse(
        {},
        status_code=307,
        headers={"location": "http://evil"},
    )
    monkeypatch.setitem(
        driver._resolve_redirect_url.__globals__,
        "safety_policy",
        SimpleNamespace(resolve_redirect_safely=lambda base, location: None),
    )
    assert driver._resolve_redirect_url(response) is None


@pytest.mark.asyncio
async def test_stream_request_coroutine_lines(monkeypatch):
    class FakeResponseWithCoroutine(FakeResponse):
        async def aiter_lines(self):
            async def _generator():
                for line in ['{"result": 3}']:
                    yield line

            return _generator()

    response = FakeResponseWithCoroutine({}, lines=[])
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

    assert chunks == [{"result": 3}]


@pytest.mark.asyncio
async def test_send_request_initialize_with_redirect(monkeypatch):
    first = FakeResponse(
        {"result": {"protocolVersion": "2025-11-25"}},
        status_code=307,
        headers={"location": "http://redirect"},
    )
    second = FakeResponse({"result": {"protocolVersion": "2025-11-25"}})
    client = FakeClient([first, second])
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=True,
        process_manager=MagicMock(),
    )
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(driver, "_validate_network_request", lambda url: None)
    monkeypatch.setitem(
        driver._resolve_redirect_url.__globals__,
        "safety_policy",
        SimpleNamespace(resolve_redirect_safely=lambda base, location: location),
    )
    seen = {}
    monkeypatch.setitem(
        driver.send_request.__globals__,
        "maybe_update_spec_version_from_result",
        lambda result: seen.setdefault("pv", result.get("protocolVersion")),
    )

    result = await driver.send_request("initialize", {"x": 1})
    assert result["protocolVersion"] == "2025-11-25"
    assert seen["pv"] == "2025-11-25"


@pytest.mark.asyncio
async def test_send_raw_invalid_payload_logs(monkeypatch):
    response = FakeResponse({"result": {"ok": True}})
    client = FakeClient([response])
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=MagicMock(),
    )
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    def _raise_bad(*_args, **_kwargs):
        raise ValueError("bad")

    monkeypatch.setattr(driver, "_validate_jsonrpc_payload", _raise_bad)
    monkeypatch.setattr(
        driver,
        "_validate_payload_serializable",
        lambda *_args, **_kwargs: None,
    )

    result = await driver.send_raw({"jsonrpc": "2.0", "method": "x"})
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_send_notification_redirect(monkeypatch):
    first = FakeResponse(
        {"result": {}},
        status_code=307,
        headers={"location": "http://redirect"},
    )
    second = FakeResponse({"result": {}})
    client = FakeClient([first, second])
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=True,
        process_manager=MagicMock(),
    )
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    monkeypatch.setattr(driver, "_validate_network_request", lambda url: None)
    monkeypatch.setitem(
        driver._resolve_redirect_url.__globals__,
        "safety_policy",
        SimpleNamespace(resolve_redirect_safely=lambda base, location: location),
    )
    monkeypatch.setattr(
        driver,
        "_validate_jsonrpc_payload",
        lambda payload, strict=False: None,
    )

    await driver.send_notification("notify", {"x": 1})


@pytest.mark.asyncio
async def test_stream_request_handles_invalid_json(monkeypatch):
    lines = ["{bad}", 'data: {bad}', ""]
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

    assert chunks == []


@pytest.mark.asyncio
async def test_send_raw_initialize_updates_spec(monkeypatch):
    response = FakeResponse({"result": {"protocolVersion": "2025-11-25"}})
    client = FakeClient([response])
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=MagicMock(),
    )
    monkeypatch.setattr(driver, "_create_http_client", lambda timeout: client)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)
    seen = {}
    monkeypatch.setitem(
        driver.send_raw.__globals__,
        "maybe_update_spec_version_from_result",
        lambda result: seen.setdefault("pv", result.get("protocolVersion")),
    )

    result = await driver.send_raw({"jsonrpc": "2.0", "method": "initialize"})
    assert result["protocolVersion"] == "2025-11-25"
    assert seen["pv"] == "2025-11-25"


@pytest.mark.asyncio
async def test_get_process_stats_and_timeout_signal(monkeypatch):
    pm = MagicMock()
    pm.get_stats = AsyncMock(return_value={"ok": True})
    pm.send_timeout_signal_to_all = AsyncMock(return_value={1: True})
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=pm,
    )

    assert await driver.get_process_stats() == {"ok": True}
    assert await driver.send_timeout_signal_to_all() == {1: True}


@pytest.mark.asyncio
async def test_stream_request_redirect_closes_response(monkeypatch):
    class TrackingResponse(FakeResponse):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.closed = False

        async def aclose(self):
            self.closed = True

    first = TrackingResponse(
        {}, status_code=307, headers={"location": "http://redirect"}
    )
    second = TrackingResponse({}, lines=[])
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

    items = []
    async for item in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
        items.append(item)
    assert items == []
    assert first.closed is True


@pytest.mark.asyncio
async def test_http_driver_close_handles_shutdown_error():
    pm = MagicMock()
    pm.shutdown = AsyncMock(side_effect=RuntimeError("boom"))
    driver = HttpDriver(
        "http://localhost",
        safety_enabled=False,
        process_manager=pm,
    )
    driver._owns_process_manager = True

    await driver.close()
