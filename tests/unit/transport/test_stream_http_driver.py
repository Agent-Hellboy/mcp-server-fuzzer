#!/usr/bin/env python3
"""
Unit tests for StreamHttpDriver helpers.
"""

import asyncio
import json
from unittest.mock import MagicMock, AsyncMock

import httpx
import pytest

from mcp_fuzzer.transport.drivers.stream_http_driver import StreamHttpDriver
from mcp_fuzzer.exceptions import TransportError


class FakeResponse:
    def __init__(self, status_code=200, headers=None, lines=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self._lines = lines or []
        self.text = text

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    async def aclose(self):
        return None

    def raise_for_status(self):
        return None


class FakeJsonResponse(FakeResponse):
    def __init__(self, status_code=200, headers=None, lines=None, json_data=None):
        super().__init__(status_code=status_code, headers=headers, lines=lines)
        self._json_data = json_data
        self.text = ""

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://localhost")
            raise httpx.HTTPStatusError(
                "error",
                request=request,
                response=self,
            )


class MockClientContext:
    """Mock async context manager for httpx client."""

    def __init__(self, client):
        self.client = client

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeStreamContext:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def stream(self, *_args, **_kwargs):
        return FakeStreamContext(self._responses.pop(0))

    async def post(self, *_args, **_kwargs):
        return self._responses.pop(0)


def create_mock_client_factory(client):
    """Factory to create mock _create_http_client replacement."""

    def mock_create_client(timeout):
        return MockClientContext(client)

    return mock_create_client


def test_prepare_headers_with_session():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    driver.session_id = "sid"
    driver.protocol_version = "2025-06-18"

    headers = driver._prepare_headers()

    assert headers["mcp-session-id"] == "sid"
    assert headers["mcp-protocol-version"] == "2025-06-18"


def test_extract_session_headers():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(
        headers={"mcp-session-id": "sid", "mcp-protocol-version": "v"}
    )

    driver._maybe_extract_session_headers(response)

    assert driver.session_id == "sid"
    assert driver.protocol_version == "v"


def test_extract_protocol_version_from_result():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    driver._maybe_extract_protocol_version_from_result({"protocolVersion": "v"})
    assert driver.protocol_version == "v"


def test_resolve_redirect(monkeypatch):
    """Test resolve_redirect method."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(status_code=307, headers={"location": "http://redirect"})
    monkeypatch.setitem(
        driver._resolve_redirect.__globals__,
        "resolve_redirect_safely",
        lambda base, location: location,
    )

    result = driver._resolve_redirect(response)

    assert result == "http://redirect"


def test_resolve_redirect_falls_back_to_trailing_slash(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(status_code=307, headers={})

    monkeypatch.setitem(
        driver._resolve_redirect.__globals__,
        "resolve_redirect_safely",
        lambda _base, location: location,
    )

    assert driver._resolve_redirect(response) == "http://localhost/"


def test_resolve_redirect_rejected(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(status_code=307, headers={"location": "http://evil"})

    monkeypatch.setitem(
        driver._resolve_redirect.__globals__,
        "resolve_redirect_safely",
        lambda _base, _location: None,
    )

    assert driver._resolve_redirect(response) is None


def test_resolve_redirect_missing_location_with_trailing_slash():
    driver = StreamHttpDriver("http://localhost/", safety_enabled=False)
    response = FakeResponse(status_code=307, headers={})

    assert driver._resolve_redirect(response) is None


@pytest.mark.asyncio
async def test_parse_sse_response_for_result():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(lines=['data: {"result": {"protocolVersion": "v"}}', ""])

    result = await driver._parse_sse_response_for_result(response)

    assert result == {"protocolVersion": "v"}
    assert driver.protocol_version == "v"


@pytest.mark.asyncio
async def test_parse_sse_response_handles_server_request_then_error(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    driver._send_client_response = AsyncMock()

    lines = [
        'data: {"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage"}',
        "",
        'data: {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}}',
        "",
    ]
    response = FakeResponse(lines=lines)

    result = await driver._parse_sse_response_for_result(response)

    assert result["error"]["message"] == "x"
    driver._send_client_response.assert_called_once()


@pytest.mark.asyncio
async def test_parse_sse_response_result_updates_protocol_version():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    lines = [
        'data: {"jsonrpc": "2.0", "result": {"protocolVersion": "2025-11-25"}}',
        "",
    ]
    response = FakeResponse(lines=lines)

    result = await driver._parse_sse_response_for_result(response)

    assert result["protocolVersion"] == "2025-11-25"
    assert driver.protocol_version == "2025-11-25"


@pytest.mark.asyncio
async def test_parse_sse_response_skips_invalid_json_then_returns_result():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    lines = [
        "data: {not json}",
        "",
        'data: {"jsonrpc": "2.0", "result": {"ok": true}}',
        "",
    ]
    response = FakeResponse(lines=lines)

    result = await driver._parse_sse_response_for_result(response)

    assert result["ok"] is True


def test_maybe_extract_protocol_version_handles_error():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)

    class BadDict(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    driver._maybe_extract_protocol_version_from_result(
        BadDict({"protocolVersion": "x"})
    )


@pytest.mark.asyncio
async def test_post_with_retries_success_after_retry(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse()
    client = MagicMock()
    client.post = AsyncMock(side_effect=[httpx.ConnectError("boom"), response])
    monkeypatch.setattr(asyncio, "sleep", AsyncMock())

    result = await driver._post_with_retries(
        client,
        "http://localhost",
        {"method": "initialize"},
        {},
        retries=1,
    )

    assert result is response


@pytest.mark.asyncio
async def test_post_with_retries_retries_on_safe_method(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    calls = {"count": 0}

    class StubClient:
        async def post(self, *_args, **_kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                raise httpx.ConnectError("fail")
            return FakeResponse()

    monkeypatch.setattr(asyncio, "sleep", AsyncMock())

    response = await driver._post_with_retries(
        StubClient(),
        "http://localhost",
        {"method": "initialize"},
        {},
        retries=1,
    )

    assert isinstance(response, FakeResponse)
    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_post_with_retries_raises_for_unsafe_method():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)

    class StubClient:
        async def post(self, *_args, **_kwargs):
            raise httpx.ConnectError("fail")

    with pytest.raises(TransportError):
        await driver._post_with_retries(
            StubClient(),
            "http://localhost",
            {"method": "tools/call"},
            {},
            retries=0,
        )


@pytest.mark.asyncio
async def test_post_with_retries_payload_get_raises():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)

    class Payload:
        def get(self, *_args, **_kwargs):
            raise AttributeError("missing")

    class StubClient:
        async def post(self, *_args, **_kwargs):
            raise httpx.ConnectError("fail")

    with pytest.raises(TransportError):
        await driver._post_with_retries(
            StubClient(),
            "http://localhost",
            Payload(),
            {},
            retries=0,
        )


def test_prepare_headers_with_auth_safety_disabled():
    """Test _prepare_headers_with_auth when safety is disabled."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    driver.auth_headers = {"Authorization": "Bearer token"}
    headers = {"Content-Type": "application/json"}

    result = driver._prepare_headers_with_auth(headers)

    assert result["Content-Type"] == "application/json"
    assert result["Authorization"] == "Bearer token"


def test_prepare_headers_without_session():
    """Test _prepare_headers without session information."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    driver.session_id = None
    driver.protocol_version = None

    headers = driver._prepare_headers()

    assert "mcp-session-id" not in headers
    assert "mcp-protocol-version" not in headers


def test_extract_protocol_version_from_result_exception():
    """Test _maybe_extract_protocol_version_from_result handles exceptions."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)

    # Test with non-dict result
    driver._maybe_extract_protocol_version_from_result("not a dict")
    assert driver.protocol_version is None

    # Test with dict missing protocolVersion
    driver._maybe_extract_protocol_version_from_result({"other": "value"})
    assert driver.protocol_version is None

    # Test with None protocolVersion
    driver._maybe_extract_protocol_version_from_result({"protocolVersion": None})
    assert driver.protocol_version is None


@pytest.mark.asyncio
async def test_parse_sse_response_json_decode_error():
    """Test _parse_sse_response_for_result handles JSON decode errors."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(lines=['data: invalid json', ""])

    result = await driver._parse_sse_response_for_result(response)

    assert result is None


@pytest.mark.asyncio
async def test_parse_sse_response_error_passthrough():
    """Test _parse_sse_response_for_result passes through errors."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    error_payload = {"error": {"code": -1, "message": "Test error"}}
    response = FakeResponse(
        lines=[f'data: {json.dumps(error_payload)}', ""]
    )

    result = await driver._parse_sse_response_for_result(response)

    assert result == error_payload


@pytest.mark.asyncio
async def test_parse_sse_response_comment_lines():
    """Test _parse_sse_response_for_result ignores comment lines."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(
        lines=[
            ":comment line",
            'data: {"result": {"ok": true}}',
            "",
        ]
    )

    result = await driver._parse_sse_response_for_result(response)

    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_parse_sse_response_unknown_field():
    """Test _parse_sse_response_for_result handles unknown fields."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(
        lines=[
            "unknown: field",  # Unknown fields are ignored
            'data: {"result": {"ok": true}}',
            "",
        ]
    )

    result = await driver._parse_sse_response_for_result(response)

    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_parse_sse_response_no_response():
    """Test _parse_sse_response_for_result returns None when no response."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(lines=[])

    result = await driver._parse_sse_response_for_result(response)

    assert result is None


@pytest.mark.asyncio
async def test_handle_server_request_non_matching_method():
    """Test _handle_server_request with non-matching method."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    payload = {"method": "other/method", "id": 1}

    result = await driver._handle_server_request(payload)

    assert result is False


@pytest.mark.asyncio
async def test_handle_server_request_missing_id():
    """Test _handle_server_request with missing id."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    payload = {"method": "sampling/createMessage"}

    result = await driver._handle_server_request(payload)

    assert result is False


@pytest.mark.asyncio
async def test_send_client_response_with_redirect(monkeypatch):
    """Test _send_client_response handles redirects."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    first_response = FakeResponse(status_code=307, headers={"location": "http://redirect"})
    second_response = FakeResponse()

    client = MagicMock()
    client.post = AsyncMock(side_effect=[first_response, second_response])
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    monkeypatch.setattr(
        driver, "_create_http_client", create_mock_client_factory(client)
    )
    monkeypatch.setattr(
        driver, "_resolve_redirect", lambda resp: "http://redirect"
    )
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    await driver._send_client_response({"result": "ok"})

    assert client.post.call_count == 2


@pytest.mark.asyncio
async def test_send_client_response_with_safety(monkeypatch):
    """Test _send_client_response with safety enabled."""
    driver = StreamHttpDriver("http://localhost", safety_enabled=True)
    response = FakeResponse()

    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    monkeypatch.setattr(
        driver, "_create_http_client", create_mock_client_factory(client)
    )
    monkeypatch.setattr(driver, "_validate_network_request", lambda url: None)
    monkeypatch.setattr(driver, "_resolve_redirect", lambda resp: None)
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda resp: None)

    await driver._send_client_response({"result": "ok"})

    client.post.assert_called_once()


@pytest.mark.asyncio
async def test_send_raw_json_sets_initialized_and_protocol_version(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeJsonResponse(
        headers={"content-type": "application/json"},
        json_data={"result": {"protocolVersion": "v1"}},
    )
    client = MagicMock()
    client.post = AsyncMock(return_value=response)

    monkeypatch.setattr(
        driver,
        "_create_http_client",
        create_mock_client_factory(client),
    )

    result = await driver.send_raw({"method": "initialize"})

    assert result == {"protocolVersion": "v1"}
    assert driver.protocol_version == "v1"
    assert driver._initialized is True


@pytest.mark.asyncio
async def test_send_raw_handles_status_codes(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)

    class StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *_args, **_kwargs):
            return FakeResponse(status_code=202, headers={})

    monkeypatch.setattr(driver, "_create_http_client", lambda _timeout: StubClient())
    monkeypatch.setattr(
        driver,
        "_post_with_retries",
        AsyncMock(return_value=FakeResponse(status_code=202, headers={})),
    )

    assert await driver.send_raw({"method": "ping"}) == {}

    not_found = FakeResponse(status_code=404, headers={})
    monkeypatch.setattr(driver, "_post_with_retries", AsyncMock(return_value=not_found))
    with pytest.raises(TransportError):
        await driver.send_raw({"method": "ping"})


@pytest.mark.asyncio
async def test_send_raw_not_found_raises(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeJsonResponse(
        status_code=404,
        headers={"content-type": "application/json"},
        json_data={"result": {}},
    )
    client = MagicMock()
    client.post = AsyncMock(return_value=response)

    monkeypatch.setattr(
        driver,
        "_create_http_client",
        create_mock_client_factory(client),
    )

    with pytest.raises(TransportError):
        await driver.send_raw({"method": "tools/list"})


@pytest.mark.asyncio
async def test_send_raw_unexpected_content_type(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    driver._initialized = True
    response = FakeResponse(status_code=200, headers={"content-type": "text/plain"})

    class StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *_args, **_kwargs):
            return response

    monkeypatch.setattr(driver, "_create_http_client", lambda _timeout: StubClient())
    monkeypatch.setattr(driver, "_post_with_retries", AsyncMock(return_value=response))
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)

    with pytest.raises(TransportError):
        await driver.send_raw({"method": "ping"})


@pytest.mark.asyncio
async def test_post_with_retries_unsafe_method(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    client = MagicMock()
    client.post = AsyncMock(side_effect=httpx.ConnectError("boom"))
    monkeypatch.setattr(asyncio, "sleep", AsyncMock())

    payload = {"method": "tools/call"}
    with pytest.raises(TransportError):
        await driver._post_with_retries(
            client,
            "http://localhost",
            payload,
            {},
            retries=2,
        )

    asyncio.sleep.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_raw_payload_get_attribute_error(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    driver._initialized = True
    response = FakeResponse(
        status_code=200,
        headers={"content-type": "application/json"},
    )

    class Payload:
        def get(self, *_args, **_kwargs):
            raise AttributeError("missing")

    class StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(driver, "_create_http_client", lambda _timeout: StubClient())
    monkeypatch.setattr(driver, "_post_with_retries", AsyncMock(return_value=response))
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)
    monkeypatch.setattr(
        driver,
        "_parse_http_response_json",
        lambda *_args, **_kwargs: {},
    )

    result = await driver.send_raw(Payload())

    assert result == {}


@pytest.mark.asyncio
async def test_send_notification_validates_when_safety_enabled(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=True)
    response = FakeResponse(status_code=200, headers={})

    class StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    validate = MagicMock()
    monkeypatch.setattr(driver, "_validate_network_request", validate)
    monkeypatch.setattr(driver, "_create_http_client", lambda _timeout: StubClient())
    monkeypatch.setattr(driver, "_post_with_retries", AsyncMock(return_value=response))
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)

    await driver.send_notification("ping", {})

    validate.assert_called_once_with(driver.url)


@pytest.mark.asyncio
async def test_do_initialize_ignores_notification_error(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    monkeypatch.setattr(driver, "send_raw", AsyncMock())
    monkeypatch.setattr(
        driver,
        "send_notification",
        AsyncMock(side_effect=RuntimeError("boom")),
    )

    await driver._do_initialize()

    assert driver._initialized is True


@pytest.mark.asyncio
async def test_yield_streamed_lines_parses_data(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(
        headers={},
        lines=["", "not json", "data: {bad}", 'data: {"ok": true}'],
    )
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)
    monkeypatch.setattr(driver, "_maybe_extract_session_headers", lambda _resp: None)

    items = [item async for item in driver._yield_streamed_lines(response)]

    assert items == [{"ok": True}]


@pytest.mark.asyncio
async def test_send_client_response_follows_redirect(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    first = FakeResponse(status_code=307, headers={"location": "http://redirect"})
    second = FakeResponse(status_code=200, headers={})

    monkeypatch.setattr(
        driver,
        "_post_with_retries",
        AsyncMock(side_effect=[first, second]),
    )
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)
    monkeypatch.setattr(driver, "_maybe_extract_session_headers", lambda _resp: None)
    monkeypatch.setitem(
        driver._resolve_redirect.__globals__,
        "resolve_redirect_safely",
        lambda _base, location: location,
    )

    await driver._send_client_response({"result": "ok"})

    assert driver._post_with_retries.call_count == 2


@pytest.mark.asyncio
async def test_send_raw_triggers_initialize(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(
        status_code=200,
        headers={"content-type": "application/json"},
    )

    monkeypatch.setattr(
        driver,
        "_create_http_client",
        lambda _timeout: FakeClient([response]),
    )
    monkeypatch.setattr(driver, "_post_with_retries", AsyncMock(return_value=response))
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)
    monkeypatch.setattr(
        driver,
        "_parse_http_response_json",
        lambda _resp, fallback_to_sse=False: {"ok": True},
    )

    driver._do_initialize = AsyncMock()
    result = await driver.send_raw({"method": "tools/list"})

    assert result == {"ok": True}
    driver._do_initialize.assert_called_once()


@pytest.mark.asyncio
async def test_send_raw_sse_none_returns_empty(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(
        status_code=200,
        headers={"content-type": "text/event-stream"},
    )

    monkeypatch.setattr(
        driver,
        "_create_http_client",
        lambda _timeout: FakeClient([response]),
    )
    monkeypatch.setattr(driver, "_post_with_retries", AsyncMock(return_value=response))
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)
    monkeypatch.setattr(
        driver,
        "_parse_sse_response_for_result",
        AsyncMock(return_value=None),
    )

    result = await driver.send_raw({"method": "initialize"})
    assert result == {}


@pytest.mark.asyncio
async def test_send_notification_follows_redirect(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    first = FakeResponse(status_code=307, headers={"location": "http://redirect"})
    second = FakeResponse(status_code=200, headers={})

    monkeypatch.setattr(
        driver,
        "_create_http_client",
        lambda _timeout: FakeClient([first, second]),
    )
    monkeypatch.setattr(
        driver,
        "_post_with_retries",
        AsyncMock(side_effect=[first, second]),
    )
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)
    monkeypatch.setitem(
        driver._resolve_redirect.__globals__,
        "resolve_redirect_safely",
        lambda _base, location: location,
    )

    await driver.send_notification("notify", {})


@pytest.mark.asyncio
async def test_stream_request_validates_when_safety_enabled(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=True)
    response = FakeResponse(status_code=200, headers={})

    class StubClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def stream(self, *_args, **_kwargs):
            return FakeStreamContext(response)

    validate = MagicMock()
    monkeypatch.setattr(driver, "_validate_network_request", validate)
    monkeypatch.setattr(driver, "_create_http_client", lambda _timeout: StubClient())

    async def _yield_lines(_response):
        yield {"ok": True}

    monkeypatch.setattr(driver, "_yield_streamed_lines", _yield_lines)

    items = [item async for item in driver._stream_request({"method": "ping"})]

    assert items == [{"ok": True}]
    validate.assert_called_once_with(driver.url)


@pytest.mark.asyncio
async def test_stream_request_redirect(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    first = FakeResponse(status_code=307, headers={"location": "http://redirect"})
    second = FakeResponse(status_code=200, headers={}, lines=['{"ok": true}'])

    monkeypatch.setattr(
        driver,
        "_create_http_client",
        lambda _timeout: FakeClient([first, second]),
    )
    monkeypatch.setattr(driver, "_handle_http_response_error", lambda _resp: None)
    monkeypatch.setitem(
        driver._resolve_redirect.__globals__,
        "resolve_redirect_safely",
        lambda _base, location: location,
    )

    items = [item async for item in driver._stream_request({"method": "tools/list"})]
    assert items == [{"ok": True}]


@pytest.mark.asyncio
async def test_send_client_response_posts_with_retries(monkeypatch):
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(status_code=200, headers={})

    monkeypatch.setattr(
        driver,
        "_create_http_client",
        lambda _timeout: FakeClient([response]),
    )
    monkeypatch.setattr(driver, "_post_with_retries", AsyncMock(return_value=response))

    await driver._send_client_response({"jsonrpc": "2.0"})

    driver._post_with_retries.assert_called_once()
