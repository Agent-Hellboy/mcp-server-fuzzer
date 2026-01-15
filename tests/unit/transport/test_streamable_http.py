import asyncio
import types
from typing import Any, Dict, List, Optional, Union
from unittest.mock import AsyncMock, patch

import pytest
from mcp_fuzzer.transport.drivers.stream_http_driver import (
    StreamHttpDriver,
    CONTENT_TYPE,
)
from mcp_fuzzer.config import DEFAULT_PROTOCOL_VERSION
from mcp_fuzzer.exceptions import TransportError


# Force anyio to use asyncio backend for these tests (no trio dependency required)
@pytest.fixture
def anyio_backend():
    return "asyncio"


class _DummyResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        content_type: str = "application/json",
    ) -> None:
        self.status_code = status_code
        self._json = json_body
        self.headers = {CONTENT_TYPE: content_type}
        if headers:
            self.headers.update(headers)

    def raise_for_status(self) -> None:  # pragma: no cover - simple stub
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP error: {self.status_code}")

    def json(self) -> Any:
        return self._json


class _DummySSEStreamResponse:
    def __init__(
        self,
        *,
        headers: Optional[Dict[str, str]] = None,
        lines: Union[List[str], None] = None,
    ) -> None:
        self.status_code = 200
        self.headers = {CONTENT_TYPE: "text/event-stream"}
        if headers:
            self.headers.update(headers)
        self._lines = lines or []

    def raise_for_status(self) -> None:  # pragma: no cover - simple stub
        pass

    async def aiter_lines(
        self,
    ):  # pragma: no cover - behavior validated via result
        for line in self._lines:
            # Simulate network scheduling
            await asyncio.sleep(0)
            yield line


class _FakeAsyncClient:
    def __init__(self, responses: List[Any]):
        self._responses = list(responses)
        self.calls: List[Dict[str, Any]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url: str, json: Dict[str, Any], headers: Dict[str, str]):
        self.calls.append({"url": url, "json": json, "headers": headers})
        if not self._responses:
            raise AssertionError("No more fake responses queued")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.mark.anyio("asyncio")
async def test_streamable_http_json_initialize(monkeypatch):
    # Arrange: first call returns JSON initialize with session header
    init_result = {"protocolVersion": DEFAULT_PROTOCOL_VERSION, "ok": True}
    resp1 = _DummyResponse(
        headers={"mcp-session-id": "sess-123"},
        json_body={"jsonrpc": "2.0", "id": "1", "result": init_result},
        content_type="application/json",
    )
    # Second call returns plain JSON result
    resp2 = _DummyResponse(
        json_body={"jsonrpc": "2.0", "id": "2", "result": {"tools": []}},
        content_type="application/json",
    )
    # After centralizing initialized notification in _do_initialize, the
    # explicit initialize call does not emit a notification here.
    fake = _FakeAsyncClient([resp1, resp2])

    # Patch httpx.AsyncClient to our fake
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: fake)

    t = StreamHttpDriver("http://test/mcp", timeout=1)

    # Act: initialize
    result = await t.send_request("initialize", {"params": {}})

    # Assert: protocol and session headers captured
    assert result == init_result
    assert t.session_id == "sess-123"
    assert t.protocol_version == DEFAULT_PROTOCOL_VERSION

    # Act: second request should include headers
    result2 = await t.send_request("tools/list", {})
    assert result2 == {"tools": []}
    # Verify last call included session + protocol headers
    last_headers = fake.calls[-1]["headers"]
    assert last_headers.get("mcp-session-id") == "sess-123"
    assert last_headers.get("mcp-protocol-version") == DEFAULT_PROTOCOL_VERSION


@pytest.mark.anyio("asyncio")
async def test_streamable_http_sse_response(monkeypatch):
    # Arrange: SSE data with one JSON-RPC response containing result
    sse_lines = [
        "id: 1",
        "event: message",
        'data: {"jsonrpc": "2.0", "id": "1", "result": {"ok": true}}',
        "",  # dispatch
    ]
    resp = _DummySSEStreamResponse(
        headers={"mcp-session-id": "sess-xyz"}, lines=sse_lines
    )
    fake = _FakeAsyncClient([resp])

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: fake)

    t = StreamHttpDriver("http://test/mcp", timeout=1)

    # Act
    result = await t.send_request("initialize", {})

    # Assert
    assert result == {"ok": True}
    assert t.session_id == "sess-xyz"


@pytest.mark.anyio("asyncio")
async def test_streamable_http_sse_handles_server_request(monkeypatch):
    sse_lines = [
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
    resp = _DummySSEStreamResponse(lines=sse_lines)
    fake = _FakeAsyncClient([resp])

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: fake)

    t = StreamHttpDriver("http://test/mcp", timeout=1)
    t._initialized = True

    with patch.object(t, "_send_client_response", new=AsyncMock()) as mock_send:
        result = await t.send_raw(
            {"jsonrpc": "2.0", "id": "1", "method": "ping", "params": {}}
        )

    assert result == {"ok": True}
    mock_send.assert_awaited_once()
    sent_payload = mock_send.await_args.args[0]
    assert sent_payload["id"] == "srv-1"
    assert sent_payload["jsonrpc"] == "2.0"
    assert "result" in sent_payload


@pytest.mark.anyio("asyncio")
async def test_streamable_http_wraps_http_status_error(monkeypatch):
    import httpx

    bad_request = httpx.Request("POST", "http://test/mcp")
    bad_response = httpx.Response(500, request=bad_request)
    fake = _FakeAsyncClient([bad_response])
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: fake)

    transport = StreamHttpDriver("http://test/mcp", timeout=1)
    transport._initialized = True

    with pytest.raises(TransportError) as excinfo:
        await transport.send_raw(
            {"jsonrpc": "2.0", "id": "1", "method": "tools/list", "params": {}}
        )

    assert excinfo.value.context["status"] == 500
    assert excinfo.value.context["url"].startswith("http://test/mcp")


@pytest.mark.anyio("asyncio")
async def test_streamable_http_wraps_connect_errors(monkeypatch):
    import httpx

    req = httpx.Request("POST", "http://test/mcp")
    connect_exc = httpx.ConnectError("boom", request=req)
    fake = _FakeAsyncClient([connect_exc])
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: fake)

    transport = StreamHttpDriver("http://test/mcp", timeout=1)
    transport._initialized = True

    with pytest.raises(TransportError) as excinfo:
        await transport.send_raw(
            {"jsonrpc": "2.0", "id": "1", "method": "custom.call", "params": {}}
        )

    assert excinfo.value.context["error_type"] == "ConnectError"
    assert excinfo.value.context["method"] == "custom.call"
    assert excinfo.value.context["attempts"] == 1
