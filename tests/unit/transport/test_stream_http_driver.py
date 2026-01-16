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


class FakeResponse:
    def __init__(self, status_code=200, headers=None, lines=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._lines = lines or []

    async def aiter_lines(self):
        for line in self._lines:
            yield line


class MockClientContext:
    """Mock async context manager for httpx client."""

    def __init__(self, client):
        self.client = client

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, exc_type, exc, tb):
        return False


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


@pytest.mark.asyncio
async def test_parse_sse_response_for_result():
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(lines=['data: {"result": {"protocolVersion": "v"}}', ""])

    result = await driver._parse_sse_response_for_result(response)

    assert result == {"protocolVersion": "v"}
    assert driver.protocol_version == "v"


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
            "unknown: field",  # Unknown fields are treated as data continuation
            'data: {"result": {"ok": true}}',
            "",
        ]
    )

    result = await driver._parse_sse_response_for_result(response)

    # Unknown fields are treated as data continuation, which breaks JSON parsing
    # So the result will be None because the combined data is not valid JSON
    assert result is None


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
