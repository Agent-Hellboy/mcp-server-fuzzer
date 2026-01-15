#!/usr/bin/env python3
"""
Unit tests for StreamHttpDriver helpers.
"""

import asyncio
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
    driver = StreamHttpDriver("http://localhost", safety_enabled=False)
    response = FakeResponse(status_code=307, headers={"location": "http://r"})
    monkeypatch.setattr(
        "mcp_fuzzer.transport.drivers.stream_http_driver.resolve_redirect_safely",
        lambda base, location: location,
    )

    assert driver._resolve_redirect(response) == "http://r"


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
