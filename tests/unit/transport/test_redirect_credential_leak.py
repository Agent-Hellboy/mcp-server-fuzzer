#!/usr/bin/env python3
"""A hostile MCP server must not harvest credentials via a redirect.

The target server chooses the ``Location`` header. Replaying the original
request headers at that location hands the operator's bearer token to
whoever the server names, so credentials must be withheld the moment the
origin changes.
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from mcp_fuzzer.transport.drivers.http_driver import HttpDriver
from mcp_fuzzer.transport.interfaces.behaviors import is_same_origin

TOKEN = "Bearer SUPER-SECRET-ASSESSOR-TOKEN"


def _response(status, headers=None):
    response = MagicMock(spec=httpx.Response)
    response.status_code = status
    response.headers = headers or {}
    response.json.return_value = {"jsonrpc": "2.0", "id": "1", "result": {}}
    response.text = ""
    return response


class _RecordingClient:
    """Fake httpx client that records every POST it is handed."""

    def __init__(self, redirect_to):
        self.redirect_to = redirect_to
        self.posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None, stream=False):
        self.posts.append((url, dict(headers or {})))
        if len(self.posts) == 1:
            return _response(307, {"location": self.redirect_to})
        return _response(200)


async def _run(redirect_to):
    driver = HttpDriver(
        "https://target.example/mcp",
        auth_headers={"Authorization": TOKEN},
        safety_enabled=False,
    )
    client = _RecordingClient(redirect_to)
    with patch.object(HttpDriver, "_create_http_client", return_value=client):
        try:
            await driver.send_request("tools/list")
        except Exception:
            # The leak is what matters here, not the request outcome.
            pass
    return client.posts


@pytest.mark.asyncio
async def test_cross_origin_redirect_does_not_forward_credentials():
    posts = await _run("http://attacker.example/steal")

    assert len(posts) == 2, "the driver should follow exactly one redirect"
    target_url, target_headers = posts[0]
    attacker_url, attacker_headers = posts[1]

    assert "target.example" in target_url
    assert target_headers.get("Authorization") == TOKEN

    assert "attacker.example" in attacker_url
    assert attacker_headers.get("Authorization") is None
    assert TOKEN not in str(attacker_headers)


@pytest.mark.asyncio
async def test_same_origin_redirect_keeps_credentials():
    """Redirects within the target must still authenticate, or the scan breaks."""
    posts = await _run("https://target.example/mcp/v2")

    assert len(posts) == 2
    _, redirected_headers = posts[1]
    assert redirected_headers.get("Authorization") == TOKEN


@pytest.mark.asyncio
async def test_scheme_downgrade_is_treated_as_cross_origin():
    """https -> http is a different origin; it would also expose the token."""
    posts = await _run("http://target.example/mcp")

    _, redirected_headers = posts[1]
    assert redirected_headers.get("Authorization") is None


@pytest.mark.asyncio
async def test_streaming_redirect_does_not_forward_credentials():
    """``_stream_request`` follows its own redirect and must strip the token too."""

    async def _no_lines():
        return
        yield  # pragma: no cover - makes this an async generator

    def _stream_response(status, headers=None):
        response = _response(status, headers)
        response.aiter_lines.return_value = _no_lines()
        response.aclose = MagicMock(side_effect=lambda: _noop())
        return response

    async def _noop():
        return None

    driver = HttpDriver(
        "https://target.example/mcp",
        auth_headers={"Authorization": TOKEN},
        safety_enabled=False,
    )

    posts = []

    class _StreamingClient(_RecordingClient):
        async def post(self, url, json=None, headers=None, stream=False):
            posts.append((url, dict(headers or {})))
            if len(posts) == 1:
                return _stream_response(
                    307, {"location": "http://attacker.example/steal"}
                )
            return _stream_response(200)

    client = _StreamingClient("http://attacker.example/steal")
    with patch.object(HttpDriver, "_create_http_client", return_value=client):
        async for _ in driver._stream_request({"jsonrpc": "2.0", "method": "x"}):
            pass

    assert len(posts) == 2
    _, attacker_headers = posts[1]
    assert attacker_headers.get("Authorization") is None
    assert TOKEN not in str(attacker_headers)


@pytest.mark.parametrize(
    "a,b,same",
    [
        ("https://t.example/mcp", "https://t.example/other", True),
        ("https://t.example/mcp", "https://t.example:443/other", True),
        ("https://t.example/mcp", "http://t.example/other", False),
        ("https://t.example/mcp", "https://evil.example/x", False),
        ("https://t.example/mcp", "https://t.example.evil.com/x", False),
        ("https://t.example/mcp", "https://t.example:8443/x", False),
        # Userinfo must not be mistaken for the host.
        ("https://t.example/mcp", "https://t.example@evil.example/x", False),
        ("https://t.example/mcp", "", False),
    ],
)
def test_origin_comparison(a, b, same):
    assert is_same_origin(a, b) is same
