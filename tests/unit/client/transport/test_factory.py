#!/usr/bin/env python3
"""Unit tests for the transport factory with auth support."""

from unittest.mock import MagicMock, patch

import pytest

from mcp_fuzzer.client.transport.factory import (
    AUTH_PROTOCOLS,
    TransportBuildRequest,
    build_driver_with_auth,
)
from mcp_fuzzer.transport.retrying import RetryingTransport

pytestmark = [pytest.mark.unit, pytest.mark.client]


def test_transport_build_request_defaults():
    req = TransportBuildRequest(protocol="stdio", endpoint="cmd")
    assert req.timeout == 30.0
    assert req.transport_retries == 1
    assert req.auth_manager is None
    assert req.safety_enabled is True
    assert req.transport_retry_delay == 0.5
    assert req.transport_retry_backoff == 2.0
    assert req.transport_retry_max_delay == 5.0
    assert req.transport_retry_jitter == 0.1


def test_transport_build_request_is_frozen():
    req = TransportBuildRequest(protocol="stdio", endpoint="cmd")
    with pytest.raises((AttributeError, TypeError)):
        req.protocol = "http"  # type: ignore[misc]


def test_auth_protocols_contains_expected():
    for proto in ("http", "https", "streamablehttp", "sse"):
        assert proto in AUTH_PROTOCOLS


def _fake_transport():
    return MagicMock()


def test_build_driver_no_auth_non_http():
    """stdio transport: no auth headers, no safety_enabled kwarg."""
    mock_transport = _fake_transport()
    req = TransportBuildRequest(protocol="stdio", endpoint="cmd")

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ) as mock_build:
        result = build_driver_with_auth(req)

    mock_build.assert_called_once_with("stdio", "cmd", timeout=30.0)
    assert result is mock_transport


def test_build_driver_http_no_auth_manager():
    """HTTP without auth manager passes safety_enabled but not auth_header_provider."""
    mock_transport = _fake_transport()
    req = TransportBuildRequest(protocol="http", endpoint="http://localhost:8080")

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ) as mock_build:
        result = build_driver_with_auth(req)

    _, kwargs = mock_build.call_args
    assert kwargs["safety_enabled"] is True
    assert "auth_header_provider" not in kwargs
    assert result is mock_transport


def test_build_driver_http_with_auth_manager():
    """HTTP with auth manager injects auth_header_provider callable."""
    mock_transport = _fake_transport()
    mock_auth = MagicMock()
    mock_auth.get_default_auth_headers.return_value = {"Authorization": "Bearer tok"}

    req = TransportBuildRequest(
        protocol="http",
        endpoint="http://localhost:8080",
        auth_manager=mock_auth,
    )

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ) as mock_build:
        result = build_driver_with_auth(req)

    _, kwargs = mock_build.call_args
    assert callable(kwargs["auth_header_provider"])
    assert kwargs["auth_header_provider"]() == {"Authorization": "Bearer tok"}
    assert result is mock_transport


def test_build_driver_sse_with_auth_manager():
    """SSE is an AUTH_PROTOCOL - auth_header_provider should be injected."""
    mock_transport = _fake_transport()
    mock_auth = MagicMock()
    mock_auth.get_default_auth_headers.return_value = {"Authorization": "Bearer sse"}

    req = TransportBuildRequest(
        protocol="sse",
        endpoint="http://localhost:8080/sse",
        auth_manager=mock_auth,
    )

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ) as mock_build:
        build_driver_with_auth(req)

    _, kwargs = mock_build.call_args
    assert "auth_header_provider" in kwargs


def test_build_driver_streamablehttp_safety_disabled():
    """safety_enabled=False is passed through to streamablehttp transport."""
    mock_transport = _fake_transport()
    req = TransportBuildRequest(
        protocol="streamablehttp",
        endpoint="http://localhost:8080",
        safety_enabled=False,
    )

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ) as mock_build:
        build_driver_with_auth(req)

    _, kwargs = mock_build.call_args
    assert kwargs["safety_enabled"] is False


def test_build_driver_with_retries_wraps_transport():
    """transport_retries > 1 wraps result in RetryingTransport."""
    mock_transport = _fake_transport()
    req = TransportBuildRequest(
        protocol="stdio",
        endpoint="cmd",
        transport_retries=3,
        transport_retry_delay=0.1,
        transport_retry_max_delay=1.0,
        transport_retry_backoff=1.5,
        transport_retry_jitter=0.0,
    )

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ):
        result = build_driver_with_auth(req)

    assert isinstance(result, RetryingTransport)


def test_build_driver_retries_one_no_wrap():
    """transport_retries=1 returns the transport unwrapped."""
    mock_transport = _fake_transport()
    req = TransportBuildRequest(
        protocol="stdio", endpoint="cmd", transport_retries=1
    )

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ):
        result = build_driver_with_auth(req)

    assert result is mock_transport


def test_build_driver_invalid_retries_fallback_to_one():
    """Non-integer transport_retries falls back to 1 (no wrap)."""
    mock_transport = _fake_transport()
    req = TransportBuildRequest(
        protocol="stdio",
        endpoint="cmd",
        transport_retries="not-a-number",  # type: ignore[arg-type]
    )

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ):
        result = build_driver_with_auth(req)

    assert result is mock_transport


def test_build_driver_non_auth_protocol_with_auth_manager_skips_auth():
    """stdio transport ignores auth manager (no auth_header_provider injected)."""
    mock_transport = _fake_transport()
    mock_auth = MagicMock()
    mock_auth.get_default_auth_headers.return_value = {"Authorization": "Bearer tok"}

    req = TransportBuildRequest(
        protocol="stdio",
        endpoint="cmd",
        auth_manager=mock_auth,
    )

    with patch(
        "mcp_fuzzer.client.transport.factory.base_build_driver",
        return_value=mock_transport,
    ) as mock_build:
        build_driver_with_auth(req)

    _, kwargs = mock_build.call_args
    assert "auth_header_provider" not in kwargs
    assert "safety_enabled" not in kwargs
