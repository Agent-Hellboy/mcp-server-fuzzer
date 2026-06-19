"""Unit tests for transport protocol negotiation helpers."""

import pytest

from mcp_fuzzer.transport.protocol import (
    ProtocolNegotiationState,
    current_protocol_version,
    negotiated_headers,
    normalize_protocol_version,
    supports_streamable_http,
)

pytestmark = [pytest.mark.unit, pytest.mark.transport]


def test_normalize_protocol_version_accepts_iso_dates_only():
    assert normalize_protocol_version("2025-11-25") == "2025-11-25"
    assert normalize_protocol_version(" 2025-11-25 ") == "2025-11-25"
    assert normalize_protocol_version("2025-13-99") is None
    assert normalize_protocol_version("latest") is None
    assert normalize_protocol_version(None) is None


def test_current_protocol_version_falls_back_on_invalid_env(monkeypatch):
    monkeypatch.setenv("MCP_SPEC_SCHEMA_VERSION", "latest")

    assert current_protocol_version() == "2025-11-25"


def test_streamable_http_cutoff_rule():
    assert supports_streamable_http("2025-03-26") is True
    assert supports_streamable_http("2025-06-18") is True
    assert supports_streamable_http("2024-11-05") is False
    assert supports_streamable_http("invalid") is False


def test_negotiated_headers_omit_protocol_version_on_initialize():
    state = ProtocolNegotiationState("2025-06-18")

    assert "mcp-protocol-version" not in negotiated_headers(
        {"Accept": "application/json"}, method="initialize", state=state
    )
    assert (
        negotiated_headers({"Accept": "application/json"}, method="ping", state=state)[
            "mcp-protocol-version"
        ]
        == "2025-06-18"
    )


def test_negotiation_state_rejects_invalid_versions():
    state = ProtocolNegotiationState()

    state.seed("not-a-version")
    assert state.protocol_version is None
    assert state.update("2025-03-26") == "2025-03-26"
    assert state.protocol_version == "2025-03-26"
