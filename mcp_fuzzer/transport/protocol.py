"""MCP transport protocol version and header negotiation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import os
import re
from typing import Mapping

from ..config import MCP_PROTOCOL_VERSION_HEADER
from .methods import is_initialize_method

SPEC_VERSION_ENV = "MCP_SPEC_SCHEMA_VERSION"
DEFAULT_PROTOCOL_VERSION = "2025-11-25"
STREAMABLE_HTTP_MIN_PROTOCOL_VERSION = "2025-03-26"
_SPEC_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def normalize_protocol_version(value: object) -> str | None:
    """Return a valid ISO-date MCP protocol version string, if present."""
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or not _SPEC_VERSION_RE.match(normalized):
        return None
    try:
        date.fromisoformat(normalized)
    except ValueError:
        return None
    return normalized


def current_protocol_version() -> str:
    """Return the configured MCP protocol version, falling back on invalid input."""
    return (
        normalize_protocol_version(os.getenv(SPEC_VERSION_ENV))
        or DEFAULT_PROTOCOL_VERSION
    )


def supports_streamable_http(version: str) -> bool:
    """Streamable HTTP is selected for MCP spec versions from 2025-03-26 onward."""
    normalized = normalize_protocol_version(version)
    if normalized is None:
        return False
    return date.fromisoformat(normalized) >= date.fromisoformat(
        STREAMABLE_HTTP_MIN_PROTOCOL_VERSION
    )


@dataclass
class ProtocolNegotiationState:
    """Mutable protocol negotiation state shared by HTTP-like transports."""

    protocol_version: str | None = None

    def seed(self, protocol_version: str | None) -> None:
        normalized = normalize_protocol_version(protocol_version)
        if normalized:
            self.protocol_version = normalized

    def update(self, protocol_version: object) -> str | None:
        normalized = normalize_protocol_version(protocol_version)
        if normalized:
            self.protocol_version = normalized
        return normalized


def negotiated_headers(
    base_headers: Mapping[str, str],
    *,
    method: str | None = None,
    state: ProtocolNegotiationState,
) -> dict[str, str]:
    """Return headers with protocol version omitted from initialize requests."""
    headers = dict(base_headers)
    if not is_initialize_method(method) and state.protocol_version:
        headers[MCP_PROTOCOL_VERSION_HEADER] = state.protocol_version
    return headers
