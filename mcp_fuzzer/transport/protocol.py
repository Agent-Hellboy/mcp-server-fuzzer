"""MCP transport protocol version and header negotiation helpers."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from datetime import date
import os
import re
from typing import Any, Mapping

from ..config import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
)
from .methods import is_initialize_method

SPEC_VERSION_ENV = "MCP_SPEC_SCHEMA_VERSION"
DEFAULT_PROTOCOL_VERSION = "2025-11-25"
STREAMABLE_HTTP_MIN_PROTOCOL_VERSION = "2025-03-26"
STATELESS_PROTOCOL_VERSION = "2026-07-28"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
MCP_PARAM_HEADER_PREFIX = "Mcp-Param-"
_SPEC_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HEADER_NAME_RE = re.compile(r"^[!-9;-~]+$")
_BASE64_SENTINEL_PREFIX = "=?base64?"
_BASE64_SENTINEL_SUFFIX = "?="


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


def is_stateless_protocol_version(version: str | None) -> bool:
    """Return True for MCP revisions that use per-request protocol metadata."""
    normalized = normalize_protocol_version(version)
    if normalized is None:
        return False
    return date.fromisoformat(normalized) >= date.fromisoformat(
        STATELESS_PROTOCOL_VERSION
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
    params: Mapping[str, Any] | None = None,
    state: ProtocolNegotiationState,
) -> dict[str, str]:
    """Return headers with protocol version omitted from initialize requests."""
    headers = dict(base_headers)
    if is_stateless_protocol_version(state.protocol_version):
        headers[MCP_PROTOCOL_VERSION_HEADER] = state.protocol_version or ""
        if method:
            headers[MCP_METHOD_HEADER] = _encode_header_value(method)
        name = _request_name_header_value(method, params)
        if name is not None:
            headers[MCP_NAME_HEADER] = _encode_header_value(name)
    elif not is_initialize_method(method) and state.protocol_version:
        headers[MCP_PROTOCOL_VERSION_HEADER] = state.protocol_version
    return headers


def tool_call_param_headers(
    params: Mapping[str, Any] | None,
    tool_definition: Mapping[str, Any] | None,
) -> dict[str, str]:
    """Return SEP-2243 ``Mcp-Param-*`` headers for a ``tools/call`` payload."""
    if not isinstance(params, Mapping) or not isinstance(tool_definition, Mapping):
        return {}
    arguments = params.get("arguments")
    if not isinstance(arguments, Mapping):
        return {}
    input_schema = tool_definition.get("inputSchema")
    if not isinstance(input_schema, Mapping):
        return {}
    properties = input_schema.get("properties")
    if not isinstance(properties, Mapping):
        return {}

    headers: dict[str, str] = {}
    seen: set[str] = set()
    for parameter, schema in properties.items():
        if not isinstance(parameter, str) or not isinstance(schema, Mapping):
            continue
        header_name = schema.get("x-mcp-header")
        if not _valid_param_header_name(header_name):
            continue
        normalized_header_name = str(header_name).lower()
        if normalized_header_name in seen:
            return {}
        seen.add(normalized_header_name)
        if schema.get("type") not in {"string", "number", "integer", "boolean"}:
            continue
        if parameter not in arguments:
            continue
        encoded = _encode_param_header_value(arguments[parameter])
        if encoded is not None:
            headers[f"{MCP_PARAM_HEADER_PREFIX}{header_name}"] = encoded
    return headers


def _valid_param_header_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and bool(_HEADER_NAME_RE.fullmatch(value))
    )


def _encode_param_header_value(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return _encode_header_value("true" if value else "false")
    if isinstance(value, (int, float, str)):
        return _encode_header_value(str(value))
    return None


def _request_name_header_value(
    method: str | None, params: Mapping[str, Any] | None
) -> str | None:
    if method not in {"tools/call", "resources/read", "prompts/get"}:
        return None
    if not isinstance(params, Mapping):
        return None
    key = "uri" if method == "resources/read" else "name"
    value = params.get(key)
    return str(value) if value is not None else None


def _encode_header_value(value: str) -> str:
    needs_encoding = (
        value != value.strip()
        or value.startswith(_BASE64_SENTINEL_PREFIX)
        and value.endswith(_BASE64_SENTINEL_SUFFIX)
        or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value)
    )
    if not needs_encoding:
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"{_BASE64_SENTINEL_PREFIX}{encoded}{_BASE64_SENTINEL_SUFFIX}"


def with_stateless_request_metadata(
    payload: dict[str, Any],
    *,
    protocol_version: str,
    client_capabilities: Mapping[str, Any],
    client_info: Mapping[str, Any],
) -> dict[str, Any]:
    """Return payload with 2026-style per-request MCP metadata."""
    enriched = copy.deepcopy(payload)
    params = enriched.get("params")
    if params is None:
        params = {}
        enriched["params"] = params
    if not isinstance(params, dict):
        return enriched
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        meta = {}
        params["_meta"] = meta
    meta.setdefault(PROTOCOL_VERSION_META_KEY, protocol_version)
    meta.setdefault(CLIENT_INFO_META_KEY, dict(client_info))
    meta.setdefault(CLIENT_CAPABILITIES_META_KEY, dict(client_capabilities))
    return enriched
