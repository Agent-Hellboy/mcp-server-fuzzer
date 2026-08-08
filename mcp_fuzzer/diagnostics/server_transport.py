"""Transport surface checks for MCP server audit."""

from __future__ import annotations

import ipaddress
from datetime import date
from typing import Mapping
from urllib.parse import urljoin, urlsplit

import httpx

from ..config import MCP_METHOD_HEADER, MCP_PROTOCOL_VERSION_HEADER
from ..transport.protocol import (
    current_protocol_version,
    is_stateless_protocol_version,
    normalize_protocol_version,
    with_stateless_request_metadata,
)
from .model import Finding
from .server import TRANSPORT_PAPER_ARXIV_ID, server_finding

_LOCAL_HTTP_HOSTS = frozenset(
    {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
)

# Origin validation is a MUST from 2024-11-05 onward, but only 2025-11-25 and
# later mandate HTTP 403 specifically for an invalid Origin.
ORIGIN_403_MIN_PROTOCOL_VERSION = "2025-11-25"
# Same-host canonicalization (``/mcp`` -> ``/mcp/``, HTTP -> HTTPS) can happen
# before the Origin check, so the probe follows a few of those hops itself.
_MAX_ORIGIN_PROBE_REDIRECTS = 3


def _is_local_http_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    lowered = hostname.lower()
    if lowered in _LOCAL_HTTP_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        return False
    return address.is_loopback


def audit_insecure_transport(endpoint: str) -> list[Finding]:
    """Flag cleartext HTTP endpoints (MCPSecBench transport surface)."""
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme.lower() != "http":
        return []
    if _is_local_http_host(parsed.hostname):
        return []
    return [
        server_finding(
            "TR1",
            "insecure_transport",
            "medium",
            "mcp_endpoint",
            f"MCP endpoint uses cleartext HTTP ({endpoint!r}); credentials and "
            "tool traffic are not protected in transit.",
            arxiv_id=TRANSPORT_PAPER_ARXIV_ID,
            evidence={"endpoint": endpoint, "scheme": parsed.scheme},
        )
    ]


def _mandates_origin_403(version: str) -> bool:
    """True for MCP revisions that require HTTP 403 for an invalid Origin."""
    normalized = normalize_protocol_version(version)
    if normalized is None:
        return False
    return date.fromisoformat(normalized) >= date.fromisoformat(
        ORIGIN_403_MIN_PROTOCOL_VERSION
    )


def _same_host_redirect_target(current_url: str, location: str | None) -> str | None:
    """Resolve *location* when it stays on the same host, else return None.

    Only same-host hops are followed: a redirect to another host is a different
    server, so its Origin handling says nothing about the target under audit.
    """
    if not location:
        return None
    target = urljoin(current_url, location)
    target_parts = urlsplit(target)
    if target_parts.scheme.lower() not in {"http", "https"}:
        return None
    current_host = (urlsplit(current_url).hostname or "").lower()
    if not current_host or (target_parts.hostname or "").lower() != current_host:
        return None
    return target


def audit_origin_validation(
    endpoint: str,
    *,
    protocol: str = "streamablehttp",
    protocol_version: str | None = None,
    timeout: float = 30.0,
    auth_headers: Mapping[str, str] | None = None,
    http: httpx.Client | None = None,
) -> list[Finding]:
    """Probe whether an HTTP/SSE server rejects a foreign Origin.

    MCP servers must validate the ``Origin`` header to prevent browser-triggered
    DNS rebinding; revisions from 2025-11-25 onward additionally mandate HTTP
    403 for an invalid Origin. The probe is opt-in because it sends an extra
    request outside the normal fuzz session.

    Any configured transport authentication is replayed so that a server which
    authenticates *before* it evaluates Origin still reaches the Origin check.
    When the probe is still refused with HTTP 401 the result is reported as
    inconclusive rather than clean, because an unauthenticated rejection proves
    nothing about Origin handling.
    """
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return []

    version = normalize_protocol_version(protocol_version) or current_protocol_version()
    stateless = is_stateless_protocol_version(version)
    origin = "https://mcp-fuzzer.invalid"
    # MCP 2026-07-28 removed the GET stream endpoint (a GET there answers 405),
    # so only legacy SSE revisions are probed with GET.
    request_method = "GET" if protocol.lower() == "sse" and not stateless else "POST"
    headers: dict[str, str] = {
        key: str(value) for key, value in (auth_headers or {}).items()
    }
    headers.update(
        {
            "Origin": origin,
            "Accept": "text/event-stream"
            if request_method == "GET"
            else "application/json, text/event-stream",
        }
    )
    payload: dict[str, object] | None = None
    if request_method == "POST":
        headers["Content-Type"] = "application/json"
        payload = {
            "jsonrpc": "2.0",
            "id": "mcp-fuzzer-origin-audit",
            "method": "server/discover" if stateless else "initialize",
            "params": {},
        }
        if stateless:
            payload = with_stateless_request_metadata(
                payload,
                protocol_version=version,
                client_capabilities={},
                client_info={
                    "name": "mcp-fuzzer",
                    "version": "security-audit",
                },
            )
            headers[MCP_PROTOCOL_VERSION_HEADER] = version
            headers[MCP_METHOD_HEADER] = "server/discover"
        else:
            payload["params"] = {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-fuzzer",
                    "version": "security-audit",
                },
            }

    status: int
    client = http
    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=timeout, follow_redirects=False)

    url = endpoint
    try:
        for _ in range(_MAX_ORIGIN_PROBE_REDIRECTS + 1):
            if request_method == "GET":
                with client.stream("GET", url, headers=headers) as response:
                    status = response.status_code
                    location = response.headers.get("location")
            else:
                response = client.post(url, headers=headers, json=payload)
                status = response.status_code
                location = response.headers.get("location")
            if not 300 <= status < 400:
                break
            # A redirect is not Origin acceptance: the MCP request was never
            # served. Follow same-host canonicalization and judge the endpoint
            # that actually answers.
            next_url = _same_host_redirect_target(url, location)
            if next_url is None or next_url == url:
                break
            url = next_url
    except httpx.HTTPError:
        return []
    finally:
        if owns_client:
            client.close()

    if status == 401:
        return [
            server_finding(
                "OR2",
                "origin_validation_inconclusive",
                "info",
                "mcp_endpoint",
                "Origin validation could not be evaluated: the server answered "
                f"HTTP 401 for the foreign-Origin probe ({origin!r}), so it "
                "rejected the request on authentication before any Origin "
                "check. Re-run with credentials that reach the MCP endpoint.",
                arxiv_id=TRANSPORT_PAPER_ARXIV_ID,
                evidence={
                    "origin": origin,
                    "response_status": status,
                    "request_method": request_method,
                    "protocol": protocol,
                    "protocol_version": version,
                    "authenticated_probe": bool(auth_headers),
                },
            )
        ]

    # 403 is the spec-mandated rejection. A remaining redirect, or 400/404/405,
    # means the MCP request was never served, so only a successful response is
    # evidence that a foreign Origin was accepted.
    if not 200 <= status < 300:
        return []

    expectation = (
        "instead of rejecting the request with HTTP 403"
        if _mandates_origin_403(version)
        else "instead of rejecting the request"
    )
    evidence: dict[str, object] = {
        "origin": origin,
        "response_status": status,
        "request_method": request_method,
        "protocol": protocol,
        "protocol_version": version,
        "authenticated_probe": bool(auth_headers),
    }
    if url != endpoint:
        evidence["final_url"] = url
    return [
        server_finding(
            "OR1",
            "missing_origin_validation",
            "high",
            "mcp_endpoint",
            f"Server accepted a foreign Origin ({origin!r}) with HTTP {status} "
            f"{expectation}.",
            arxiv_id=TRANSPORT_PAPER_ARXIV_ID,
            evidence=evidence,
        )
    ]
