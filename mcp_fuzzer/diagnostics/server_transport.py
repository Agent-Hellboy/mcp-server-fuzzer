"""Transport surface checks for MCP server audit."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

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


def audit_origin_validation(
    endpoint: str,
    *,
    protocol: str = "streamablehttp",
    protocol_version: str | None = None,
    timeout: float = 30.0,
    http: httpx.Client | None = None,
) -> list[Finding]:
    """Probe whether an HTTP/SSE server rejects a foreign Origin.

    MCP Streamable HTTP servers must reject invalid origins with HTTP 403 to
    prevent browser-triggered DNS rebinding. The probe is opt-in because it
    sends an additional request outside the normal fuzz session.
    """
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return []

    version = normalize_protocol_version(protocol_version) or current_protocol_version()
    stateless = is_stateless_protocol_version(version)
    origin = "https://mcp-fuzzer.invalid"
    headers = {
        "Origin": origin,
        "Accept": "text/event-stream"
        if protocol.lower() == "sse"
        else "application/json, text/event-stream",
    }
    request_method = "GET" if protocol.lower() == "sse" else "POST"
    status: int
    client = http
    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=timeout, follow_redirects=False)

    try:
        if request_method == "GET":
            with client.stream("GET", endpoint, headers=headers) as response:
                status = response.status_code
        else:
            headers["Content-Type"] = "application/json"
            payload = {
                "jsonrpc": "2.0",
                "id": "mcp-fuzzer-origin-audit",
                "method": "server/discover"
                if stateless
                else "initialize",
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
            response = client.post(
                endpoint,
                headers=headers,
                json=payload,
            )
            status = response.status_code
    except httpx.HTTPError:
        return []
    finally:
        if owns_client:
            client.close()

    # A protected endpoint may authenticate before it evaluates Origin. HTTP
    # 400/404/405 can also be unrelated routing/protocol failures, so only
    # report successful or redirecting acceptance as exploitation evidence.
    if status in {401, 403} or not 200 <= status < 400:
        return []

    severity = "high" if status < 300 else "medium"
    return [
        server_finding(
            "OR1",
            "missing_origin_validation",
            severity,
            "mcp_endpoint",
            f"Server accepted a foreign Origin ({origin!r}) with HTTP {status} "
            "instead of rejecting the request with HTTP 403.",
            arxiv_id=TRANSPORT_PAPER_ARXIV_ID,
            evidence={
                "origin": origin,
                "response_status": status,
                "request_method": request_method,
                "protocol": protocol,
                "protocol_version": version,
            },
        )
    ]
