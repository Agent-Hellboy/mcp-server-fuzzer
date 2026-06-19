"""Transport surface checks for MCP server audit."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

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
