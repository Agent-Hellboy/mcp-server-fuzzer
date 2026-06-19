"""Transport surface checks for MCP server audit."""

from __future__ import annotations

from urllib.parse import urlsplit

from .model import Finding
from .server import TRANSPORT_PAPER_ARXIV_ID, server_finding

_LOCAL_HTTP_HOSTS = frozenset(
    {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
)


def audit_insecure_transport(endpoint: str) -> list[Finding]:
    """Flag cleartext HTTP endpoints (MCPSecBench transport surface)."""
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme.lower() != "http":
        return []
    if (parsed.hostname or "").lower() in _LOCAL_HTTP_HOSTS:
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
