"""Canonical MCP server resource URI for OAuth Resource Indicators (RFC 8707).

The MCP authorization spec requires the ``resource`` parameter to carry the
canonical URI of the MCP server in both authorization and token requests.
The canonical form uses a lowercase scheme and host, contains no fragment,
and omits a redundant trailing slash.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def canonical_resource_uri(url: str) -> str:
    """Return the RFC 8707 canonical resource URI for an MCP endpoint.

    - Lowercases the scheme and host (netloc).
    - Drops any fragment.
    - Removes a trailing slash unless the path is the bare root.

    Raises ``ValueError`` if the URL has no scheme or host.
    """
    parsed = urlsplit(url.strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"resource URI must be absolute with a scheme: {url!r}")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    # Strip a redundant trailing slash (but keep the bare root meaningful).
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    # The bare root path contributes nothing to the canonical identifier.
    if path == "/":
        path = ""

    return urlunsplit((scheme, netloc, path, parsed.query, ""))
