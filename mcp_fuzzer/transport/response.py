"""Helper adapters for HTTP response metadata access."""

from __future__ import annotations

from typing import Optional

import httpx

from ..config import (
    CONTENT_TYPE_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    MCP_SESSION_ID_HEADER,
)


class HTTPResponseView:
    """Encapsulate header access to avoid touching response internals."""

    def __init__(self, response: httpx.Response):
        self._response = response

    def get_header(self, name: str, default: str | None = None) -> Optional[str]:
        """Return a specific header value."""
        return self._response.headers.get(name, default)

    @property
    def session_id(self) -> Optional[str]:
        """Return the MCP session identifier header if present."""
        return self.get_header(MCP_SESSION_ID_HEADER)

    @property
    def protocol_version(self) -> Optional[str]:
        """Return the MCP protocol version header if present."""
        return self.get_header(MCP_PROTOCOL_VERSION_HEADER)

    @property
    def content_type(self) -> str:
        """Return the response Content-Type header."""
        return self.get_header(CONTENT_TYPE_HEADER, "") or ""
