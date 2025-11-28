"""URL parsing utilities for transport creation.

This module provides URL parsing functionality extracted from the factory,
supporting both standard URLs and custom transport schemes.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse
from typing import TYPE_CHECKING

from ..interfaces.states import ParsedEndpoint

if TYPE_CHECKING:
    from .catalog import DriverCatalog


class EndpointResolver:
    """Parser for transport URLs and protocol+endpoint patterns.

    Handles both standard URLs (http://..., https://...) and custom
    transport schemes (sse://..., stdio:..., streamablehttp://..., etc.)
    """

    def __init__(self, registry: DriverCatalog | None = None):
        """Initialize URL parser.

        Args:
            registry: Optional registry to check for custom schemes
        """
        self._registry = registry

    def set_registry(self, registry: DriverCatalog) -> None:
        """Set or update the registry used for custom scheme lookup.

        Args:
            registry: Registry instance
        """
        self._registry = registry

    def parse(
        self, url_or_protocol: str, endpoint: str | None = None
    ) -> ParsedEndpoint:
        """Parse a URL or protocol+endpoint into structured components.

        Supports two calling patterns:
        1. Single URL: parse("http://localhost:8080/api")
        2. Protocol + endpoint: parse("http", "localhost:8080/api")

        Args:
            url_or_protocol: Full URL or protocol name
            endpoint: Optional endpoint (for protocol+endpoint pattern)

        Returns:
            ParsedEndpoint with structured components
        """
        url_or_protocol = url_or_protocol.strip()
        endpoint = endpoint.strip() if isinstance(endpoint, str) else endpoint
        # Handle protocol+endpoint pattern
        if endpoint is not None:
            return self._parse_protocol_endpoint(url_or_protocol, endpoint)

        # Handle full URL pattern
        return self._parse_url(url_or_protocol)

    def _parse_protocol_endpoint(self, protocol: str, endpoint: str) -> ParsedEndpoint:
        """Parse protocol and endpoint into ParsedEndpoint.

        Args:
            protocol: Transport protocol name
            endpoint: Endpoint string

        Returns:
            ParsedEndpoint with protocol as scheme and endpoint
        """
        protocol_lower = protocol.strip().lower()

        # Check if it's a custom transport
        is_custom = False
        if self._registry:
            is_custom = self._registry.is_registered(protocol_lower)

        return ParsedEndpoint(
            scheme=protocol_lower,
            endpoint=endpoint,
            is_custom=is_custom,
            original_url=f"{protocol}://{endpoint}",
        )

    def _parse_url(self, url: str) -> ParsedEndpoint:
        """Parse a full URL into ParsedEndpoint.

        Args:
            url: Full URL string

        Returns:
            ParsedEndpoint with parsed components
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()

        # Handle schemes that urlparse doesn't recognize (e.g., custom drivers)
        if not scheme and "://" in url:
            scheme = url.split("://", 1)[0].strip().lower()

        # Check if custom transport
        is_custom = False
        if self._registry and scheme:
            is_custom = self._registry.is_custom_transport(scheme)

        # Determine endpoint based on scheme
        endpoint = self._resolve_endpoint(url, parsed, scheme)

        return ParsedEndpoint(
            scheme=scheme,
            endpoint=endpoint,
            is_custom=is_custom,
            original_url=url,
            netloc=parsed.netloc,
            path=parsed.path,
            params=parsed.params,
            query=parsed.query,
            fragment=parsed.fragment,
        )

    def _resolve_endpoint(self, original_url: str, parsed, scheme: str) -> str:
        """Resolve the endpoint from parsed URL components.

        Args:
            original_url: Original URL string
            parsed: Result from urlparse
            scheme: URL scheme

        Returns:
            Resolved endpoint string
        """
        # For stdio, extract command
        if scheme == "stdio":
            has_parts = parsed.netloc or parsed.path
            cmd_source = (parsed.netloc + parsed.path) if has_parts else ""
            return cmd_source.lstrip("/")

        # For SSE and StreamableHTTP, convert to HTTP URL
        if scheme in ("sse", "streamablehttp"):
            return urlunparse(
                (
                    "http",
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )

        # For HTTP/HTTPS, return original URL
        if scheme in ("http", "https"):
            return original_url

        # For custom transports, return original URL
        return original_url
