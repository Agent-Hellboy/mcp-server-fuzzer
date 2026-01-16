"""Transport factory for creating transport instances.

This module provides a simplified factory that uses the unified registry
and URL parser to create transport instances.
"""

from __future__ import annotations

from ..interfaces.driver import TransportDriver
from .catalog import driver_catalog
from .resolver import EndpointResolver
from ...exceptions import TransportRegistrationError


endpoint_resolver = EndpointResolver(driver_catalog)


def _unsupported_scheme_error(scheme: str) -> str:
    builtin = list(driver_catalog.list_builtin_transports().keys())
    custom = list(driver_catalog.list_custom_drivers().keys())
    error_msg = f"Unsupported transport scheme: '{scheme}'"
    if builtin:
        error_msg += f"\nBuilt-in transports: {', '.join(builtin)}"
    if custom:
        error_msg += f"\nCustom transports: {', '.join(custom)}"
    return error_msg


def build_driver(
    url_or_protocol: str, endpoint: str | None = None, **kwargs
) -> TransportDriver:
    """Create a transport from either a full URL or protocol + endpoint.

    This factory function supports two calling patterns:
    1. Single URL: build_driver("http://localhost:8080/api")
    2. Protocol + endpoint: build_driver("http", "localhost:8080/api")

    The function automatically detects custom transports and handles URL parsing.

    Args:
        url_or_protocol: Full URL or protocol name
        endpoint: Optional endpoint (for protocol+endpoint pattern)
        **kwargs: Additional arguments to pass to transport constructor

    Returns:
        Transport instance

    Raises:
        TransportRegistrationError: If protocol/scheme is not supported

    Examples:
        >>> transport = build_driver("http://localhost:8080")
        >>> transport = build_driver("http", "localhost:8080")
        >>> transport = build_driver("sse://localhost:8080/events")
        >>> transport = build_driver("stdio:python server.py")
    """
    # Parse URL or protocol+endpoint
    parsed = endpoint_resolver.parse(url_or_protocol, endpoint)

    if not parsed.scheme:
        raise TransportRegistrationError(
            f"Could not determine transport scheme from: {url_or_protocol}"
        )

    # Check if transport is registered
    if not driver_catalog.is_registered(parsed.scheme):
        raise TransportRegistrationError(_unsupported_scheme_error(parsed.scheme))

    # Create transport using registry
    try:
        return driver_catalog.build_driver(parsed.scheme, parsed.endpoint, **kwargs)
    except Exception as e:
        raise TransportRegistrationError(
            f"Failed to create transport '{parsed.scheme}': {e}"
        ) from e


# Register built-in transports with the global unified registry
def _register_builtin_transports():
    """Register all built-in transport types."""
    from ..drivers.http_driver import HttpDriver
    from ..drivers.sse_driver import SseDriver
    from ..drivers.stdio_driver import StdioDriver
    from ..drivers.stream_http_driver import StreamHttpDriver

    # Only register if not already registered (allow tests to override)
    transports = {
        "http": HttpDriver,
        "https": HttpDriver,
        "sse": SseDriver,
        "stdio": StdioDriver,
        "streamablehttp": StreamHttpDriver,
    }

    for name, cls in transports.items():
        if not driver_catalog.is_registered(name):
            driver_catalog.register(
                name,
                cls,
                description=f"Built-in {name.upper()} driver",
                is_custom=False,
            )


# Register built-in transports on module import
_register_builtin_transports()
