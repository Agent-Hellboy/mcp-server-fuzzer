"""Transport factory for creating transport instances.

This module provides a simplified factory that uses the unified registry
and URL parser to create transport instances.
"""

from __future__ import annotations

from ..core.base import TransportProtocol
from .registry import registry as global_registry
from .url_parser import URLParser
from ..exceptions import TransportRegistrationError


# Create URL parser with global registry
url_parser = URLParser(global_registry)


def create_transport(
    url_or_protocol: str, endpoint: str | None = None, **kwargs
) -> TransportProtocol:
    """Create a transport from either a full URL or protocol + endpoint.

    This factory function supports two calling patterns:
    1. Single URL: create_transport("http://localhost:8080/api")
    2. Protocol + endpoint: create_transport("http", "localhost:8080/api")

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
        >>> transport = create_transport("http://localhost:8080")
        >>> transport = create_transport("http", "localhost:8080")
        >>> transport = create_transport("sse://localhost:8080/events")
        >>> transport = create_transport("stdio:python server.py")
    """
    # Parse URL or protocol+endpoint
    parsed = url_parser.parse(url_or_protocol, endpoint)

    if not parsed.scheme:
        raise TransportRegistrationError(
            f"Could not determine transport scheme from: {url_or_protocol}"
        )

    # Check if transport is registered
    if not global_registry.is_registered(parsed.scheme):
        # List available transports for error message
        builtin = list(global_registry.list_builtin_transports().keys())
        custom = list(global_registry.list_custom_transports().keys())

        error_msg = f"Unsupported transport scheme: '{parsed.scheme}'"
        if builtin:
            error_msg += f"\nBuilt-in transports: {', '.join(builtin)}"
        if custom:
            error_msg += f"\nCustom transports: {', '.join(custom)}"

        raise TransportRegistrationError(error_msg)

    # Create transport using registry
    try:
        return global_registry.create_transport(
            parsed.scheme, parsed.endpoint, **kwargs
        )
    except Exception as e:
        raise TransportRegistrationError(
            f"Failed to create transport '{parsed.scheme}': {e}"
        ) from e


# Maintain backward compatibility - export old registry class name
class TransportRegistry:
    """Legacy transport registry class for backward compatibility.

    This class is deprecated and wraps the unified registry.
    Use UnifiedTransportRegistry directly for new code.
    """

    def __init__(self):
        self._registry = global_registry

    def register(self, name: str, cls: type[TransportProtocol]) -> None:
        """Register a transport class by name."""
        self._registry.register(name, cls, is_custom=False, allow_override=True)

    def list_transports(self) -> dict[str, type[TransportProtocol]]:
        """List all registered transports."""
        transports = self._registry.list_builtin_transports()
        return {name: info["class"] for name, info in transports.items()}

    def create_transport(self, name: str, *args, **kwargs) -> TransportProtocol:
        """Create a transport instance by name."""
        return self._registry.create_transport(name, *args, **kwargs)


# Legacy global registry instance for backward compatibility
registry = TransportRegistry()


# Register built-in transports with the global unified registry
def _register_builtin_transports():
    """Register all built-in transport types."""
    from ..implementations.http import HTTPTransport
    from ..implementations.sse import SSETransport
    from ..implementations.stdio import StdioTransport
    from ..implementations.streamable_http import StreamableHTTPTransport

    # Only register if not already registered (allow tests to override)
    transports = {
        "http": HTTPTransport,
        "https": HTTPTransport,
        "sse": SSETransport,
        "stdio": StdioTransport,
        "streamablehttp": StreamableHTTPTransport,
    }

    for name, cls in transports.items():
        if not global_registry.is_registered(name):
            global_registry.register(
                name,
                cls,
                description=f"Built-in {name.upper()} transport",
                is_custom=False,
            )


# Register built-in transports on module import
_register_builtin_transports()
