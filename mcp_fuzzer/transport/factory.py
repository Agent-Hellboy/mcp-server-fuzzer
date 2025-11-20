
from typing import Any

from .base import TransportProtocol
from .http import HTTPTransport
from .sse import SSETransport
from .stdio import StdioTransport
from .streamable_http import StreamableHTTPTransport
from .custom import registry as custom_registry
from urllib.parse import urlparse, urlunparse
from ..exceptions import TransportRegistrationError

class TransportRegistry:
    """Registry for transport classes."""

    def __init__(self):
        self._transports: dict[str, type[TransportProtocol]] = {}

    def register(self, name: str, cls: type[TransportProtocol]) -> None:
        """Register a transport class by name."""
        self._transports[name.lower()] = cls

    def list_transports(self) -> dict[str, type[TransportProtocol]]:
        """List all registered transports."""
        return self._transports.copy()

    def get_transport_names(self) -> list[str]:
        """Return the registered transport names."""
        return sorted(self._transports.keys())

    def has_transport(self, name: str) -> bool:
        """Return True if the transport name is registered."""
        return name.strip().lower() in self._transports

    def create_transport(self, name: str, *args, **kwargs) -> TransportProtocol:
        """Create a transport instance by name."""
        name_lower = name.lower()
        if name_lower not in self._transports:
            raise TransportRegistrationError(f"Unknown transport: {name}")
        cls = self._transports[name_lower]
        return cls(*args, **kwargs)


class TransportFactory:
    """Factory for creating transport instances with dependency injection."""

    def __init__(self):
        self.registry = TransportRegistry()
        # Register built-in transports
        self.registry.register("http", HTTPTransport)
        self.registry.register("https", HTTPTransport)
        self.registry.register("sse", SSETransport)
        self.registry.register("stdio", StdioTransport)
        self.registry.register("streamablehttp", StreamableHTTPTransport)

    def create_transport(
        self, url_or_protocol: str, endpoint: str | None = None, **kwargs
    ) -> TransportProtocol:
        """Create a transport from either a full URL or protocol + endpoint."""
        return _create_transport_impl(
            url_or_protocol, endpoint, self.registry, **kwargs
        )

    def create_transport_with_auth(
        self, args: Any, client_args: dict[str, Any]
    ) -> TransportProtocol:
        """Create a transport with authentication headers."""
        return _create_transport_with_auth_impl(
            args, client_args, self.registry
        )


# Global instance for backward compatibility
_default_factory = TransportFactory()
registry = _default_factory.registry

def _create_transport_impl(
    url_or_protocol: str, endpoint: str | None, registry: TransportRegistry, **kwargs
) -> TransportProtocol:
    """Internal implementation for transport creation."""
    # Back-compat path: two-argument usage
    if endpoint is not None:
        key = url_or_protocol.strip().lower()
        # Try custom transports first
        try:
            return custom_registry.create_transport(key, endpoint, **kwargs)
        except TransportRegistrationError:
            pass
        # Try built-in registry
        try:
            return registry.create_transport(key, endpoint, **kwargs)
        except TransportRegistrationError:
            raise TransportRegistrationError(
                f"Unsupported protocol: {url_or_protocol}. "
                f"Supported: {', '.join(registry.get_transport_names())}; "
                f"custom: {', '.join(custom_registry.get_transport_names())}"
            )

    # Single-URL usage
    parsed = urlparse(url_or_protocol)
    scheme = (parsed.scheme or "").lower()

    # Handle custom schemes that urlparse doesn't recognize
    if not scheme and "://" in url_or_protocol:
        # Extract scheme manually for custom transports
        scheme_part = url_or_protocol.split("://", 1)[0].strip().lower()
        if custom_registry.has_transport(scheme_part):
            scheme = scheme_part

    # Check for custom transport schemes first
    if scheme:
        try:
            return custom_registry.create_transport(scheme, url_or_protocol, **kwargs)
        except TransportRegistrationError:
            pass  # Fall through to built-in schemes

    if scheme in ("http", "https"):
        return registry.create_transport("http", url_or_protocol, **kwargs)
    if scheme == "sse":
        # Convert sse://host/path to http://host/path (preserve params/query/fragment)
        http_url = urlunparse(
            (
                "http",
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        return registry.create_transport("sse", http_url, **kwargs)
    if scheme == "stdio":
        # Allow stdio:cmd or stdio://cmd; default empty if none
        has_parts = parsed.netloc or parsed.path
        cmd_source = (parsed.netloc + parsed.path) if has_parts else ""
        cmd = cmd_source.lstrip("/")
        return registry.create_transport("stdio", cmd, **kwargs)
    if scheme == "streamablehttp":
        http_url = urlunparse(
            (
                "http",
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        return registry.create_transport("streamablehttp", http_url, **kwargs)

    raise TransportRegistrationError(
        f"Unsupported URL scheme: {scheme or 'none'}. "
        f"Supported: {', '.join(registry.get_transport_names())}, "
        f"custom: {', '.join(custom_registry.get_transport_names())}"
    )


def _create_transport_with_auth_impl(
    args, client_args: dict[str, Any], registry: TransportRegistry
):
    """Create a transport with authentication headers if available.

    This function handles applying auth headers to HTTP-based transports.
    For HTTP-like protocols, it extracts auth headers from the auth_manager
    and includes them in the transport initialization.

    Args:
        args: Arguments object with protocol, endpoint, timeout attributes
        client_args: Dictionary containing optional auth_manager

    Returns:
        Initialized TransportProtocol instance

    Raises:
        SystemExit: On transport creation error
    """
    try:
        auth_headers = None
        auth_manager = client_args.get("auth_manager")

        if auth_manager:
            # Prefer default provider headers, fall back to explicit tool mapping
            auth_headers = auth_manager.get_default_auth_headers()
            if not auth_headers:
                auth_headers = auth_manager.get_auth_headers_for_tool("")
            if auth_headers:
                header_keys = list(auth_headers.keys())
                import logging
                logger = logging.getLogger(__name__)
                logger.debug(f"Auth headers found for transport: {header_keys}")
            else:
                import logging
                logger = logging.getLogger(__name__)
                logger.debug("No auth headers found for default tool mapping")

        factory_kwargs = {"timeout": args.timeout}

        # Apply auth headers to HTTP-based protocols
        if args.protocol in ("http", "https", "streamablehttp", "sse") and auth_headers:
            factory_kwargs["auth_headers"] = auth_headers
            import logging
            logger = logging.getLogger(__name__)
            logger.debug(f"Adding auth headers to {args.protocol.upper()} transport")

        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"Creating {args.protocol.upper()} transport to {args.endpoint}")
        transport = create_transport(
            args.protocol,
            args.endpoint,
            **factory_kwargs,
        )
        if auth_headers:
            msg = "Transport created successfully with auth headers"
        else:
            msg = "Transport created successfully"
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(msg)
        return transport
    except Exception as transport_error:
        from rich.console import Console
        console = Console()
        console.print(f"[bold red]Unexpected error:[/bold red] {transport_error}")
        import logging
        logger = logging.getLogger(__name__)
        logger.exception("Transport creation failed")
        import sys
        sys.exit(1)


# Backward compatibility functions that delegate to default factory
def create_transport(
    url_or_protocol: str, endpoint: str | None = None, **kwargs
) -> TransportProtocol:
    """Create a transport from either a full URL or protocol + endpoint
    (backward compatibility)."""
    return _default_factory.create_transport(url_or_protocol, endpoint, **kwargs)


def create_transport_with_auth(
    args: Any, client_args: dict[str, Any]
) -> TransportProtocol:
    """Create a transport with authentication headers (backward compatibility)."""
    return _default_factory.create_transport_with_auth(args, client_args)
