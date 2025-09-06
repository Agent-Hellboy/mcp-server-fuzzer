from .base import TransportProtocol
from .http import HTTPTransport
from .sse import SSETransport
from .stdio import StdioTransport
from .streamable_http import StreamableHTTPTransport
from .custom import registry as custom_registry
from urllib.parse import urlparse, urlunparse


def create_transport(
    url_or_protocol: str, endpoint: str | None = None, **kwargs
) -> TransportProtocol:
    """Create a transport from either a full URL or protocol + endpoint.

    Backward-compatible with previous signature (protocol, endpoint).
    """
    # Back-compat path: two-argument usage
    if endpoint is not None:
        key = url_or_protocol.strip().lower()
        # Try custom transports first
        try:
            return custom_registry.create_transport(key, endpoint, **kwargs)
        except KeyError:
            pass
        mapping = {
            "http": HTTPTransport,
            "https": HTTPTransport,
            "streamablehttp": StreamableHTTPTransport,
            "sse": SSETransport,
            "stdio": StdioTransport,
        }
        try:
            transport_cls = mapping[key]
        except KeyError:
            raise ValueError(
                f"Unsupported protocol: {url_or_protocol}. "
                f"Supported: http, https, sse, stdio, streamablehttp; "
                f"custom: {', '.join(sorted(custom_registry.list_transports().keys()))}"
            )
        return transport_cls(endpoint, **kwargs)

    # Single-URL usage
    parsed = urlparse(url_or_protocol)
    scheme = (parsed.scheme or "").lower()

    # Handle custom schemes that urlparse doesn't recognize
    if not scheme and "://" in url_or_protocol:
        # Extract scheme manually for custom transports
        scheme_part = url_or_protocol.split("://", 1)[0].strip().lower()
        if custom_registry.list_transports().get(scheme_part):
            scheme = scheme_part

    # Check for custom transport schemes first
    if scheme:
        try:
            return custom_registry.create_transport(scheme, url_or_protocol, **kwargs)
        except KeyError:
            pass  # Fall through to built-in schemes

    if scheme in ("http", "https"):
        return HTTPTransport(url_or_protocol, **kwargs)
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
        return SSETransport(http_url, **kwargs)
    if scheme == "stdio":
        # Allow stdio:cmd or stdio://cmd; default empty if none
        has_parts = parsed.netloc or parsed.path
        cmd_source = (parsed.netloc + parsed.path) if has_parts else ""
        cmd = cmd_source.lstrip("/")
        return StdioTransport(cmd, **kwargs)
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
        return StreamableHTTPTransport(http_url, **kwargs)

    raise ValueError(
        f"Unsupported URL scheme: {scheme or 'none'}. "
        f"Supported: http, https, sse, stdio, streamablehttp, "
        f"custom: {', '.join(sorted(custom_registry.list_transports().keys()))}"
    )
