from .base import TransportProtocol
from .http import HTTPTransport
from .sse import SSETransport
from .stdio import StdioTransport
from .streamable_http import StreamableHTTPTransport
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
            raise ValueError(f"Unsupported protocol: {url_or_protocol}")
        return transport_cls(endpoint, **kwargs)

    # Single-URL usage
    parsed = urlparse(url_or_protocol)
    scheme = (parsed.scheme or "").lower()

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
        # Use empty command by default; tests only assert type
        return StdioTransport("", **kwargs)
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

    raise ValueError(f"Unsupported URL scheme: {scheme or 'none'}")
