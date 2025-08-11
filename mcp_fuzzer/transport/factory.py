from .base import TransportProtocol
from .http import HTTPTransport
from .sse import SSETransport
from .stdio import StdioTransport
from .websocket import WebSocketTransport


def create_transport(protocol: str, endpoint: str, **kwargs) -> TransportProtocol:
    if protocol == "http":
        return HTTPTransport(endpoint, **kwargs)
    if protocol == "sse":
        return SSETransport(endpoint, **kwargs)
    if protocol == "stdio":
        return StdioTransport(endpoint, **kwargs)
    if protocol == "websocket":
        return WebSocketTransport(endpoint, **kwargs)
    raise ValueError(f"Unsupported protocol: {protocol}")
