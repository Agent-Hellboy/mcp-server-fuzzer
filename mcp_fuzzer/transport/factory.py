from .base import TransportProtocol
from .http import HTTPTransport
from .sse import SSETransport
from .stdio import StdioTransport


def create_transport(protocol: str, endpoint: str, **kwargs) -> TransportProtocol:
    key = protocol.strip().lower()
    mapping = {
        "http": HTTPTransport,
        "https": HTTPTransport,
        "sse": SSETransport,
        "stdio": StdioTransport,
    }
    try:
        transport_cls = mapping[key]
    except KeyError:
        raise ValueError(f"Unsupported protocol: {protocol}")
    return transport_cls(endpoint, **kwargs)
