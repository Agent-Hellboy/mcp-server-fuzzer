"""Core driver interfaces, states, shared behaviors, and RPC adapters."""

from .driver import TransportDriver
from .states import DriverState, ParsedEndpoint
from .behaviors import (
    DriverBaseBehavior,
    HttpClientBehavior,
    ResponseParserBehavior,
    LifecycleBehavior,
    TransportError,
    NetworkError,
    PayloadValidationError,
)
from .rpc_adapter import JsonRpcAdapter

__all__ = [
    "TransportDriver",
    "DriverState",
    "ParsedEndpoint",
    "DriverBaseBehavior",
    "HttpClientBehavior",
    "ResponseParserBehavior",
    "LifecycleBehavior",
    "TransportError",
    "NetworkError",
    "PayloadValidationError",
    "JsonRpcAdapter",
]
