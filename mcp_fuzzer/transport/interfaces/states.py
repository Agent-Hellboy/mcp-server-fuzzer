"""Transport type definitions and enums.

This module defines shared types, enums, and data structures used across
the transport layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DriverState(Enum):
    """Lifecycle states for transport drivers."""

    INIT = "init"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    CLOSED = "closed"
    ERROR = "error"


@dataclass
class ParsedEndpoint:
    """Structured result of endpoint resolution."""

    scheme: str
    """URL scheme (e.g., 'http', 'https', 'sse', 'stdio', 'streamablehttp')"""

    endpoint: str
    """Endpoint/URL after scheme processing"""

    is_custom: bool = False
    """Whether this is a custom transport scheme"""

    original_url: str = ""
    """Original URL before parsing"""

    netloc: str = ""
    """Network location from URL parsing"""

    path: str = ""
    """Path component from URL parsing"""

    params: str = ""
    """Parameters from URL parsing"""

    query: str = ""
    """Query string from URL parsing"""

    fragment: str = ""
    """Fragment from URL parsing"""

    def __post_init__(self):
        """Ensure endpoint is set if not provided."""
        if not self.endpoint and self.original_url:
            self.endpoint = self.original_url
