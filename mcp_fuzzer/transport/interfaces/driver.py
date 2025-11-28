"""Core driver interface for all transport implementations.

The TransportDriver describes the contract that every concrete driver
must follow. JSON-RPC specific helpers live in the rpc_adapter module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator


class TransportDriver(ABC):
    """Abstract base class for transport drivers.

    This interface defines the core methods that all transports must implement
    for sending requests, notifications, and streaming data. JSON-RPC specific
    operations (get_tools, call_tool, etc.) have been moved to JsonRpcAdapter.
    """

    @abstractmethod
    async def send_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> Any:
        """Send a JSON-RPC request and return the response.

        Args:
            method: The method name to call
            params: Optional parameters for the method

        Returns:
            Response data from the server

        Raises:
            TransportError: If the request fails
        """
        pass

    @abstractmethod
    async def send_raw(self, payload: dict[str, Any]) -> Any:
        """Send a raw payload and return the response.

        Args:
            payload: Raw payload to send (should be JSON-RPC compatible)

        Returns:
            Response data from the server

        Raises:
            TransportError: If the request fails
        """
        pass

    @abstractmethod
    async def send_notification(
        self, method: str, params: dict[str, Any] | None = None
    ) -> None:
        """Send a JSON-RPC notification (fire-and-forget).

        Args:
            method: The method name to call
            params: Optional parameters for the method

        Raises:
            TransportError: If the notification fails to send
        """
        pass

    async def connect(self) -> None:
        """Connect to the transport.

        Default implementation does nothing. Transports that require
        explicit connection setup should override this method.
        """
        pass

    async def disconnect(self) -> None:
        """Disconnect from the transport.

        Default implementation does nothing. Transports that require
        explicit connection teardown should override this method.
        """
        pass

    async def stream_request(
        self, payload: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a request to the transport.

        This is the public interface for streaming. The actual implementation
        is delegated to _stream_request which subclasses must implement.

        Args:
            payload: The request payload

        Yields:
            Response chunks from the transport
        """
        async for response in self._stream_request(payload):
            yield response

    @abstractmethod
    async def _stream_request(
        self, payload: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a request to the transport (implementation).

        Subclasses must implement this method to provide streaming support.

        Args:
            payload: The request payload

        Yields:
            Response chunks from the transport
        """
        pass
