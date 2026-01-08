"""Transport subsystem manager for coordinating transport operations.

This module provides the TransportCoordinator which coordinates all
transport-related operations including creation, lifecycle, and JSON-RPC operations.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from ..interfaces.driver import TransportDriver
from ..interfaces.rpc_adapter import JsonRpcAdapter
from ..catalog.catalog import driver_catalog
from ...exceptions import TransportError


class TransportCoordinator:
    """Manager for the transport subsystem.

    Coordinates transport creation, lifecycle, JSON-RPC operations, and error handling.
    This manager acts as the single point of coordination for all transport-related
    operations within the transport module.
    """

    def __init__(self, config: Dict[str, Any] | None = None):
        """Initialize transport subsystem manager.

        Args:
            config: Optional configuration dictionary for transport settings
        """
        self._logger = logging.getLogger(__name__)
        self._config = config or {}
        self._active_transports: dict[str, TransportDriver] = {}
        self._jsonrpc_helper = JsonRpcAdapter()

    def get_jsonrpc_helper(self) -> JsonRpcAdapter:
        """Get the JSON-RPC helper for transport operations.

        Returns:
            JsonRpcAdapter instance
        """
        return self._jsonrpc_helper

    async def build_driver(
        self,
        url_or_protocol: str,
        endpoint: str | None = None,
        transport_id: str | None = None,
        **kwargs,
    ) -> TransportDriver:
        """Create a transport instance.

        Args:
            url_or_protocol: Full URL or protocol name
            endpoint: Optional endpoint (for protocol+endpoint pattern)
            transport_id: Optional ID to track this transport
            **kwargs: Additional arguments for transport constructor

        Returns:
            Transport instance

        Raises:
            TransportError: If transport creation fails
        """
        try:
            # Local import avoids circular dependency during module initialization
            from ..catalog.builder import build_driver as build_driver_fn

            transport = build_driver_fn(url_or_protocol, endpoint, **kwargs)

            # Track active transport if ID provided
            if transport_id:
                self._active_transports[transport_id] = transport

            # Set transport in JSON-RPC helper for use
            self._jsonrpc_helper.set_transport(transport)

            self._logger.debug(
                f"Created transport: {url_or_protocol}"
                + (f" (id: {transport_id})" if transport_id else "")
            )

            return transport
        except Exception as e:
            self._logger.error(f"Failed to create transport: {e}")
            raise TransportError(f"Transport creation failed: {e}") from e

    async def connect(
        self, transport: TransportDriver, transport_id: str | None = None
    ) -> None:
        """Connect a transport.

        Args:
            transport: Transport to connect
            transport_id: Optional ID for tracking

        Raises:
            TransportError: If connection fails
        """
        try:
            await transport.connect()

            if transport_id and transport_id not in self._active_transports:
                self._active_transports[transport_id] = transport

            msg = "Connected transport"
            if transport_id:
                msg += f" (id: {transport_id})"
            self._logger.debug(msg)
        except Exception as e:
            self._logger.error(f"Failed to connect transport: {e}")
            raise TransportError(f"Transport connection failed: {e}") from e

    async def disconnect(
        self, transport: TransportDriver, transport_id: str | None = None
    ) -> None:
        """Disconnect a transport.

        Args:
            transport: Transport to disconnect
            transport_id: Optional ID for tracking

        Raises:
            TransportError: If disconnection fails
        """
        try:
            await transport.disconnect()

            if transport_id and transport_id in self._active_transports:
                del self._active_transports[transport_id]

            msg = "Disconnected transport"
            if transport_id:
                msg += f" (id: {transport_id})"
            self._logger.debug(msg)
        except Exception as e:
            self._logger.warning(f"Error disconnecting transport: {e}")
            # Don't raise on disconnect errors, just log

    async def send_request(
        self,
        transport: TransportDriver,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Send a JSON-RPC request through a transport.

        Args:
            transport: Transport to use
            method: JSON-RPC method name
            params: Optional parameters

        Returns:
            Response from server

        Raises:
            TransportError: If request fails
        """
        try:
            return await transport.send_request(method, params)
        except Exception as e:
            self._logger.error(f"Request failed ({method}): {e}")
            raise TransportError(f"Request failed: {e}") from e

    async def send_raw(
        self, transport: TransportDriver, payload: dict[str, Any]
    ) -> Any:
        """Send a raw payload through a transport.

        Args:
            transport: Transport to use
            payload: Raw payload to send

        Returns:
            Response from server

        Raises:
            TransportError: If request fails
        """
        try:
            return await transport.send_raw(payload)
        except Exception as e:
            self._logger.error(f"Raw request failed: {e}")
            raise TransportError(f"Raw request failed: {e}") from e

    async def get_tools(self, transport: TransportDriver) -> list[dict[str, Any]]:
        """Get tools from server using JSON-RPC helper.

        Args:
            transport: Transport to use

        Returns:
            List of tools from server
        """
        self._jsonrpc_helper.set_transport(transport)
        return await self._jsonrpc_helper.get_tools()

    async def call_tool(
        self, transport: TransportDriver, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        """Call a tool using JSON-RPC helper.

        Args:
            transport: Transport to use
            tool_name: Name of tool to call
            arguments: Tool arguments

        Returns:
            Tool execution result
        """
        self._jsonrpc_helper.set_transport(transport)
        return await self._jsonrpc_helper.call_tool(tool_name, arguments)

    def get_active_transports(self) -> dict[str, TransportDriver]:
        """Get all active tracked transports.

        Returns:
            Dictionary mapping transport IDs to transport instances
        """
        return dict(self._active_transports)

    def list_available_transports(self) -> dict[str, dict[str, Any]]:
        """List all available transport types.

        Returns:
            Dictionary of available transports (built-in and custom)
        """
        return driver_catalog.list_transports()

    async def cleanup(self) -> None:
        """Clean up all active transports."""
        self._logger.debug("Cleaning up transport subsystem")

        for transport_id, transport in list(self._active_transports.items()):
            try:
                await self.disconnect(transport, transport_id)
            except Exception as e:
                self._logger.warning(f"Error cleaning up transport {transport_id}: {e}")

        self._active_transports.clear()
        self._logger.debug("Transport subsystem cleanup complete")
