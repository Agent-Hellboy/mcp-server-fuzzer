"""Unified transport registry system.

This module provides a single registry for both built-in and custom transports,
replacing the previous dual registry system.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Type

from ..core.base import TransportProtocol
from ..exceptions import TransportRegistrationError

logger = logging.getLogger(__name__)


class TransportMetadata:
    """Metadata for a registered transport."""

    def __init__(
        self,
        transport_class: Type[TransportProtocol],
        description: str = "",
        config_schema: dict[str, Any] | None = None,
        factory_function: Callable | None = None,
        is_custom: bool = False,
    ):
        self.transport_class = transport_class
        self.description = description
        self.config_schema = config_schema
        self.factory_function = factory_function
        self.is_custom = is_custom


class UnifiedTransportRegistry:
    """Unified registry for both built-in and custom transports.

    This registry replaces the previous dual registry system (TransportRegistry
    and CustomTransportRegistry) with a single, consistent interface.
    """

    def __init__(self):
        """Initialize the unified transport registry."""
        self._transports: dict[str, TransportMetadata] = {}

    def register(
        self,
        name: str,
        transport_class: Type[TransportProtocol],
        description: str = "",
        config_schema: dict[str, Any] | None = None,
        factory_function: Callable | None = None,
        is_custom: bool = False,
        allow_override: bool = False,
    ) -> None:
        """Register a transport with the registry.

        Args:
            name: Unique name for the transport (case-insensitive)
            transport_class: The transport class to register
            description: Human-readable description
            config_schema: JSON schema for transport configuration
            factory_function: Optional factory function for creating instances
            is_custom: Whether this is a custom (non-built-in) transport
            allow_override: Whether to allow overriding existing registration

        Raises:
            TransportRegistrationError: If name already registered and
                override not allowed
        """
        key = name.strip().lower()

        # Check for existing registration
        if key in self._transports and not allow_override:
            existing = self._transports[key]
            existing_type = "custom" if existing.is_custom else "built-in"
            new_type = "custom" if is_custom else "built-in"
            raise TransportRegistrationError(
                f"Transport '{name}' is already registered as "
                f"{existing_type} transport. "
                f"Cannot register as {new_type} transport without "
                "allow_override=True."
            )

        # Validate transport class
        if not issubclass(transport_class, TransportProtocol):
            raise TransportRegistrationError(
                f"Transport class {transport_class} must inherit from TransportProtocol"
            )

        # Register the transport
        self._transports[key] = TransportMetadata(
            transport_class=transport_class,
            description=description,
            config_schema=config_schema,
            factory_function=factory_function,
            is_custom=is_custom,
        )

        transport_type = "custom" if is_custom else "built-in"
        logger.info(f"Registered {transport_type} transport: {key}")

    def unregister(self, name: str) -> None:
        """Unregister a transport.

        Args:
            name: Name of the transport to unregister

        Raises:
            TransportRegistrationError: If transport is not registered
        """
        key = name.strip().lower()
        if key not in self._transports:
            raise TransportRegistrationError(f"Transport '{name}' is not registered")

        metadata = self._transports[key]
        transport_type = "custom" if metadata.is_custom else "built-in"
        del self._transports[key]
        logger.info(f"Unregistered {transport_type} transport: {key}")

    def is_registered(self, name: str) -> bool:
        """Check if a transport is registered.

        Args:
            name: Transport name to check

        Returns:
            True if registered, False otherwise
        """
        return name.strip().lower() in self._transports

    def is_custom_transport(self, name: str) -> bool:
        """Check if a registered transport is custom.

        Args:
            name: Transport name to check

        Returns:
            True if registered and custom, False otherwise
        """
        key = name.strip().lower()
        if key not in self._transports:
            return False
        return self._transports[key].is_custom

    def get_transport_class(self, name: str) -> Type[TransportProtocol]:
        """Get the transport class for a registered transport.

        Args:
            name: Name of the registered transport

        Returns:
            The transport class

        Raises:
            TransportRegistrationError: If transport is not registered
        """
        key = name.strip().lower()
        if key not in self._transports:
            raise TransportRegistrationError(f"Transport '{name}' is not registered")
        return self._transports[key].transport_class

    def get_transport_info(self, name: str) -> dict[str, Any]:
        """Get information about a registered transport.

        Args:
            name: Name of the registered transport

        Returns:
            Dictionary containing transport information

        Raises:
            TransportRegistrationError: If transport is not registered
        """
        key = name.strip().lower()
        if key not in self._transports:
            raise TransportRegistrationError(f"Transport '{name}' is not registered")

        metadata = self._transports[key]
        return {
            "class": metadata.transport_class,
            "description": metadata.description,
            "config_schema": metadata.config_schema,
            "factory": metadata.factory_function,
            "is_custom": metadata.is_custom,
        }

    def list_transports(self, include_custom: bool = True) -> dict[str, dict[str, Any]]:
        """List registered transports.

        Args:
            include_custom: Whether to include custom transports

        Returns:
            Dictionary mapping transport names to their information
        """
        result = {}
        for name, metadata in self._transports.items():
            if not include_custom and metadata.is_custom:
                continue
            result[name] = {
                "class": metadata.transport_class,
                "description": metadata.description,
                "config_schema": metadata.config_schema,
                "factory": metadata.factory_function,
                "is_custom": metadata.is_custom,
            }
        return result

    def list_builtin_transports(self) -> dict[str, dict[str, Any]]:
        """List only built-in transports.

        Returns:
            Dictionary mapping transport names to their information
        """
        return {
            name: info
            for name, metadata in self._transports.items()
            if not metadata.is_custom
            for info in [
                {
                    "class": metadata.transport_class,
                    "description": metadata.description,
                    "config_schema": metadata.config_schema,
                    "factory": metadata.factory_function,
                    "is_custom": metadata.is_custom,
                }
            ]
        }

    def list_custom_transports(self) -> dict[str, dict[str, Any]]:
        """List only custom transports.

        Returns:
            Dictionary mapping transport names to their information
        """
        return {
            name: info
            for name, metadata in self._transports.items()
            if metadata.is_custom
            for info in [
                {
                    "class": metadata.transport_class,
                    "description": metadata.description,
                    "config_schema": metadata.config_schema,
                    "factory": metadata.factory_function,
                    "is_custom": metadata.is_custom,
                }
            ]
        }

    def create_transport(self, name: str, *args, **kwargs) -> TransportProtocol:
        """Create an instance of a registered transport.

        Args:
            name: Name of the registered transport
            *args: Positional arguments to pass to transport constructor/factory
            **kwargs: Keyword arguments to pass to transport constructor/factory

        Returns:
            Transport instance

        Raises:
            TransportRegistrationError: If transport is not registered
        """
        metadata = self.get_transport_info(name)
        transport_class = metadata["class"]
        factory = metadata.get("factory")

        # Use factory if provided
        if factory is not None:
            return factory(*args, **kwargs)

        # Handle custom transport URL shorthand (e.g., "custom://endpoint")
        if (
            metadata["is_custom"]
            and args
            and len(args) == 1
            and isinstance(args[0], str)
        ):
            url = args[0]
            if f"{name}://" in url:
                endpoint = url.split(f"{name}://", 1)[1]
                args = (endpoint,) + args[1:]

        # Use class constructor
        return transport_class(*args, **kwargs)

    def clear(self) -> None:
        """Clear all registered transports. Useful for testing."""
        self._transports.clear()
        logger.debug("Cleared all registered transports")


# Global registry instance
registry = UnifiedTransportRegistry()
