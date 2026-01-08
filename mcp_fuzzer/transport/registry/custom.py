"""Custom transport registry and utilities.

This module provides support for registering and managing custom transport
implementations. It now uses the unified registry system internally for
consistency across all transport types.
"""

from __future__ import annotations

import logging
from typing import Type, Any, Callable

from ..core.base import TransportProtocol
from .registry import registry as unified_registry
from ..exceptions import TransportRegistrationError

logger = logging.getLogger(__name__)


class CustomTransportRegistry:
    """Registry for custom transport implementations.

    This class now wraps the unified registry, marking transports as custom.
    It maintains backward compatibility with the previous API while using
    the unified registry internally.
    """

    def __init__(self):
        """Initialize custom transport registry."""
        # Use the unified registry internally
        self._registry = unified_registry

    def clear(self) -> None:
        """Clear all registered custom transports. Useful for testing."""
        # Only clear custom transports
        custom_transports = list(self._registry.list_custom_transports().keys())
        for name in custom_transports:
            try:
                self._registry.unregister(name)
            except TransportRegistrationError:
                logger.debug(
                    "Could not unregister transport '%s' during clear",
                    name,
                    exc_info=True,
                )

    def _validate_custom_transport(self, name: str, action: str) -> str:
        """Validate that a transport is registered and custom.

        Args:
            name: Transport name to validate
            action: Action being performed (for error messages)

        Returns:
            Normalized transport key

        Raises:
            TransportRegistrationError: If not registered or not custom
        """
        key = name.strip().lower()
        if not self._registry.is_custom_transport(key):
            if self._registry.is_registered(key):
                if action == "unregister":
                    raise TransportRegistrationError(
                        f"Transport '{name}' is a built-in transport and "
                        "cannot be unregistered"
                    )
                raise TransportRegistrationError(
                    f"Transport '{name}' is a built-in transport, not custom"
                )
            raise TransportRegistrationError(f"Transport '{name}' is not registered")
        return key

    def register(
        self,
        name: str,
        transport_class: Type[TransportProtocol],
        description: str = "",
        config_schema: dict[str, Any] | None = None,
        factory_function: Callable | None = None,
    ) -> None:
        """Register a custom transport.

        Args:
            name: Unique name for the transport
            transport_class: The transport class to register
            description: Human-readable description
            config_schema: JSON schema for transport configuration
            factory_function: Optional factory function to create transport instances

        Raises:
            TransportRegistrationError: If transport name is already registered
        """
        # Use unified registry with custom flag
        self._registry.register(
            name=name,
            transport_class=transport_class,
            description=description or f"Custom {name} transport",
            config_schema=config_schema,
            factory_function=factory_function,
            is_custom=True,
            allow_override=False,
        )

    def unregister(self, name: str) -> None:
        """Unregister a custom transport.

        Args:
            name: Name of the transport to unregister

        Raises:
            TransportRegistrationError: If transport is not registered or not custom
        """
        key = self._validate_custom_transport(name, "unregister")
        self._registry.unregister(key)

    def get_transport_class(self, name: str) -> Type[TransportProtocol]:
        """Get the transport class for a registered custom transport.

        Args:
            name: Name of the registered transport

        Returns:
            The transport class

        Raises:
            TransportRegistrationError: If transport is not registered or not custom
        """
        key = self._validate_custom_transport(name, "get_transport_class")
        return self._registry.get_transport_class(key)

    def get_transport_info(self, name: str) -> dict[str, Any]:
        """Get information about a registered custom transport.

        Args:
            name: Name of the registered transport

        Returns:
            Dictionary containing transport information

        Raises:
            TransportRegistrationError: If transport is not registered or not custom
        """
        key = self._validate_custom_transport(name, "get_transport_info")
        return self._registry.get_transport_info(key)

    def list_transports(self) -> dict[str, dict[str, Any]]:
        """List all registered custom transports.

        Returns:
            Dictionary mapping transport names to their information
        """
        return self._registry.list_custom_transports()

    def create_transport(self, name: str, *args, **kwargs) -> TransportProtocol:
        """Create an instance of a registered custom transport.

        Args:
            name: Name of the registered transport
            *args: Positional arguments to pass to transport constructor
            **kwargs: Keyword arguments to pass to transport constructor

        Returns:
            Transport instance

        Raises:
            TransportRegistrationError: If transport is not registered or not custom
        """
        key = self._validate_custom_transport(name, "create_transport")
        return self._registry.create_transport(key, *args, **kwargs)


# Global registry instance
registry = CustomTransportRegistry()


def register_custom_transport(
    name: str,
    transport_class: Type[TransportProtocol],
    description: str = "",
    config_schema: dict[str, Any] | None = None,
    factory_function: Callable | None = None,
) -> None:
    """Register a custom transport with the global registry.

    Args:
        name: Unique name for the transport
        transport_class: The transport class to register
        description: Human-readable description
        config_schema: JSON schema for transport configuration
        factory_function: Optional factory function to create transport instances
    """
    registry.register(
        name, transport_class, description, config_schema, factory_function
    )


def create_custom_transport(name: str, *args, **kwargs) -> TransportProtocol:
    """Create an instance of a registered custom transport.

    Args:
        name: Name of the registered transport
        *args: Positional arguments to pass to transport constructor
        **kwargs: Keyword arguments to pass to transport constructor

    Returns:
        Transport instance
    """
    return registry.create_transport(name, *args, **kwargs)


def list_custom_transports() -> dict[str, dict[str, Any]]:
    """List all registered custom transports.

    Returns:
        Dictionary mapping transport names to their information
    """
    return registry.list_transports()
