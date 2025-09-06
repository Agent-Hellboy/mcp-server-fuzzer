"""
Custom transport registry and utilities.

This module provides support for registering and managing custom transport
implementations that can be used alongside built-in transports.
"""

import logging
from typing import Dict, Type, Any, Optional, Callable
from .base import TransportProtocol

logger = logging.getLogger(__name__)


class CustomTransportRegistry:
    """Registry for custom transport implementations."""

    def __init__(self):
        self._transports: Dict[str, Dict[str, Any]] = {}

    def clear(self) -> None:
        """Clear all registered transports. Useful for testing."""
        self._transports.clear()

    def register(
        self,
        name: str,
        transport_class: Type[TransportProtocol],
        description: str = "",
        config_schema: Optional[Dict[str, Any]] = None,
        factory_function: Optional[Callable] = None,
    ) -> None:
        """Register a custom transport.

        Args:
            name: Unique name for the transport
            transport_class: The transport class to register
            description: Human-readable description
            config_schema: JSON schema for transport configuration
            factory_function: Optional factory function to create transport instances

        Raises:
            ValueError: If transport name is already registered
        """
        key = name.strip().lower()
        if key in self._transports:
            raise ValueError(f"Transport '{name}' is already registered")

        if not issubclass(transport_class, TransportProtocol):
            raise ValueError(
                f"Transport class {transport_class} must inherit from TransportProtocol"
            )

        self._transports[key] = {
            "class": transport_class,
            "description": description,
            "config_schema": config_schema,
            "factory": factory_function,
        }

        logger.info(f"Registered custom transport: {key}")

    def unregister(self, name: str) -> None:
        """Unregister a custom transport.

        Args:
            name: Name of the transport to unregister

        Raises:
            KeyError: If transport is not registered
        """
        key = name.strip().lower()
        if key not in self._transports:
            raise KeyError(f"Transport '{name}' is not registered")

        del self._transports[key]
        logger.info(f"Unregistered custom transport: {key}")

    def get_transport_class(self, name: str) -> Type[TransportProtocol]:
        """Get the transport class for a registered transport.

        Args:
            name: Name of the registered transport

        Returns:
            The transport class

        Raises:
            KeyError: If transport is not registered
        """
        key = name.strip().lower()
        if key not in self._transports:
            raise KeyError(f"Transport '{name}' is not registered")
        return self._transports[key]["class"]

    def get_transport_info(self, name: str) -> Dict[str, Any]:
        """Get information about a registered transport.

        Args:
            name: Name of the registered transport

        Returns:
            Dictionary containing transport information

        Raises:
            KeyError: If transport is not registered
        """
        key = name.strip().lower()
        if key not in self._transports:
            raise KeyError(f"Transport '{name}' is not registered")
        return self._transports[key].copy()

    def list_transports(self) -> Dict[str, Dict[str, Any]]:
        """List all registered custom transports.

        Returns:
            Dictionary mapping transport names to their information
        """
        return self._transports.copy()

    def create_transport(self, name: str, *args, **kwargs) -> TransportProtocol:
        """Create an instance of a registered transport.

        Args:
            name: Name of the registered transport
            *args: Positional arguments to pass to transport constructor
            **kwargs: Keyword arguments to pass to transport constructor

        Returns:
            Transport instance

        Raises:
            KeyError: If transport is not registered
        """
        transport_info = self.get_transport_info(name)
        transport_class = transport_info["class"]
        factory = transport_info.get("factory")

        # If no factory is provided, support "name://endpoint" shorthand by
        # rewriting the first positional arg to just the endpoint.
        if factory is None:
            if args and len(args) == 1 and isinstance(args[0], str):
                url = args[0]
                if f"{name}://" in url:
                    endpoint = url.split(f"{name}://", 1)[1]
                    args = (endpoint,) + args[1:]
            return transport_class(*args, **kwargs)
        else:
            # Pass through as-is; factories can handle full URLs or endpoints.
            return factory(*args, **kwargs)


# Global registry instance
registry = CustomTransportRegistry()


def register_custom_transport(
    name: str,
    transport_class: Type[TransportProtocol],
    description: str = "",
    config_schema: Optional[Dict[str, Any]] = None,
    factory_function: Optional[Callable] = None,
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


def list_custom_transports() -> Dict[str, Dict[str, Any]]:
    """List all registered custom transports.

    Returns:
        Dictionary mapping transport names to their information
    """
    return registry.list_transports()
