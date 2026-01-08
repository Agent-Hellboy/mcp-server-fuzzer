#!/usr/bin/env python3
"""Custom transport registration helpers."""

from __future__ import annotations

import importlib
import logging
from typing import Any

from ...exceptions import ConfigFileError, MCPError
from ...transport.catalog import register_custom_driver
from ...transport.interfaces.driver import TransportDriver

logger = logging.getLogger(__name__)


def load_custom_transports(config_data: dict[str, Any]) -> None:
    """Load and register custom transports from configuration.

    Args:
        config_data: Configuration dictionary containing custom_transports section
    """
    custom_transports = config_data.get("custom_transports", {})

    for transport_name, transport_config in custom_transports.items():
        try:
            module_path = transport_config["module"]
            class_name = transport_config["class"]

            module = importlib.import_module(module_path)
            transport_class = getattr(module, class_name)
            try:
                if not issubclass(transport_class, TransportDriver):
                    raise ConfigFileError(
                        f"{module_path}.{class_name} must subclass TransportDriver"
                    )
            except TypeError:
                raise ConfigFileError(f"{module_path}.{class_name} is not a class")

            description = transport_config.get("description", "")
            config_schema = transport_config.get("config_schema")
            factory_fn = None
            factory_path = transport_config.get("factory")
            if factory_path:
                try:
                    mod_path, attr = factory_path.rsplit(".", 1)
                except ValueError as ve:
                    raise ConfigFileError(
                        f"Invalid factory path '{factory_path}'; expected 'module.attr'"
                    ) from ve
                fmod = importlib.import_module(mod_path)
                factory_fn = getattr(fmod, attr)
                if not callable(factory_fn):
                    raise ConfigFileError(f"Factory '{factory_path}' is not callable")

            register_custom_driver(
                name=transport_name,
                transport_class=transport_class,
                description=description,
                config_schema=config_schema,
                factory_function=factory_fn,
            )

            logger.info(
                "Loaded custom transport '%s' from %s.%s",
                transport_name,
                module_path,
                class_name,
            )

        except MCPError:
            raise
        except Exception as e:
            logger.error("Failed to load custom transport '%s': %s", transport_name, e)
            raise ConfigFileError(
                f"Failed to load custom transport '{transport_name}': {e}"
            ) from e
