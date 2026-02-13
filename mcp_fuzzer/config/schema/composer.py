#!/usr/bin/env python3
"""Schema composer that combines all schema builders."""

from __future__ import annotations

from typing import Any

from .builders import (
    build_auth_schema,
    build_basic_schema,
    build_custom_transports_schema,
    build_fuzzing_schema,
    build_network_schema,
    build_output_schema,
    build_safety_schema,
    build_transport_retry_schema,
    build_timeout_schema,
)


def get_config_schema() -> dict[str, Any]:
    """Return the JSON schema describing the configuration structure.

    The schema is built by composing smaller schema builders for logical
    groupings of configuration properties.

    Returns:
        Complete JSON schema dictionary for configuration validation
    """
    properties = {}
    properties.update(build_timeout_schema())
    properties.update(build_transport_retry_schema())
    properties.update(build_basic_schema())
    properties.update(build_fuzzing_schema())
    properties.update(build_network_schema())
    properties.update(build_auth_schema())
    properties.update(build_custom_transports_schema())
    properties.update(build_safety_schema())
    properties.update(build_output_schema())

    return {
        "type": "object",
        "properties": properties,
    }
