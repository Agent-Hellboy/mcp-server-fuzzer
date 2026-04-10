"""Shared schema helper utilities for generating default values and tool args."""

from __future__ import annotations

import copy
from typing import Any


def _first_schema_choice(schema: dict[str, Any]) -> Any:
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return copy.deepcopy(enum_values[0])

    for key in ("oneOf", "anyOf"):
        variants = schema.get(key)
        if not isinstance(variants, list):
            continue
        for variant in variants:
            if isinstance(variant, dict) and "const" in variant:
                return copy.deepcopy(variant["const"])
    return None


def _default_schema_value(name: str, schema: dict[str, Any]) -> Any:
    """Create a deterministic default value for a JSON schema fragment."""
    if "default" in schema:
        return copy.deepcopy(schema["default"])

    chosen = _first_schema_choice(schema)
    if chosen is not None:
        return chosen

    schema_type = schema.get("type")
    if schema_type == "boolean":
        return False
    if schema_type in {"integer", "number"}:
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)):
            return minimum
        return 0
    if schema_type == "array":
        items = schema.get("items")
        if isinstance(items, dict):
            return [_default_schema_value(name, items)]
        return []
    if schema_type == "object":
        properties = schema.get("properties")
        required = (
            schema.get("required")
            if isinstance(schema.get("required"), list)
            else []
        )
        if not isinstance(properties, dict):
            return {}
        built: dict[str, Any] = {}
        for key in required:
            prop_schema = properties.get(key)
            if isinstance(key, str) and isinstance(prop_schema, dict):
                built[key] = _default_schema_value(key, prop_schema)
        return built
    if schema_type == "null":
        return None
    return f"{name}-value"


def _build_tool_arguments(tool: dict[str, Any]) -> dict[str, Any]:
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    required = (
        schema.get("required") if isinstance(schema.get("required"), list) else []
    )
    arguments: dict[str, Any] = {}
    for key in required:
        prop_schema = properties.get(key)
        if isinstance(key, str) and isinstance(prop_schema, dict):
            arguments[key] = _default_schema_value(key, prop_schema)
    return arguments


def _tool_task_support(tool: dict[str, Any]) -> str:
    execution = tool.get("execution")
    if not isinstance(execution, dict):
        return "forbidden"
    task_support = execution.get("taskSupport")
    if isinstance(task_support, str):
        return task_support
    return "forbidden"
