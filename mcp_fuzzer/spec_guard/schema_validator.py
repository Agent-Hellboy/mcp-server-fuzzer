"""JSON Schema validation helpers for MCP spec guard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .helpers import SpecCheck, _spec_version

try:
    from jsonschema import Draft202012Validator, validators

    HAVE_JSONSCHEMA = True
except Exception:  # noqa: BLE001 - optional dependency
    Draft202012Validator = None
    validators = None
    HAVE_JSONSCHEMA = False

_SCHEMA_SPEC = {
    "spec_id": "MCP-Schema",
    "spec_url": "https://modelcontextprotocol.io/specification/{version}/schema",
}

SCHEMA_BASE_PATH = (
    Path(__file__).resolve().parent.parent.parent / "schemas" / "mcp-spec" / "schema"
)
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def _make_check(status: str, message: str, details: dict[str, Any]) -> SpecCheck:
    spec_url = _SCHEMA_SPEC["spec_url"].format(version=_spec_version())
    return {
        "id": "schema-validate",
        "status": status,
        "message": message,
        "spec_id": _SCHEMA_SPEC["spec_id"],
        "spec_url": spec_url,
        "details": details,
    }


def _load_schema(version: str) -> dict[str, Any]:
    if version in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[version]

    schema_path = SCHEMA_BASE_PATH / version / "schema.json"
    data = json.loads(schema_path.read_text(encoding="utf-8"))
    _SCHEMA_CACHE[version] = data
    return data


def get_all_result_definitions(version: str | None = None) -> list[str]:
    """Discover all Result-type definitions from the schema."""
    if version is None:
        version = _spec_version()
    
    try:
        schema = _load_schema(version)
    except Exception:  # noqa: BLE001 - schema load errors
        return []
    
    defs_key = "$defs" if "$defs" in schema else "definitions"
    definitions = schema.get(defs_key, {})
    
    # Find all definitions that end with "Result"
    result_types = [
        name for name in definitions.keys() 
        if name.endswith("Result") and name != "Result"
    ]
    
    return sorted(result_types)


def get_result_to_method_mapping() -> dict[str, tuple[str, str | None]]:
    """
    Map Result type names to (method, capability) tuples.
    
    Returns a dict mapping Result type name to (method_name, capability_key).
    capability_key is None if the method doesn't require a specific capability.
    """
    return {
        "InitializeResult": ("initialize", None),
        "EmptyResult": ("ping", None),
        "ListToolsResult": ("tools/list", "tools"),
        "CallToolResult": ("tools/call", "tools"),
        "ListResourcesResult": ("resources/list", "resources"),
        "ReadResourceResult": ("resources/read", "resources"),
        "ListResourceTemplatesResult": ("resources/templates/list", "resources"),
        "ListPromptsResult": ("prompts/list", "prompts"),
        "GetPromptResult": ("prompts/get", "prompts"),
        "CompleteResult": ("completion/complete", "completions"),
        "CreateTaskResult": ("tasks/create", "tasks"),
        "GetTaskResult": ("tasks/get", "tasks"),
        "GetTaskPayloadResult": ("tasks/getPayload", "tasks"),
        "CancelTaskResult": ("tasks/cancel", "tasks"),
        "ListTasksResult": ("tasks/list", "tasks"),
        "CreateMessageResult": ("sampling/createMessage", "sampling"),
        "ElicitResult": ("sampling/elicit", "sampling"),
    }


def discover_testable_schemas(
    version: str | None = None,
    capabilities: dict[str, Any] | None = None,
) -> list[tuple[str, str, str | None]]:
    """
    Discover all Result-type schemas that can be tested based on server capabilities.
    
    Returns a list of tuples: (result_type, method, capability_key)
    """
    if version is None:
        version = _spec_version()
    
    result_types = get_all_result_definitions(version)
    mapping = get_result_to_method_mapping()
    capabilities = capabilities or {}
    
    testable = []
    for result_type in result_types:
        if result_type in mapping:
            method, capability_key = mapping[result_type]
            # If capability_key is None, always include it
            # Otherwise, check if server supports the capability
            if capability_key is None:
                testable.append((result_type, method, None))
            elif isinstance(capabilities, dict):
                # Check if capability is supported
                # Capabilities can be boolean or an object
                cap_value = capabilities.get(capability_key)
                if cap_value is not None and cap_value is not False:
                    testable.append((result_type, method, capability_key))
    
    return testable


def validate_definition(
    definition_name: str,
    instance: Any,
    version: str | None = None,
) -> list[SpecCheck]:
    """Validate an instance against a named definition in the MCP schema."""
    if version is None:
        version = _spec_version()
    if not HAVE_JSONSCHEMA:
        return [
            _make_check(
                "WARN",
                "jsonschema not installed; schema validation skipped",
                {"definition": definition_name},
            )
        ]

    try:
        schema = _load_schema(version)
    except Exception as exc:  # noqa: BLE001 - schema load errors
        return [
            _make_check(
                "WARN",
                f"Schema load failed: {exc}",
                {"definition": definition_name},
            )
        ]

    defs_key = "$defs" if "$defs" in schema else "definitions"
    definitions = schema.get(defs_key, {})
    if definition_name not in definitions:
        return [
            _make_check(
                "WARN",
                "Schema definition not found",
                {"definition": definition_name},
            )
        ]

    wrapper = {
        "$schema": schema.get("$schema"),
        "$ref": f"#/{defs_key}/{definition_name}",
        defs_key: definitions,
    }

    try:
        validator_cls = validators.validator_for(wrapper, default=Draft202012Validator)
    except Exception as exc:  # noqa: BLE001 - unknown schema dialect
        return [
            _make_check(
                "WARN",
                f"Schema dialect not recognized: {exc}",
                {"definition": definition_name},
            )
        ]

    validator = validator_cls(wrapper)
    errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)
    if errors:
        return [
            _make_check(
                "FAIL",
                "Schema validation failed",
                {
                    "definition": definition_name,
                    "errors": [e.message for e in errors],
                },
            )
        ]

    return [
        _make_check(
            "PASS",
            "Schema validation passed",
            {"definition": definition_name},
        )
    ]
