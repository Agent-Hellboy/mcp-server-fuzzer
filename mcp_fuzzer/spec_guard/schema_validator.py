"""JSON Schema validation helpers for MCP spec guard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .helpers import SpecCheck

try:
    from jsonschema import Draft202012Validator, validators

    HAVE_JSONSCHEMA = True
except Exception:  # noqa: BLE001 - optional dependency
    Draft202012Validator = None
    validators = None
    HAVE_JSONSCHEMA = False

_SCHEMA_SPEC = {
    "spec_id": "MCP-Schema",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/schema",
}

SCHEMA_BASE_PATH = (
    Path(__file__).resolve().parent.parent.parent / "schemas" / "mcp-spec" / "schema"
)
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def _make_check(status: str, message: str, details: dict[str, Any]) -> SpecCheck:
    return {
        "id": "schema-validate",
        "status": status,
        "message": message,
        "spec_id": _SCHEMA_SPEC["spec_id"],
        "spec_url": _SCHEMA_SPEC["spec_url"],
        "details": details,
    }


def _load_schema(version: str) -> dict[str, Any]:
    if version in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[version]

    schema_path = SCHEMA_BASE_PATH / version / "schema.json"
    data = json.loads(schema_path.read_text(encoding="utf-8"))
    _SCHEMA_CACHE[version] = data
    return data


def validate_definition(
    definition_name: str,
    instance: Any,
    version: str = "2025-06-18",
) -> list[SpecCheck]:
    """Validate an instance against a named definition in the MCP schema."""
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
