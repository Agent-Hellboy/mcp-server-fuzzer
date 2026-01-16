#!/usr/bin/env python3
"""
Schema-driven protocol fuzzing helpers.

Loads MCP spec JSON Schema from the submodule and generates request payloads
that stay schema-valid while exercising edge cases.
"""

from __future__ import annotations

import json
import os
import random
import re
from pathlib import Path
from typing import Any, Callable

from .schema_helpers import apply_schema_edge_cases, apply_semantic_combos
from .schema_parser import make_fuzz_strategy_from_jsonschema

_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def clear_schema_cache() -> None:
    """Clear the in-memory schema cache."""
    _SCHEMA_CACHE.clear()


def _schema_version_or_env(version: str | None) -> str | None:
    """Resolve a schema version from overrides or the environment."""
    return version or os.getenv("MCP_SPEC_SCHEMA_VERSION")


MALICIOUS_STRINGS = [
    "<script>alert('xss')</script>",
    "' OR '1'='1",
    "file:///etc/passwd",
    "../../etc/passwd",
    "cursor_" + ("A" * 128),
    "A" * 512,
    "\x00" * 32,
    "null\x00value",
]

MALICIOUS_NUMBERS = [
    -2147483648,
    2147483647,
    -9223372036854775808,
    9223372036854775807,
    0,
    999999999,
    -999999999,
]

_PROTOCOL_TYPE_OVERRIDES = {
    "CancelNotification": "CancelledNotification",
}


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (
            (parent / "pyproject.toml").exists()
            or (parent / ".git").exists()
            or (parent / "setup.cfg").exists()
        ):
            return parent
    return current.parents[4] if len(current.parents) > 4 else current.parent


def _schema_root() -> Path:
    env_root = os.getenv("MCP_SPEC_SCHEMA_ROOT")
    if env_root:
        return Path(env_root)
    return _repo_root() / "schemas" / "mcp-spec" / "schema"


def _latest_schema_version(root: Path) -> str | None:
    if not root.exists():
        return None
    versions = [p.name for p in root.iterdir() if p.is_dir()]
    if not versions:
        return None

    def _version_key(name: str) -> tuple[tuple[int, ...], str]:
        parts = tuple(int(part) for part in re.findall(r"\d+", name))
        return (parts, name)

    return max(versions, key=_version_key)


def _schema_path(version: str | None) -> Path:
    env_path = os.getenv("MCP_SPEC_SCHEMA_PATH")
    if env_path:
        return Path(env_path)
    root = _schema_root()
    chosen = (
        version
        or os.getenv("MCP_SPEC_SCHEMA_VERSION")
        or _latest_schema_version(root)
    )
    if not chosen:
        return root / "schema.json"
    return root / chosen / "schema.json"


def _load_schema(version: str | None) -> dict[str, Any] | None:
    path = _schema_path(version)
    cache_key = str(path.resolve())
    if cache_key in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[cache_key]
    if not path.exists():
        return None
    with path.open() as fh:
        data = json.load(fh)
    _SCHEMA_CACHE[cache_key] = data
    return data


def _resolve_refs(
    schema: Any,
    definitions: dict[str, Any],
    seen: set[str] | None = None,
) -> Any:
    if seen is None:
        seen = set()
    if isinstance(schema, dict):
        ref = schema.get("$ref")
        if isinstance(ref, str) and (
            ref.startswith("#/definitions/") or ref.startswith("#/$defs/")
        ):
            name = ref.split("/", 2)[2]
            if name in seen:
                return {}
            target = definitions.get(name, {})
            merged = {k: v for k, v in schema.items() if k != "$ref"}
            resolved = _resolve_refs(target, definitions, seen | {name})
            if isinstance(resolved, dict):
                merged.update(resolved)
            return _resolve_refs(merged, definitions, seen | {name})
        return {k: _resolve_refs(v, definitions, seen) for k, v in schema.items()}
    if isinstance(schema, list):
        return [_resolve_refs(item, definitions, seen) for item in schema]
    return schema


def _definition_for(protocol_type: str, version: str | None) -> dict[str, Any] | None:
    schema = _load_schema(version)
    if not schema:
        return None
    definitions = schema.get("definitions")
    if not isinstance(definitions, dict):
        definitions = schema.get("$defs", {})
    key = _PROTOCOL_TYPE_OVERRIDES.get(protocol_type, protocol_type)
    definition = definitions.get(key)
    if not isinstance(definition, dict):
        return None
    return _resolve_refs(definition, definitions)


def _generate_params(
    definition: dict[str, Any], phase: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    params_schema = definition.get("properties", {}).get("params", {"type": "object"})
    if not isinstance(params_schema, dict):
        params_schema = {"type": "object"}
    params = make_fuzz_strategy_from_jsonschema(params_schema, phase=phase)
    if not isinstance(params, dict):
        params = {}
    return params, params_schema


def _mutate_value_for_aggressive(value: Any, key: str | None = None) -> Any:
    """Recursively mutate payloads for aggressive phases."""
    if isinstance(value, dict):
        return {k: _mutate_value_for_aggressive(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_mutate_value_for_aggressive(item, key) for item in value]
    if isinstance(value, str):
        lowered = (key or "").lower()
        if any(token in lowered for token in ("uri", "url", "path", "file", "dir")):
            return random.choice(MALICIOUS_STRINGS)
        if random.random() < 0.25:
            return random.choice(MALICIOUS_STRINGS)
        return value
    if isinstance(value, (int, float)) and random.random() < 0.2:
        return random.choice(MALICIOUS_NUMBERS)
    return value


def _mutate_aggressive_params(params: dict[str, Any]) -> dict[str, Any]:
    mutated = _mutate_value_for_aggressive(params)
    if isinstance(mutated, dict):
        return mutated
    return params


def _apply_semantic_overrides(params: dict[str, Any], phase: str) -> dict[str, Any]:
    """Apply semantic overrides (e.g., pathogenic URIs) to schema-generated params."""
    if not isinstance(params, dict):
        return params
    patched = dict(params)
    if phase == "aggressive":
        # Apply aggressive mutation first
        patched = _mutate_aggressive_params(patched)
        # Then apply semantic overrides (these take precedence)
        if "uri" in patched and isinstance(patched["uri"], str):
            patched["uri"] = "file:///tmp/mcp-fuzzer/../../etc/passwd"
        if "cursor" in patched and isinstance(patched["cursor"], str):
            patched["cursor"] = "cursor_" + ("A" * 256)
        if "name" in patched and isinstance(patched["name"], str):
            patched["name"] = patched["name"] + ("_A" * 32)
        apply_semantic_combos(patched)
    return patched


def _prepare_schema_params_from_definition(
    definition: dict[str, Any], phase: str, overrides: dict[str, Any] | None
) -> dict[str, Any]:
    params, params_schema = _generate_params(definition, phase)
    params = apply_schema_edge_cases(params, params_schema, phase=phase, key="params")
    params = _apply_semantic_overrides(params, phase)
    if overrides:
        params = {**params, **overrides}
    return params


def _prepare_schema_params(
    protocol_type: str,
    phase: str,
    overrides: dict[str, Any] | None,
    schema_version: str | None,
) -> dict[str, Any]:
    version = _schema_version_or_env(schema_version)
    definition = _definition_for(protocol_type, version)
    if not definition:
        return overrides or {}
    return _prepare_schema_params_from_definition(definition, phase, overrides)


def _extract_method_const(definition: dict[str, Any]) -> str | None:
    method_spec = definition.get("properties", {}).get("method")
    if isinstance(method_spec, dict):
        return method_spec.get("const")
    return None


def _build_schema_request(
    protocol_type: str,
    phase: str,
    overrides: dict[str, Any] | None = None,
    schema_version: str | None = None,
) -> dict[str, Any] | None:
    version = _schema_version_or_env(schema_version)
    definition = _definition_for(protocol_type, version)
    if not definition:
        return None
    params = _prepare_schema_params_from_definition(definition, phase, overrides)
    method_const = _extract_method_const(definition)
    envelope: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": method_const or "unknown",
        "params": params,
    }
    if not protocol_type.endswith("Notification"):
        envelope["id"] = random.randint(1, 1000000)
    return envelope


def _build_generic_jsonrpc_request(phase: str = "aggressive") -> dict[str, Any]:
    """Build a generic JSON-RPC request without schema definitions."""
    method = random.choice(
        [
            "resources/list",
            "resources/read",
            "tools/call",
            "prompts/list",
            "custom/method",
            "unknown/method",
        ]
    )
    if phase == "aggressive":
        params: dict[str, Any] = {
            "value": random.choice(MALICIOUS_STRINGS + MALICIOUS_NUMBERS),
            "metadata": {"nested": random.choice(MALICIOUS_STRINGS)},
        }
    else:
        params = {"value": "test", "metadata": {"nested": "ok"}}
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": random.randint(1, 1000000),
    }


def get_spec_protocol_fuzzer_method(
    protocol_type: str,
    phase: str = "aggressive",
    schema_version: str | None = None,
) -> Callable[[], dict[str, Any] | None] | None:
    if protocol_type == "GenericJSONRPCRequest":
        def _build_generic() -> dict[str, Any] | None:
            return _build_generic_jsonrpc_request(phase)

        return _build_generic

    if not _definition_for(protocol_type, _schema_version_or_env(schema_version)):
        return None

    def _build() -> dict[str, Any] | None:
        return _build_schema_request(
            protocol_type, phase, schema_version=_schema_version_or_env(schema_version)
        )

    return _build


def build_spec_params(
    protocol_type: str,
    *,
    overrides: dict[str, Any] | None = None,
    phase: str = "aggressive",
    schema_version: str | None = None,
) -> dict[str, Any]:
    """
    Build params for a request using the MCP schema.

    Args:
        protocol_type: Request definition name (e.g., CallToolRequest)
        overrides: Values to merge on top of the generated params
        phase: Schema fuzzing phase
        schema_version: Optional MCP schema version to target

    Returns:
        Dict of params that conform to the spec (with overrides applied)
    """
    params = _prepare_schema_params(
        protocol_type, phase, overrides, schema_version=schema_version
    )
    return params if isinstance(params, dict) else overrides or {}
