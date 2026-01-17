"""Shared helpers for spec guard checks and runners."""

from __future__ import annotations

import os
from typing import Any, TypedDict


def _spec_version() -> str:
    return os.getenv("MCP_SPEC_SCHEMA_VERSION", "2025-06-18")


def _resolve_spec(spec: dict[str, str]) -> dict[str, str]:
    spec_id = spec.get("spec_id", "")
    spec_url = spec.get("spec_url", "")
    if "{version}" in spec_url:
        spec_url = spec_url.format(version=_spec_version())
    return {"spec_id": spec_id, "spec_url": spec_url}


class SpecCheck(TypedDict, total=False):
    """Minimal spec check record for reporting."""

    id: str
    status: str
    message: str
    spec_id: str
    spec_url: str
    details: dict[str, Any]


TOOLS_SPEC = {
    "spec_id": "MCP-Tools",
    "spec_url": "https://modelcontextprotocol.io/specification/{version}/server/tools",
}

SCHEMA_SPEC = {
    "spec_id": "MCP-Schema",
    "spec_url": "https://modelcontextprotocol.io/specification/{version}/schema",
}

RESOURCES_SPEC = {
    "spec_id": "MCP-Resources",
    "spec_url": "https://modelcontextprotocol.io/specification/{version}/server/resources",
}

PROMPTS_SPEC = {
    "spec_id": "MCP-Prompts",
    "spec_url": "https://modelcontextprotocol.io/specification/{version}/server/prompts",
}

COMPLETIONS_SPEC = {
    "spec_id": "MCP-Completions",
    "spec_url": (
        "https://modelcontextprotocol.io/specification/{version}/server/completions"
    ),
}

LOGGING_SPEC = {
    "spec_id": "MCP-Logging",
    "spec_url": (
        "https://modelcontextprotocol.io/specification/{version}/server/utilities/logging"
    ),
}

SSE_SPEC = {
    "spec_id": "MCP-SSE",
    "spec_url": (
        "https://modelcontextprotocol.io/specification/{version}/basic/transports#sse-transport"
    ),
}


def spec_variant(
    spec: dict[str, str],
    *,
    spec_id: str | None = None,
    spec_url: str | None = None,
) -> dict[str, str]:
    """Create a shallow spec metadata variant with optional overrides."""
    result = {
        "spec_id": spec_id or spec.get("spec_id", ""),
        "spec_url": spec_url or spec.get("spec_url", ""),
    }
    if "{version}" in result["spec_url"]:
        result["spec_url"] = result["spec_url"].format(version=_spec_version())
    return result


def fail(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a failure SpecCheck."""
    resolved = _resolve_spec(spec)
    return {
        "id": check_id,
        "status": "FAIL",
        "message": message,
        "spec_id": resolved.get("spec_id", ""),
        "spec_url": resolved.get("spec_url", ""),
    }


def warn(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a warning SpecCheck."""
    resolved = _resolve_spec(spec)
    return {
        "id": check_id,
        "status": "WARN",
        "message": message,
        "spec_id": resolved.get("spec_id", ""),
        "spec_url": resolved.get("spec_url", ""),
    }


def pass_check(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a passing SpecCheck."""
    resolved = _resolve_spec(spec)
    return {
        "id": check_id,
        "status": "PASS",
        "message": message,
        "spec_id": resolved.get("spec_id", ""),
        "spec_url": resolved.get("spec_url", ""),
    }
