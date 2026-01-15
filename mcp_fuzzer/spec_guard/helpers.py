"""Shared helpers for spec guard checks and runners."""

from __future__ import annotations

from typing import Any, TypedDict


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
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
}

SCHEMA_SPEC = {
    "spec_id": "MCP-Schema",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/schema",
}

RESOURCES_SPEC = {
    "spec_id": "MCP-Resources",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/resources",
}

PROMPTS_SPEC = {
    "spec_id": "MCP-Prompts",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/prompts",
}

COMPLETIONS_SPEC = {
    "spec_id": "MCP-Completions",
    "spec_url": (
        "https://modelcontextprotocol.io/specification/2025-06-18/server/completions"
    ),
}

LOGGING_SPEC = {
    "spec_id": "MCP-Logging",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/server/utilities/logging",
}

SSE_SPEC = {
    "spec_id": "MCP-SSE",
    "spec_url": "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#sse-transport",
}


def spec_variant(
    spec: dict[str, str],
    *,
    spec_id: str | None = None,
    spec_url: str | None = None,
) -> dict[str, str]:
    """Create a shallow spec metadata variant with optional overrides."""
    return {
        "spec_id": spec_id or spec.get("spec_id", ""),
        "spec_url": spec_url or spec.get("spec_url", ""),
    }


def fail(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a failure SpecCheck."""
    return {
        "id": check_id,
        "status": "FAIL",
        "message": message,
        "spec_id": spec.get("spec_id", ""),
        "spec_url": spec.get("spec_url", ""),
    }


def warn(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a warning SpecCheck."""
    return {
        "id": check_id,
        "status": "WARN",
        "message": message,
        "spec_id": spec.get("spec_id", ""),
        "spec_url": spec.get("spec_url", ""),
    }


def pass_check(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a passing SpecCheck."""
    return {
        "id": check_id,
        "status": "PASS",
        "message": message,
        "spec_id": spec.get("spec_id", ""),
        "spec_url": spec.get("spec_url", ""),
    }
