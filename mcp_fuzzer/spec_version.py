"""Helpers for managing MCP spec schema versions."""

from __future__ import annotations

import os
import re
from datetime import date
from typing import Any

_SPEC_VERSION_ENV = "MCP_SPEC_SCHEMA_VERSION"
_SPEC_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _normalize_spec_version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or not _SPEC_VERSION_RE.match(normalized):
        return None
    try:
        date.fromisoformat(normalized)
    except ValueError:
        return None
    return normalized


def maybe_update_spec_version(value: Any) -> str | None:
    """Update MCP spec schema version env var if value looks like a version."""
    normalized = _normalize_spec_version(value)
    if not normalized:
        return None
    os.environ[_SPEC_VERSION_ENV] = normalized
    return normalized


def maybe_update_spec_version_from_result(result: Any) -> str | None:
    """Update spec schema version from an MCP result payload if present."""
    if not isinstance(result, dict):
        return None
    return maybe_update_spec_version(result.get("protocolVersion"))
