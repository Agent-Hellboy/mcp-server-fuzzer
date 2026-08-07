"""MCP spec schema versions.

Two related concerns, one home:
- **current version** — track/record the version negotiated at runtime (from an
  MCP result's ``protocolVersion``), stored in an env var.
- **supported versions** — discover and validate the schema versions bundled or
  configured for this install.
"""

from __future__ import annotations

import os
import re
from datetime import date
from functools import lru_cache
from pathlib import Path

_SPEC_VERSION_ENV = "MCP_SPEC_SCHEMA_VERSION"
_SPEC_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RC_PROTOCOL_VERSION = "2026-07-28"
RC_SCHEMA_DIR = "draft"


# --- current version (runtime tracking) -------------------------------------


def _normalize_spec_version(value: object) -> str | None:
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


def maybe_update_spec_version(value: object) -> str | None:
    """Update MCP spec schema version env var if value looks like a version."""
    normalized = _normalize_spec_version(value)
    if not normalized:
        return None
    os.environ[_SPEC_VERSION_ENV] = normalized
    return normalized


def maybe_update_spec_version_from_result(result: object) -> str | None:
    """Update spec schema version from an MCP result payload if present."""
    if not isinstance(result, dict):
        return None
    return maybe_update_spec_version(result.get("protocolVersion"))


# --- supported versions (data-driven discovery) -----------------------------


def _has_any_schema(root: Path) -> bool:
    """True when *root* looks like a populated MCP schema directory."""
    try:
        if not root.is_dir():
            return False
    except OSError:
        return False
    return any(root.glob("*/schema.json"))


def _packaged_schema_root() -> Path:
    """Schema directory shipped inside the installed ``mcp_fuzzer`` package."""
    package_root = Path(__file__).resolve().parents[1]
    return package_root / "schemas" / "mcp-spec" / "schema"


def _repo_schema_root() -> Path:
    """Schema directory from the ``schemas/mcp-spec`` git submodule (dev only)."""
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "schemas" / "mcp-spec" / "schema"


def _schema_root() -> Path:
    """Resolve the MCP schema directory for this install.

    Order of preference:
    1. ``MCP_SPEC_SCHEMA_ROOT`` when set (always wins, even if empty).
    2. Schemas packaged inside ``mcp_fuzzer`` — the normal installed case.
    3. The ``schemas/mcp-spec`` git submodule, for a source checkout.
    """
    env_root = os.getenv("MCP_SPEC_SCHEMA_ROOT")
    if env_root:
        return Path(env_root)
    packaged = _packaged_schema_root()
    if _has_any_schema(packaged):
        return packaged
    repo = _repo_schema_root()
    if _has_any_schema(repo):
        return repo
    return packaged


@lru_cache(maxsize=1)
def supported_protocol_versions() -> tuple[str, ...]:
    """Return sorted MCP schema versions bundled or configured for this install."""
    extra = os.getenv("MCP_SUPPORTED_PROTOCOL_VERSIONS", "")
    extras = tuple(
        part.strip()
        for part in extra.split(",")
        if part.strip() and _SPEC_VERSION_RE.match(part.strip())
    )
    root = _schema_root()
    discovered: list[str] = []
    if root.exists():
        for child in root.iterdir():
            if child.is_dir() and _SPEC_VERSION_RE.match(child.name):
                schema_file = child / "schema.json"
                if schema_file.exists():
                    discovered.append(child.name)
        if (root / RC_SCHEMA_DIR / "schema.json").exists():
            discovered.append(RC_PROTOCOL_VERSION)
    combined = sorted(set(discovered) | set(extras), reverse=True)
    return tuple(combined)


def is_supported_protocol_version(version: str) -> bool:
    """Return True when *version* is a known MCP schema release."""
    if not isinstance(version, str) or not _SPEC_VERSION_RE.match(version):
        return False
    if version in supported_protocol_versions():
        return True
    env_override = os.getenv("MCP_SUPPORTED_PROTOCOL_VERSIONS", "")
    return version in {
        part.strip() for part in env_override.split(",") if part.strip()
    }


def schema_path_for_version(version: str) -> Path:
    """Resolve the schema.json path for a protocol version."""
    env_path = os.getenv("MCP_SPEC_SCHEMA_PATH")
    if env_path:
        return Path(env_path)
    if version == RC_PROTOCOL_VERSION:
        release_schema = _schema_root() / version / "schema.json"
        if release_schema.exists():
            return release_schema
        return _schema_root() / RC_SCHEMA_DIR / "schema.json"
    return _schema_root() / version / "schema.json"
