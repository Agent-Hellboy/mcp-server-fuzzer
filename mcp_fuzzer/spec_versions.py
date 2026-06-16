"""Data-driven MCP protocol version discovery and validation."""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path


_VERSION_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _schema_root() -> Path:
    env_root = os.getenv("MCP_SPEC_SCHEMA_ROOT")
    if env_root:
        return Path(env_root)
    repo_root = Path(__file__).resolve().parents[1]
    return repo_root / "schemas" / "mcp-spec" / "schema"


@lru_cache(maxsize=1)
def supported_protocol_versions() -> tuple[str, ...]:
    """Return sorted MCP schema versions bundled or configured for this install."""
    extra = os.getenv("MCP_SUPPORTED_PROTOCOL_VERSIONS", "")
    extras = tuple(
        part.strip()
        for part in extra.split(",")
        if part.strip() and _VERSION_PATTERN.match(part.strip())
    )
    root = _schema_root()
    discovered: list[str] = []
    if root.exists():
        for child in root.iterdir():
            if child.is_dir() and _VERSION_PATTERN.match(child.name):
                schema_file = child / "schema.json"
                if schema_file.exists():
                    discovered.append(child.name)
    combined = sorted(set(discovered) | set(extras), reverse=True)
    return tuple(combined)


def is_supported_protocol_version(version: str) -> bool:
    """Return True when *version* is a known MCP schema release."""
    if not isinstance(version, str) or not _VERSION_PATTERN.match(version):
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
    return _schema_root() / version / "schema.json"
