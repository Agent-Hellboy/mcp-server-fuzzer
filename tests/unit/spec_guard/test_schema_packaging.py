#!/usr/bin/env python3
"""Guards that the MCP spec schemas actually ship with the package.

Without these files ``supported_protocol_versions()`` returns ``()`` and every
spec check silently no-ops, so an installed fuzzer would report conformance on
the basis of zero checks. These tests fail loudly if the schemas stop shipping.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import mcp_fuzzer.spec_guard.spec_version as spec_version

# Versions that must be present inside the installed package.
REQUIRED_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28",
)


@pytest.fixture(autouse=True)
def clear_version_cache():
    spec_version.supported_protocol_versions.cache_clear()
    yield
    spec_version.supported_protocol_versions.cache_clear()


def test_schemas_are_packaged_inside_mcp_fuzzer():
    """Schemas live under mcp_fuzzer/ so they survive a wheel install."""
    packaged = spec_version._packaged_schema_root()
    assert packaged.is_dir(), f"packaged schema dir missing: {packaged}"
    # Must sit inside the importable package, not the repo root.
    import mcp_fuzzer

    package_dir = Path(mcp_fuzzer.__file__).resolve().parent
    assert package_dir in packaged.resolve().parents


@pytest.mark.parametrize("version", REQUIRED_VERSIONS)
def test_required_version_ships_valid_schema(version):
    schema_file = spec_version._packaged_schema_root() / version / "schema.json"
    assert schema_file.is_file(), f"missing packaged schema for {version}"
    data = json.loads(schema_file.read_text())
    assert isinstance(data, dict) and data, f"empty schema for {version}"


def test_schema_root_prefers_packaged_over_repo_submodule(monkeypatch):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_ROOT", raising=False)
    assert spec_version._schema_root() == spec_version._packaged_schema_root()


def test_schema_root_env_override_still_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_SPEC_SCHEMA_ROOT", str(tmp_path))
    assert spec_version._schema_root() == tmp_path


def test_supported_versions_non_empty_without_repo_checkout(monkeypatch):
    """The installed-package case: no submodule, no env vars, still works."""
    monkeypatch.delenv("MCP_SPEC_SCHEMA_ROOT", raising=False)
    monkeypatch.delenv("MCP_SUPPORTED_PROTOCOL_VERSIONS", raising=False)
    # Force the repo-submodule fallback to look absent.
    monkeypatch.setattr(
        spec_version,
        "_repo_schema_root",
        lambda: Path("/nonexistent-mcp-fuzzer-schema-root"),
    )
    versions = spec_version.supported_protocol_versions()
    assert versions, "spec validation would silently no-op"
    for required in REQUIRED_VERSIONS:
        assert required in versions


def test_schema_path_resolves_for_every_supported_version(monkeypatch):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_PATH", raising=False)
    monkeypatch.delenv("MCP_SPEC_SCHEMA_ROOT", raising=False)
    for version in REQUIRED_VERSIONS:
        path = spec_version.schema_path_for_version(version)
        assert path.is_file(), f"unresolvable schema path for {version}: {path}"


def test_vendored_schemas_match_submodule_when_present():
    """Vendored copies must not drift from the schemas/mcp-spec submodule."""
    repo_root = spec_version._repo_schema_root()
    if not spec_version._has_any_schema(repo_root):
        pytest.skip("schemas/mcp-spec submodule not checked out")
    packaged_root = spec_version._packaged_schema_root()
    for version in REQUIRED_VERSIONS:
        upstream = repo_root / version / "schema.json"
        vendored = packaged_root / version / "schema.json"
        if not upstream.is_file():
            continue
        assert vendored.read_bytes() == upstream.read_bytes(), (
            f"vendored schema for {version} has drifted from the submodule; "
            f"re-copy {upstream} to {vendored}"
        )
