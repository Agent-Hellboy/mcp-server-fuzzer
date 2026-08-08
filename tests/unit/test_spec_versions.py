#!/usr/bin/env python3
"""Tests for MCP protocol version discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

import mcp_fuzzer.spec_guard.spec_version as spec_versions


@pytest.fixture(autouse=True)
def clear_version_cache():
    spec_versions.supported_protocol_versions.cache_clear()
    yield
    spec_versions.supported_protocol_versions.cache_clear()


def test_supported_protocol_versions_includes_bundled_schemas():
    versions = spec_versions.supported_protocol_versions()
    assert "2025-11-25" in versions or len(versions) >= 1


def test_supported_protocol_versions_merges_env_extra(monkeypatch):
    monkeypatch.setenv("MCP_SUPPORTED_PROTOCOL_VERSIONS", "2099-01-01")
    versions = spec_versions.supported_protocol_versions()
    assert "2099-01-01" in versions


def test_is_supported_protocol_version_rejects_invalid_format():
    assert spec_versions.is_supported_protocol_version("not-a-version") is False
    assert spec_versions.is_supported_protocol_version("2025-13-40") is False


def test_is_supported_protocol_version_env_only_override(monkeypatch):
    monkeypatch.setenv("MCP_SUPPORTED_PROTOCOL_VERSIONS", "2099-06-15")
    spec_versions.supported_protocol_versions.cache_clear()
    assert spec_versions.is_supported_protocol_version("2099-06-15") is True


def test_schema_path_for_version_uses_env_override(monkeypatch, tmp_path):
    schema_file = tmp_path / "custom-schema.json"
    schema_file.write_text("{}")
    monkeypatch.setenv("MCP_SPEC_SCHEMA_PATH", str(schema_file))
    assert spec_versions.schema_path_for_version("2025-11-25") == schema_file


def test_schema_root_uses_env_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_SPEC_SCHEMA_ROOT", str(tmp_path))
    assert spec_versions._schema_root() == tmp_path


def test_schema_path_for_version_default_layout():
    path = spec_versions.schema_path_for_version("2025-11-25")
    assert path.name == "schema.json"
    assert path.parent.name == "2025-11-25"
    assert isinstance(path, Path)


def test_schema_root_helpers_point_at_expected_layout():
    packaged = spec_versions._packaged_schema_root()
    repo = spec_versions._repo_schema_root()
    for root in (packaged, repo):
        assert root.parts[-3:] == ("schemas", "mcp-spec", "schema")
    assert packaged.parents[2].name == "mcp_fuzzer"
    assert repo.parents[2] == packaged.parents[3]


def test_has_any_schema_survives_oserror(monkeypatch):
    """A probe of an unreadable path must report "no schemas", not raise."""

    def raise_oserror(self):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "is_dir", raise_oserror)
    assert spec_versions._has_any_schema(Path("/nonexistent/root")) is False


def test_has_any_schema_false_for_non_directory(tmp_path):
    plain_file = tmp_path / "not-a-dir"
    plain_file.write_text("{}")
    assert spec_versions._has_any_schema(plain_file) is False


def test_schema_root_falls_back_to_repo_submodule(monkeypatch, tmp_path):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_ROOT", raising=False)
    packaged = tmp_path / "packaged"
    packaged.mkdir()
    repo = tmp_path / "repo"
    (repo / "2025-11-25").mkdir(parents=True)
    (repo / "2025-11-25" / "schema.json").write_text("{}")

    monkeypatch.setattr(spec_versions, "_packaged_schema_root", lambda: packaged)
    monkeypatch.setattr(spec_versions, "_repo_schema_root", lambda: repo)

    assert spec_versions._schema_root() == repo


def test_schema_root_defaults_to_packaged_when_nothing_populated(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_ROOT", raising=False)
    packaged = tmp_path / "packaged"
    repo = tmp_path / "repo"
    monkeypatch.setattr(spec_versions, "_packaged_schema_root", lambda: packaged)
    monkeypatch.setattr(spec_versions, "_repo_schema_root", lambda: repo)

    assert spec_versions._schema_root() == packaged


def test_draft_schema_directory_reports_latest_version(monkeypatch, tmp_path):
    """A draft/ directory stands in for the latest revision until it is dated."""
    draft = tmp_path / spec_versions.DRAFT_SCHEMA_DIR
    draft.mkdir()
    (draft / "schema.json").write_text("{}")
    monkeypatch.setenv("MCP_SPEC_SCHEMA_ROOT", str(tmp_path))
    monkeypatch.delenv("MCP_SUPPORTED_PROTOCOL_VERSIONS", raising=False)
    spec_versions.supported_protocol_versions.cache_clear()

    assert spec_versions.supported_protocol_versions() == (
        spec_versions.LATEST_PROTOCOL_VERSION,
    )


def test_schema_path_for_latest_falls_back_to_draft(monkeypatch, tmp_path):
    draft_schema = tmp_path / spec_versions.DRAFT_SCHEMA_DIR / "schema.json"
    draft_schema.parent.mkdir(parents=True)
    draft_schema.write_text("{}")
    monkeypatch.delenv("MCP_SPEC_SCHEMA_PATH", raising=False)
    monkeypatch.setenv("MCP_SPEC_SCHEMA_ROOT", str(tmp_path))

    # No dated directory for the latest revision, so the draft schema is used.
    assert (
        spec_versions.schema_path_for_version(
            spec_versions.LATEST_PROTOCOL_VERSION
        )
        == draft_schema
    )


def test_schema_path_for_latest_prefers_dated_directory(monkeypatch, tmp_path):
    latest = spec_versions.LATEST_PROTOCOL_VERSION
    dated_schema = tmp_path / latest / "schema.json"
    dated_schema.parent.mkdir(parents=True)
    dated_schema.write_text("{}")
    (tmp_path / spec_versions.DRAFT_SCHEMA_DIR).mkdir()
    (tmp_path / spec_versions.DRAFT_SCHEMA_DIR / "schema.json").write_text("{}")
    monkeypatch.delenv("MCP_SPEC_SCHEMA_PATH", raising=False)
    monkeypatch.setenv("MCP_SPEC_SCHEMA_ROOT", str(tmp_path))

    assert spec_versions.schema_path_for_version(latest) == dated_schema
