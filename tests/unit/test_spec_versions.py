#!/usr/bin/env python3
"""Tests for MCP protocol version discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

import mcp_fuzzer.spec_version as spec_versions


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
