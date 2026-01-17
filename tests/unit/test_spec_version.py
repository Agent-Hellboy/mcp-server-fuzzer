import os

from mcp_fuzzer import spec_version


def test_maybe_update_spec_version_valid(monkeypatch):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_VERSION", raising=False)

    updated = spec_version.maybe_update_spec_version(" 2025-11-25 ")

    assert updated == "2025-11-25"
    assert os.environ["MCP_SPEC_SCHEMA_VERSION"] == "2025-11-25"


def test_maybe_update_spec_version_invalid(monkeypatch):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_VERSION", raising=False)
    assert spec_version.maybe_update_spec_version(123) is None
    assert spec_version.maybe_update_spec_version("") is None
    assert spec_version.maybe_update_spec_version("2025-1-01") is None


def test_maybe_update_spec_version_from_result(monkeypatch):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_VERSION", raising=False)
    assert spec_version.maybe_update_spec_version_from_result("bad") is None
    assert spec_version.maybe_update_spec_version_from_result({}) is None

    updated = spec_version.maybe_update_spec_version_from_result(
        {"protocolVersion": "2025-11-25"}
    )
    assert updated == "2025-11-25"
