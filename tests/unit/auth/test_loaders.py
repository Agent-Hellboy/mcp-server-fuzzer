import json
import os

import pytest

from mcp_fuzzer import exceptions
from mcp_fuzzer.auth import loaders


def test_setup_auth_from_env_populates_providers(monkeypatch):
    monkeypatch.setenv("MCP_API_KEY", "testkey")
    monkeypatch.setenv("MCP_HEADER_NAME", "X-Test")
    monkeypatch.setenv("MCP_PREFIX", "BearerTest")
    monkeypatch.setenv("MCP_USERNAME", "user")
    monkeypatch.setenv("MCP_PASSWORD", "pass")
    monkeypatch.setenv("MCP_OAUTH_TOKEN", "tok")
    monkeypatch.setenv(
        "MCP_CUSTOM_HEADERS", json.dumps({"X-Custom": "value", "Another": 1})
    )
    monkeypatch.setenv("MCP_TOOL_AUTH_MAPPING", json.dumps({"tool": "api_key"}))
    monkeypatch.setenv("MCP_DEFAULT_AUTH_PROVIDER", "api_key")

    manager = loaders.setup_auth_from_env()
    assert set(manager.auth_providers) >= {"api_key", "basic", "oauth", "custom"}
    assert manager.tool_auth_mapping == {"tool": "api_key"}
    assert manager.default_provider == "api_key"


def test_load_auth_config_file_missing(tmp_path):
    missing = tmp_path / "nofile.json"
    with pytest.raises(FileNotFoundError):
        loaders.load_auth_config(str(missing))


def test_load_auth_config_missing_required_fields(tmp_path):
    config = {
        "providers": {
            "bad_basic": {"type": "basic", "username": "user"},
            "bad_custom": {"type": "custom", "headers": "not-a-dict"},
        }
    }
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthProviderError):
        loaders.load_auth_config(str(path))


def test_load_auth_config_tool_mapping_conflict(tmp_path):
    config = {
        "providers": {},
        "tool_mapping": {"tool": "api"},
        "tool_mappings": {"tool": "basic"},
    }
    path = tmp_path / "conflict.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthConfigError):
        loaders.load_auth_config(str(path))
