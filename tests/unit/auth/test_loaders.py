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
    monkeypatch.setenv("MCP_OAUTH_TOKEN_URL", "https://auth.example.com/token")
    monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "client-id")
    monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("MCP_OAUTH_SCOPE", "tools.read")
    monkeypatch.setenv(
        "MCP_CUSTOM_HEADERS", json.dumps({"X-Custom": "value", "Another": 1})
    )
    monkeypatch.setenv("MCP_TOOL_AUTH_MAPPING", json.dumps({"tool": "api_key"}))
    monkeypatch.setenv("MCP_DEFAULT_AUTH_PROVIDER", "api_key")

    manager = loaders.setup_auth_from_env()
    assert set(manager.auth_providers) >= {
        "api_key",
        "basic",
        "oauth",
        "oauth_client_credentials",
        "custom",
    }
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


def test_load_auth_config_rejects_legacy_tool_mappings_key(tmp_path):
    config = {
        "providers": {},
        "tool_mappings": {"tool": "basic"},
    }
    path = tmp_path / "conflict.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthConfigError, match="no longer supported"):
        loaders.load_auth_config(str(path))


def test_load_auth_config_api_key_missing_field(tmp_path):
    """api_key provider without 'api_key' field raises AuthProviderError."""
    config = {"providers": {"mykey": {"type": "api_key", "header_name": "X-Test"}}}
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthProviderError, match="api_key"):
        loaders.load_auth_config(str(path))


def test_load_auth_config_basic_missing_username(tmp_path):
    """basic provider without 'username' field raises AuthProviderError."""
    config = {"providers": {"mybasic": {"type": "basic", "password": "pass"}}}
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthProviderError, match="username"):
        loaders.load_auth_config(str(path))


def test_load_auth_config_oauth_valid(tmp_path):
    """oauth provider with token loads correctly."""
    config = {
        "providers": {
            "myoauth": {"type": "oauth", "token": "tok123", "token_type": "Bearer"}
        }
    }
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    manager = loaders.load_auth_config(str(path))
    assert "myoauth" in manager.auth_providers


def test_load_auth_config_oauth_missing_token(tmp_path):
    """oauth provider without 'token' field raises AuthProviderError."""
    config = {"providers": {"myoauth": {"type": "oauth"}}}
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthProviderError, match="token"):
        loaders.load_auth_config(str(path))


def test_load_auth_config_custom_valid(tmp_path):
    """custom provider with valid headers dict loads correctly."""
    config = {
        "providers": {
            "mycustom": {"type": "custom", "headers": {"X-Api": "val"}}
        }
    }
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    manager = loaders.load_auth_config(str(path))
    assert "mycustom" in manager.auth_providers


def test_load_auth_config_custom_missing_headers(tmp_path):
    """custom provider without 'headers' field raises AuthProviderError."""
    config = {"providers": {"mycustom": {"type": "custom"}}}
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthProviderError, match="headers"):
        loaders.load_auth_config(str(path))


def test_load_auth_config_custom_non_dict_headers(tmp_path):
    """custom provider with non-dict headers raises AuthProviderError."""
    config = {"providers": {"mycustom": {"type": "custom", "headers": ["bad"]}}}
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthProviderError):
        loaders.load_auth_config(str(path))


def test_load_auth_config_oauth_client_credentials_invalid_timeout(tmp_path):
    """oauth_client_credentials with non-numeric timeout raises AuthProviderError."""
    config = {
        "providers": {
            "m2m": {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id": "cid",
                "client_secret": "csecret",
                "timeout": "not-a-float",
            }
        }
    }
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    with pytest.raises(exceptions.AuthProviderError):
        loaders.load_auth_config(str(path))


def test_load_auth_config_no_tool_mapping(tmp_path):
    """Config without tool_mapping key produces empty mapping."""
    config = {"providers": {}}
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))

    manager = loaders.load_auth_config(str(path))
    assert manager.tool_auth_mapping == {}
