#!/usr/bin/env python3
"""
Unit tests for auth port resolution.
"""

import argparse

import pytest

from mcp_fuzzer.client.transport import auth_port

pytestmark = [pytest.mark.unit, pytest.mark.client]


def test_resolve_auth_port_config(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(auth_port, "load_auth_config", lambda path: sentinel)
    args = argparse.Namespace(auth_config="auth.json", auth_env=False)
    assert auth_port.resolve_auth_port(args) is sentinel


def test_resolve_auth_port_env(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(auth_port, "setup_auth_from_env", lambda: sentinel)
    args = argparse.Namespace(auth_config=None, auth_env=True)
    assert auth_port.resolve_auth_port(args) is sentinel


def test_resolve_auth_port_env_auto_detect(monkeypatch):
    """Env variables should trigger auto-detect when no flags are set."""
    sentinel = object()
    monkeypatch.setenv("MCP_API_KEY", "secret")
    monkeypatch.setattr(auth_port, "setup_auth_from_env", lambda: sentinel)
    args = argparse.Namespace(auth_config=None, auth_env=False)
    assert auth_port.resolve_auth_port(args) is sentinel


def test_resolve_auth_port_env_auto_detect_oauth_client_credentials(monkeypatch):
    """OAuth client credentials env variables should trigger auto-detect."""
    sentinel = object()
    monkeypatch.setenv("MCP_OAUTH_TOKEN_URL", "https://auth.example.com/token")
    monkeypatch.setattr(auth_port, "setup_auth_from_env", lambda: sentinel)
    args = argparse.Namespace(auth_config=None, auth_env=False)
    assert auth_port.resolve_auth_port(args) is sentinel


def test_resolve_auth_port_prefers_config_over_env(monkeypatch):
    """Explicit config should win even if env vars are present."""
    monkeypatch.setenv("MCP_API_KEY", "secret")
    config_sentinel = object()
    env_sentinel = object()
    monkeypatch.setattr(auth_port, "load_auth_config", lambda path: config_sentinel)
    monkeypatch.setattr(auth_port, "setup_auth_from_env", lambda: env_sentinel)

    args = argparse.Namespace(auth_config="auth.json", auth_env=False)

    assert auth_port.resolve_auth_port(args) is config_sentinel


def test_resolve_auth_port_none(monkeypatch):
    """Should return None when no config, flag, or env vars are present."""
    for key in [
        "MCP_API_KEY",
        "MCP_USERNAME",
        "MCP_PASSWORD",
        "MCP_OAUTH_TOKEN",
        "MCP_OAUTH_TOKEN_URL",
        "MCP_OAUTH_CLIENT_ID",
        "MCP_OAUTH_CLIENT_SECRET",
        "MCP_CUSTOM_HEADERS",
    ]:
        monkeypatch.delenv(key, raising=False)

    args = argparse.Namespace(auth_config=None, auth_env=False)
    assert auth_port.resolve_auth_port(args) is None


def test_resolve_auth_port_yaml_section(monkeypatch):
    sentinel = object()

    def fake_get(key):
        return {"type": "api_key"} if key == "auth" else None

    monkeypatch.setattr(auth_port.config_mediator, "get", fake_get)
    monkeypatch.setattr(
        auth_port, "build_auth_from_yaml_section", lambda section: sentinel
    )
    args = argparse.Namespace(auth_config=None, auth_env=False, oauth=False)
    assert auth_port.resolve_auth_port(args) is sentinel


def test_build_oauth_auth_manager_requires_endpoint():
    from mcp_fuzzer.exceptions import AuthConfigError

    args = argparse.Namespace(oauth=True, endpoint=None)
    with pytest.raises(AuthConfigError, match="--oauth requires --endpoint"):
        auth_port._build_oauth_auth_manager(args)


def test_build_oauth_auth_manager_uses_env_fallback(monkeypatch):
    class FakeManager:
        def __init__(self):
            self.providers = {}
            self.default = None

        def add_auth_provider(self, name, provider):
            self.providers[name] = provider

        def set_default_provider(self, name):
            self.default = name

    class FakeProvider:
        def __init__(self, endpoint, config, use_token_cache):
            self.endpoint = endpoint
            self.config = config
            self.use_token_cache = use_token_cache

    monkeypatch.setenv("MCP_OAUTH_CLIENT_ID", "env-client")
    monkeypatch.setenv("MCP_OAUTH_CLIENT_SECRET", "env-secret")
    monkeypatch.setattr("mcp_fuzzer.auth.AuthManager", FakeManager)
    monkeypatch.setattr("mcp_fuzzer.auth.oauth.MCPOAuthProvider", FakeProvider)
    monkeypatch.setattr(
        "mcp_fuzzer.auth.oauth.OAuthClientConfig",
        lambda **kwargs: type("Cfg", (), kwargs)(),
    )

    args = argparse.Namespace(
        oauth=True,
        endpoint="https://example.com/mcp",
        oauth_grant="authorization_code",
        oauth_client_id=None,
        oauth_client_secret=None,
        oauth_scope=None,
        oauth_client_id_metadata_url=None,
        oauth_open_browser=False,
        oauth_no_token_cache=False,
    )
    manager = auth_port._build_oauth_auth_manager(args)
    assert manager.default == "mcp_oauth"
    provider = manager.providers["mcp_oauth"]
    assert provider.config.client_id == "env-client"
    assert provider.config.client_secret == "env-secret"
    assert provider.use_token_cache is True
