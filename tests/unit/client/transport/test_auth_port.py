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
        "MCP_CUSTOM_HEADERS",
    ]:
        monkeypatch.delenv(key, raising=False)

    args = argparse.Namespace(auth_config=None, auth_env=False)
    assert auth_port.resolve_auth_port(args) is None
