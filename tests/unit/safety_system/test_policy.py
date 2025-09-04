#!/usr/bin/env python3
import os

from mcp_fuzzer.safety_system.policy import (
    is_host_allowed,
    resolve_redirect_safely,
    sanitize_subprocess_env,
    sanitize_headers,
    configure_network_policy,
)


def test_is_host_allowed_defaults():
    # With default config SAFETY_NO_NETWORK_DEFAULT=False, all hosts allowed
    assert is_host_allowed("http://example.com") is True
    assert is_host_allowed("http://localhost") is True


def test_is_host_allowed_strict_mode_local_only():
    assert is_host_allowed("http://example.com", deny_network_by_default=True) is False
    assert is_host_allowed("http://localhost", deny_network_by_default=True) is True


def test_resolve_redirect_safely_same_origin():
    base = "http://localhost:8000/a"
    # relative path
    assert (
        resolve_redirect_safely(base, "/b", deny_network_by_default=True)
        == "http://localhost:8000/b"
    )
    # cross-origin refused
    assert resolve_redirect_safely(base, "http://example.com/x", True) is None


def test_sanitize_subprocess_env_strips_proxies(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy")
    monkeypatch.setenv("NO_PROXY", "*")
    env = sanitize_subprocess_env(os.environ)
    assert "HTTP_PROXY" not in env
    assert "NO_PROXY" not in env


def test_sanitize_headers_drops_auth():
    cleaned = sanitize_headers({"Authorization": "x", "X-Test": "y"})
    assert "Authorization" not in cleaned
    assert cleaned["X-Test"] == "y"


def test_configure_network_policy_reset_hosts():
    # Add a host to allowed list
    configure_network_policy(extra_allowed_hosts=["example.com"])

    # Check that host is allowed when deny_network=True
    url = "http://example.com"
    assert is_host_allowed(url, deny_network_by_default=True) is True

    # Reset the allowed hosts list
    configure_network_policy(reset_allowed_hosts=True)

    # Check that host is no longer allowed
    assert is_host_allowed(url, deny_network_by_default=True) is False
