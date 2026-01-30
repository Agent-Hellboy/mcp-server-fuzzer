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


def test_resolve_auth_port_none():
    args = argparse.Namespace(auth_config=None, auth_env=False)
    assert auth_port.resolve_auth_port(args) is None
