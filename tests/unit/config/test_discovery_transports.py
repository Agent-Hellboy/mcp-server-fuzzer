#!/usr/bin/env python3
"""Targeted tests for the config discovery and transport helpers."""

from __future__ import annotations

import os
import tempfile

import pytest

from mcp_fuzzer.config.discovery import find_config_file
from mcp_fuzzer.config.transports import load_custom_transports
from mcp_fuzzer.exceptions import ConfigFileError
from mcp_fuzzer.transport.base import TransportProtocol
from mcp_fuzzer.transport.custom import list_custom_transports, registry


class DummyTransport(TransportProtocol):
    """Simple transport stub used for registration tests."""

    async def send_request(self, method: str, params=None):
        return {"jsonrpc": "2.0", "result": {}, "id": 1}

    async def send_raw(self, payload):
        return {"result": "ok"}

    async def send_notification(self, method: str, params=None):
        return None

    async def _stream_request(self, payload):
        yield {"jsonrpc": "2.0", "result": payload}


class NonTransport:
    """Helper class that does not inherit TransportProtocol."""


@pytest.fixture(autouse=True)
def clear_registry():
    """Always clear custom transport registry before and after each test."""
    registry.clear()
    yield
    registry.clear()


def test_find_config_file_prefers_explicit_path(tmp_path):
    """Explicit config_path should be returned even if other files exist."""
    path = tmp_path / "mcp-fuzzer.yaml"
    path.write_text("timeout: 5")
    assert find_config_file(config_path=str(path), search_paths=[str(tmp_path)]) == str(path)


def test_find_config_file_search_paths(tmp_path):
    """Search paths should be honored when they contain a config file."""
    path = tmp_path / "mcp-fuzzer.yml"
    path.write_text("timeout: 10\n")
    result = find_config_file(search_paths=[str(tmp_path)], file_names=["mcp-fuzzer.yml"])
    assert result == str(path)


def test_find_config_file_returns_none_when_missing(tmp_path):
    """Return None when no configuration file exists in the requested paths."""
    assert find_config_file(search_paths=[str(tmp_path)]) is None


def test_load_custom_transports_registers_transport():
    """Valid transport entry should be registered in the custom registry."""
    config_data = {
        "custom_transports": {
            "dummy": {
                "module": __name__,
                "class": "DummyTransport",
                "description": "Unit test transport",
            }
        }
    }

    load_custom_transports(config_data)
    transports = list_custom_transports()
    assert "dummy" in transports


def test_load_custom_transports_missing_module_raises():
    """Non-existent module should raise ConfigFileError."""
    with pytest.raises(ConfigFileError):
        load_custom_transports(
            {
                "custom_transports": {
                    "missing": {"module": "no.such.module", "class": "FooTransport"}
                }
            }
        )


def test_load_custom_transports_invalid_class_raises():
    """Classes that do not inherit TransportProtocol should fail validation."""
    with pytest.raises(ConfigFileError):
        load_custom_transports(
            {
                "custom_transports": {
                    "invalid": {"module": __name__, "class": "NonTransport"}
                }
            }
        )
