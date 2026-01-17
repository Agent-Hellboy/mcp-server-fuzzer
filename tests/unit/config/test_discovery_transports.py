#!/usr/bin/env python3
"""Targeted tests for the config discovery and transport helpers."""

from __future__ import annotations

import os
import tempfile
from types import SimpleNamespace

import pytest

from mcp_fuzzer.config.loading.discovery import (
    find_config_file,
    find_config_file_from_params,
)
from mcp_fuzzer.config.loading.search_params import ConfigSearchParams
from mcp_fuzzer.config.extensions.transports import load_custom_transports
from mcp_fuzzer.exceptions import ConfigFileError
from mcp_fuzzer.transport.catalog import clear_custom_drivers, list_custom_drivers
from mcp_fuzzer.transport.interfaces.driver import TransportDriver


class DummyTransport(TransportDriver):
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
    """Helper class that does not inherit TransportDriver."""


@pytest.fixture(autouse=True)
def clear_registry():
    """Always clear custom transport registry before and after each test."""
    clear_custom_drivers()
    yield
    clear_custom_drivers()


def test_find_config_file_prefers_explicit_path(tmp_path):
    """Explicit config_path should be returned even if other files exist."""
    path = tmp_path / "mcp-fuzzer.yaml"
    path.write_text("timeout: 5")
    result = find_config_file(
        config_path=str(path),
        search_paths=[str(tmp_path)],
    )
    assert result == str(path)


def test_find_config_file_missing_explicit_path_does_not_fallback(tmp_path):
    """Missing explicit config_path should not fall back to other locations."""
    missing_path = tmp_path / "missing.yml"
    fallback_path = tmp_path / "mcp-fuzzer.yml"
    fallback_path.write_text("timeout: 10\n")
    result = find_config_file(
        config_path=str(missing_path),
        search_paths=[str(tmp_path)],
        file_names=["mcp-fuzzer.yml"],
    )
    assert result is None


def test_find_config_file_search_paths(tmp_path):
    """Search paths should be honored when they contain a config file."""
    path = tmp_path / "mcp-fuzzer.yml"
    path.write_text("timeout: 10\n")
    result = find_config_file(
        search_paths=[str(tmp_path)],
        file_names=["mcp-fuzzer.yml"],
    )
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
    transports = list_custom_drivers()
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
    """Classes that do not inherit TransportDriver should fail validation."""
    with pytest.raises(ConfigFileError):
        load_custom_transports(
            {
                "custom_transports": {
                    "invalid": {"module": __name__, "class": "NonTransport"}
                }
            }
        )


def test_find_config_file_from_params(tmp_path):
    """Test find_config_file_from_params with ConfigSearchParams."""
    path = tmp_path / "mcp-fuzzer.yaml"
    path.write_text("timeout: 5")
    params = ConfigSearchParams(
        config_path=str(path),
        search_paths=[str(tmp_path)],
        file_names=["mcp-fuzzer.yaml"],
    )
    result = find_config_file_from_params(params)
    assert result == str(path)


def test_find_config_file_from_params_search(tmp_path):
    """Test find_config_file_from_params with search paths."""
    path = tmp_path / "mcp-fuzzer.yml"
    path.write_text("timeout: 10")
    params = ConfigSearchParams(
        config_path=None,
        search_paths=[str(tmp_path)],
        file_names=["mcp-fuzzer.yml"],
    )
    result = find_config_file_from_params(params)
    assert result == str(path)


def test_load_custom_transports_non_class_raises():
    """Non-class attributes should raise ConfigFileError with TypeError handling."""
    config_data = {
        "custom_transports": {
            "invalid": {
                "module": __name__,
                # This is a function, not a class
                "class": "test_load_custom_transports_non_class_raises",
            }
        }
    }
    with pytest.raises(ConfigFileError, match="is not a class"):
        load_custom_transports(config_data)


def test_load_custom_transports_logs_with_percent_formatting(monkeypatch):
    """Test that transport loading uses proper logging format (not f-strings)."""
    from unittest.mock import Mock

    mock_logger = Mock()
    monkeypatch.setattr("mcp_fuzzer.config.extensions.transports.logger", mock_logger)

    config_data = {
        "custom_transports": {
            "dummy": {
                "module": __name__,
                "class": "DummyTransport",
                "description": "Test transport",
            }
        }
    }

    load_custom_transports(config_data)

    # Verify logger.info was called with separate arguments (not f-string)
    mock_logger.info.assert_called_once()
    call_args = mock_logger.info.call_args
    # Should be called with format string and separate args (not f-string)
    assert len(call_args[0]) == 4  # format string + 3 args
    assert call_args[0][0] == "Loaded custom transport '%s' from %s.%s"
    assert call_args[0][1] == "dummy"
    assert call_args[0][2] == __name__
    assert call_args[0][3] == "DummyTransport"


def test_load_custom_transports_invalid_factory_path(monkeypatch):
    dummy_module = SimpleNamespace(DummyTransport=DummyTransport)

    def fake_import(name):
        if name == "dummy_module":
            return dummy_module
        raise ImportError(name)

    monkeypatch.setattr(
        "mcp_fuzzer.config.extensions.transports.importlib.import_module",
        fake_import,
    )
    monkeypatch.setattr(
        "mcp_fuzzer.config.extensions.transports.register_custom_driver",
        lambda **_kwargs: None,
    )

    config_data = {
        "custom_transports": {
            "dummy": {
                "module": "dummy_module",
                "class": "DummyTransport",
                "factory": "badpath",
            }
        }
    }

    with pytest.raises(ConfigFileError, match="Invalid factory path"):
        load_custom_transports(config_data)


def test_load_custom_transports_non_callable_factory(monkeypatch):
    dummy_module = SimpleNamespace(DummyTransport=DummyTransport)
    factory_module = SimpleNamespace(not_callable="nope")

    def fake_import(name):
        if name == "dummy_module":
            return dummy_module
        if name == "factory_module":
            return factory_module
        raise ImportError(name)

    monkeypatch.setattr(
        "mcp_fuzzer.config.extensions.transports.importlib.import_module",
        fake_import,
    )
    monkeypatch.setattr(
        "mcp_fuzzer.config.extensions.transports.register_custom_driver",
        lambda **_kwargs: None,
    )

    config_data = {
        "custom_transports": {
            "dummy": {
                "module": "dummy_module",
                "class": "DummyTransport",
                "factory": "factory_module.not_callable",
            }
        }
    }

    with pytest.raises(ConfigFileError, match="not callable"):
        load_custom_transports(config_data)
