#!/usr/bin/env python3
"""Unit tests for config adapter and port."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from unittest.mock import Mock, patch

import pytest

from mcp_fuzzer.client.adapters import ConfigAdapter, config_mediator
from mcp_fuzzer.client.ports import ConfigPort
from mcp_fuzzer.exceptions import ConfigFileError


def test_config_adapter_implements_port():
    """Test that ConfigAdapter implements ConfigPort interface."""
    adapter = ConfigAdapter()
    assert isinstance(adapter, ConfigPort)


def test_config_adapter_get_set():
    """Test ConfigAdapter get and set methods."""
    adapter = ConfigAdapter()
    adapter.set("test_key", "test_value")
    assert adapter.get("test_key") == "test_value"
    assert adapter.get("nonexistent", "default") == "default"


def test_config_adapter_update():
    """Test ConfigAdapter update method."""
    adapter = ConfigAdapter()
    adapter.update({"key1": "value1", "key2": "value2"})
    assert adapter.get("key1") == "value1"
    assert adapter.get("key2") == "value2"


def test_config_adapter_load_file(tmp_path):
    """Test ConfigAdapter load_file method."""
    config_file = tmp_path / "test.yaml"
    config_file.write_text("timeout: 30.0\nlog_level: DEBUG")

    adapter = ConfigAdapter()
    config_data = adapter.load_file(str(config_file))
    assert config_data["timeout"] == 30.0
    assert config_data["log_level"] == "DEBUG"


def test_config_adapter_load_file_not_found():
    """Test ConfigAdapter load_file raises error for missing file."""
    adapter = ConfigAdapter()
    with pytest.raises(ConfigFileError):
        adapter.load_file("/nonexistent/path.yaml")


def test_config_adapter_apply_file(tmp_path):
    """Test ConfigAdapter apply_file method."""
    config_file = tmp_path / "test.yaml"
    config_file.write_text("timeout: 45.0\nlog_level: INFO")

    adapter = ConfigAdapter()
    result = adapter.apply_file(config_path=str(config_file))
    assert result is True
    assert adapter.get("timeout") == 45.0
    assert adapter.get("log_level") == "INFO"


def test_config_adapter_apply_file_not_found():
    """Test ConfigAdapter apply_file returns False for missing file."""
    adapter = ConfigAdapter()
    result = adapter.apply_file(config_path="/nonexistent/path.yaml")
    assert result is False


def test_config_adapter_get_schema():
    """Test ConfigAdapter get_schema method."""
    adapter = ConfigAdapter()
    schema = adapter.get_schema()
    assert isinstance(schema, dict)
    assert schema["type"] == "object"
    assert "properties" in schema


def test_config_adapter_custom_instance():
    """Test ConfigAdapter with custom config instance."""
    mock_config = Mock()
    mock_config.get = Mock(return_value="custom_value")
    mock_config.set = Mock()
    mock_config.update = Mock()

    adapter = ConfigAdapter(config_instance=mock_config)
    assert adapter.get("test_key") == "custom_value"
    mock_config.get.assert_called_once_with("test_key", None)


def test_config_mediator_is_global_instance():
    """Test that config_mediator is a global ConfigAdapter instance."""
    assert isinstance(config_mediator, ConfigAdapter)
    assert isinstance(config_mediator, ConfigPort)


def test_config_mediator_functionality(tmp_path):
    """Test that global config_mediator works correctly."""
    config_file = tmp_path / "test.yaml"
    config_file.write_text("timeout: 60.0")

    # Test apply_file
    result = config_mediator.apply_file(config_path=str(config_file))
    assert result is True

    # Test get
    assert config_mediator.get("timeout") == 60.0

    # Test set
    config_mediator.set("custom_key", "custom_value")
    assert config_mediator.get("custom_key") == "custom_value"

    # Test update
    config_mediator.update({"key1": "val1", "key2": "val2"})
    assert config_mediator.get("key1") == "val1"
    assert config_mediator.get("key2") == "val2"


def test_config_mediator_as_mapping():
    """Test that config_mediator can be used as a Mapping-like object."""
    config_mediator.set("test_key", "test_value")
    # Should work with .get() method (Mapping interface)
    assert config_mediator.get("test_key") == "test_value"
    assert config_mediator.get("nonexistent", "default") == "default"
