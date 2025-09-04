#!/usr/bin/env python3
"""Tests for the configuration loader module."""

import os
import tempfile
import pytest
from unittest.mock import patch, mock_open

from mcp_fuzzer.config_loader import (
    find_config_file,
    load_config_file,
    apply_config_file,
    get_config_schema,
)
from mcp_fuzzer.config import config
from mcp_fuzzer.exceptions import ConfigFileError, ValidationError


@pytest.fixture
def config_files():
    """Create temporary YAML files for testing."""
    # Create temporary directory
    temp_dir = tempfile.TemporaryDirectory()

    # YAML content
    yaml_content = """
timeout: 60.0
log_level: "DEBUG"
safety:
  enabled: true
  no_network: false
  local_hosts:
    - "localhost"
    - "127.0.0.1"
"""
    # Create .yml file
    yml_path = os.path.join(temp_dir.name, "mcp-fuzzer.yml")
    with open(yml_path, "w") as f:
        f.write(yaml_content)

    # Create .yaml file
    yaml_path = os.path.join(temp_dir.name, "mcp-fuzzer.yaml")
    with open(yaml_path, "w") as f:
        f.write(yaml_content)

    # Return paths
    yield {
        "temp_dir": temp_dir,
        "yml_path": yml_path,
        "yaml_path": yaml_path,
    }

    # Cleanup
    temp_dir.cleanup()


def test_find_config_file_explicit_path(config_files):
    """Test finding a config file with an explicit path."""
    # Test with explicit path
    found_path = find_config_file(config_path=config_files["yaml_path"])
    assert found_path == config_files["yaml_path"]

    # Test with non-existent path
    found_path = find_config_file(config_path="/non/existent/path")
    assert found_path is None


def test_find_config_file_search_paths(config_files):
    """Test finding a config file in search paths."""
    # Test with search paths
    found_path = find_config_file(search_paths=[config_files["temp_dir"].name])
    assert found_path in [config_files["yml_path"], config_files["yaml_path"]]

    # Test with empty search paths
    found_path = find_config_file(search_paths=["/non/existent/path"])
    assert found_path is None


def test_load_config_file_yml(config_files):
    """Test loading a .yml config file."""
    config_data = load_config_file(config_files["yml_path"])
    assert config_data["timeout"] == 60.0
    assert config_data["log_level"] == "DEBUG"
    assert config_data["safety"]["enabled"] is True
    assert config_data["safety"]["no_network"] is False
    assert config_data["safety"]["local_hosts"] == ["localhost", "127.0.0.1"]


def test_load_config_file_yaml(config_files):
    """Test loading a .yaml config file."""
    config_data = load_config_file(config_files["yaml_path"])
    assert config_data["timeout"] == 60.0
    assert config_data["log_level"] == "DEBUG"
    assert config_data["safety"]["enabled"] is True
    assert config_data["safety"]["no_network"] is False
    assert config_data["safety"]["local_hosts"] == ["localhost", "127.0.0.1"]


def test_load_config_file_invalid_format(config_files):
    """Test loading a config file with an invalid format."""
    # Create a file with an invalid extension
    invalid_path = os.path.join(config_files["temp_dir"].name, "invalid.txt")
    with open(invalid_path, "w") as f:
        f.write("invalid content")

    with pytest.raises(ConfigFileError):
        load_config_file(invalid_path)


def test_load_config_file_not_found():
    """Test loading a non-existent config file."""
    with pytest.raises(ConfigFileError):
        load_config_file("/non/existent/path")


def test_load_config_file_invalid_yaml(config_files):
    """Test loading an invalid YAML file."""
    invalid_yaml_path = os.path.join(config_files["temp_dir"].name, "invalid.yaml")
    with open(invalid_yaml_path, "w") as f:
        f.write("invalid: yaml: content:")

    with pytest.raises(ConfigFileError):
        load_config_file(invalid_yaml_path)


def test_load_config_file_invalid_extension(config_files):
    """Test loading a file with invalid extension."""
    invalid_ext_path = os.path.join(config_files["temp_dir"].name, "config.txt")
    with open(invalid_ext_path, "w") as f:
        f.write("valid: yaml")

    with pytest.raises(ConfigFileError):
        load_config_file(invalid_ext_path)


@patch("mcp_fuzzer.config_loader.config")
def test_apply_config_file(mock_config, config_files):
    """Test applying a config file."""
    # Test with explicit path
    result = apply_config_file(config_path=config_files["yaml_path"])
    assert result is True
    mock_config.update.assert_called_once()

    # Reset mock
    mock_config.reset_mock()

    # Test with search paths
    result = apply_config_file(search_paths=[config_files["temp_dir"].name])
    assert result is True
    mock_config.update.assert_called_once()

    # Reset mock
    mock_config.reset_mock()

    # Test with non-existent path
    result = apply_config_file(config_path="/non/existent/path")
    assert result is False
    mock_config.update.assert_not_called()


def test_get_config_schema():
    """Test getting the configuration schema."""
    schema = get_config_schema()
    assert isinstance(schema, dict)
    assert schema["type"] == "object"
    assert "properties" in schema
    assert "timeout" in schema["properties"]
    assert "log_level" in schema["properties"]
    assert "safety" in schema["properties"]
