#!/usr/bin/env python3
"""Unit tests for configuration parser."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
import yaml

from mcp_fuzzer.config.loading.parser import load_config_file
from mcp_fuzzer.exceptions import ConfigFileError


def test_load_config_file_success(tmp_path):
    """Test successful loading of YAML config file."""
    config_path = tmp_path / "test.yaml"
    config_path.write_text("timeout: 30.0\nlog_level: DEBUG")

    result = load_config_file(str(config_path))
    assert result["timeout"] == 30.0
    assert result["log_level"] == "DEBUG"


def test_load_config_file_not_found():
    """Test that missing file raises ConfigFileError."""
    with pytest.raises(ConfigFileError, match="Configuration file not found"):
        load_config_file("/nonexistent/path.yaml")


def test_load_config_file_invalid_extension(tmp_path):
    """Test that non-YAML files raise ConfigFileError."""
    txt_file = tmp_path / "config.txt"
    txt_file.write_text("timeout: 30")
    with pytest.raises(ConfigFileError, match="Unsupported configuration file format"):
        load_config_file(str(txt_file))


def test_load_config_file_invalid_yaml(tmp_path):
    """Test that invalid YAML raises ConfigFileError with proper message."""
    invalid_yaml = tmp_path / "invalid.yaml"
    invalid_yaml.write_text("timeout: [1,")  # Invalid YAML syntax

    with pytest.raises(ConfigFileError, match="Error parsing YAML"):
        load_config_file(str(invalid_yaml))


def test_load_config_file_permission_error(tmp_path):
    """Test that permission errors raise ConfigFileError."""
    config_path = tmp_path / "test.yaml"
    config_path.write_text("timeout: 30")

    with patch("builtins.open", side_effect=PermissionError("Access denied")):
        with pytest.raises(ConfigFileError, match="Permission denied"):
            load_config_file(str(config_path))


def test_load_config_file_exception_formatting():
    """Test exceptions formatted without redundant str() conversion."""
    config_path = "/test/path.yaml"

    # Mock file exists check
    with patch("os.path.isfile", return_value=True):
        # Mock YAML parsing error
        yaml_error = yaml.YAMLError("YAML syntax error")
        with patch("builtins.open", mock_open(read_data="invalid: yaml: [")):
            with patch("yaml.safe_load", side_effect=yaml_error):
                with pytest.raises(ConfigFileError) as exc_info:
                    load_config_file(config_path)
                # Exception message should contain the error without redundant str()
                assert "YAML syntax error" in str(exc_info.value)
                assert config_path in str(exc_info.value)


def test_load_config_file_empty_file(tmp_path):
    """Test that empty file returns empty dict."""
    empty_file = tmp_path / "empty.yaml"
    empty_file.write_text("")

    result = load_config_file(str(empty_file))
    assert result == {}


def test_load_config_file_none_yaml_result(tmp_path):
    """Test that YAML file with only comments returns empty dict."""
    comment_file = tmp_path / "comments.yaml"
    comment_file.write_text("# Just a comment\n# Another comment")

    result = load_config_file(str(comment_file))
    assert result == {}


def test_load_config_file_non_dict_top_level(tmp_path):
    """Test that non-dict top-level config raises ConfigFileError."""
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("- item1\n- item2")  # List instead of dict

    with pytest.raises(ConfigFileError, match="must be a mapping/object"):
        load_config_file(str(config_path))


def test_load_config_file_output_dir_deprecation(tmp_path, caplog):
    """Test that output_dir key triggers deprecation warning and migration."""
    import logging

    caplog.set_level(logging.WARNING)
    config_path = tmp_path / "deprecated.yaml"
    config_path.write_text("output_dir: /tmp/output\nother: value")

    result = load_config_file(str(config_path))

    assert "output_dir" not in result
    assert "output" in result
    assert result["output"]["directory"] == "/tmp/output"
    assert result["other"] == "value"
    assert "deprecated" in caplog.text.lower()


def test_load_config_file_output_dir_with_existing_output(tmp_path):
    """Test output_dir migration when output section already exists."""
    config_path = tmp_path / "migration.yaml"
    config_path.write_text("output_dir: /old\noutput:\n  format: json")

    result = load_config_file(str(config_path))

    assert "output_dir" not in result
    assert result["output"]["directory"] == "/old"
    assert result["output"]["format"] == "json"


def test_load_config_file_output_dir_invalid_output_section(tmp_path, caplog):
    """Test output_dir migration when output section is not a dict."""
    import logging

    caplog.set_level(logging.WARNING)
    config_path = tmp_path / "invalid_output.yaml"
    config_path.write_text("output_dir: /tmp\noutput: invalid")

    result = load_config_file(str(config_path))

    assert "output" in result
    assert isinstance(result["output"], dict)
    assert result["output"]["directory"] == "/tmp"
    assert "must be a mapping" in caplog.text.lower()


def test_load_config_file_unexpected_exception(tmp_path):
    """Test that unexpected exceptions are wrapped in ConfigFileError."""
    config_path = tmp_path / "test.yaml"
    config_path.write_text("key: value")

    with patch("builtins.open", side_effect=OSError("Unexpected error")):
        with pytest.raises(ConfigFileError, match="Unexpected error"):
            load_config_file(str(config_path))
