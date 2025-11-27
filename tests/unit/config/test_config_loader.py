#!/usr/bin/env python3
"""Unit tests that exercise the new config loader helpers."""

from __future__ import annotations

import os
from pathlib import Path
from textwrap import dedent
from typing import Any

import pytest
from unittest.mock import Mock, patch

from mcp_fuzzer.config import (
    ConfigLoader,
    ConfigSearchParams,
    apply_config_file,
    find_config_file,
    get_config_schema,
    load_config_file,
)
from mcp_fuzzer.config.core.manager import Configuration
from mcp_fuzzer.exceptions import ConfigFileError


@pytest.fixture
def config_files(tmp_path: Path) -> dict[str, Any]:
    """Create a couple of temporary YAML config files for reuse."""
    content = dedent(
        """
        timeout: 60.0
        log_level: "DEBUG"
        safety:
          enabled: true
          no_network: false
          local_hosts:
            - "localhost"
        """
    ).strip()

    yml_path = tmp_path / "mcp-fuzzer.yml"
    yaml_path = tmp_path / "mcp-fuzzer.yaml"
    yml_path.write_text(content)
    yaml_path.write_text(content)

    return {
        "temp_dir": tmp_path,
        "yml_path": str(yml_path),
        "yaml_path": str(yaml_path),
    }


def test_find_config_file_explicit_path(config_files):
    result = find_config_file(config_path=config_files["yaml_path"])
    assert result == config_files["yaml_path"]


def test_find_config_file_search_paths(config_files):
    result = find_config_file(search_paths=[str(config_files["temp_dir"])])
    assert result in [config_files["yml_path"], config_files["yaml_path"]]


def test_find_config_file_default_search(monkeypatch, tmp_path):
    """Ensure the default search uses the current working directory."""
    config_path = tmp_path / "mcp-fuzzer.yml"
    config_path.write_text("timeout: 5")

    monkeypatch.chdir(tmp_path)
    assert find_config_file() == str(config_path)


def test_find_config_file_missing(tmp_path):
    result = find_config_file(
        search_paths=[str(tmp_path)],
        file_names=["nonexistent.yml"],
    )
    assert result is None


def test_load_config_file_yaml(config_files):
    config_data = load_config_file(config_files["yml_path"])
    assert config_data["log_level"] == "DEBUG"
    assert config_data["timeout"] == 60.0
    assert config_data["safety"]["enabled"] is True


def test_load_config_file_invalid_extension(tmp_path):
    invalid = tmp_path / "config.txt"
    invalid.write_text("timeout: 1")
    with pytest.raises(ConfigFileError):
        load_config_file(str(invalid))


def test_load_config_file_not_found():
    with pytest.raises(ConfigFileError):
        load_config_file("/non/existent/path.yaml")


def test_load_config_file_invalid_yaml(tmp_path):
    invalid = tmp_path / "broken.yaml"
    invalid.write_text("timeout: [1,")
    with pytest.raises(ConfigFileError):
        load_config_file(str(invalid))


@patch("mcp_fuzzer.config.loading.loader.load_custom_transports")
@patch("mcp_fuzzer.config.loading.loader.config")
def test_apply_config_file_updates_global_state(
    mock_config, mock_transports, config_files
):
    result = apply_config_file(config_path=config_files["yaml_path"])
    assert result is True
    mock_transports.assert_called_once()
    updated = mock_config.update.call_args[0][0]
    assert updated.get("timeout") == 60.0
    assert mock_config.update.call_count == 1


@patch("mcp_fuzzer.config.loading.loader.load_custom_transports")
@patch("mcp_fuzzer.config.loading.loader.config")
def test_apply_config_file_returns_false_when_missing(mock_config, mock_transports):
    result = apply_config_file(config_path="/nope.yaml")
    assert result is False
    mock_config.update.assert_not_called()
    mock_transports.assert_not_called()


def test_get_config_schema_includes_expected_fields():
    schema = get_config_schema()
    props = schema["properties"]
    assert props["timeout"]["type"] == "number"
    assert "custom_transports" in props
    assert props["custom_transports"]["patternProperties"]


def test_config_loader_load_invokes_dependencies():
    parser = Mock(return_value={"timeout": 1})
    transport_loader = Mock()
    loader = ConfigLoader(
        discoverer=lambda *_args, **_kwargs: "config.yaml",
        parser=parser,
        transport_loader=transport_loader,
    )
    data, path = loader.load()
    parser.assert_called_once_with("config.yaml")
    transport_loader.assert_called_once_with({"timeout": 1})
    assert data == {"timeout": 1}
    assert path == "config.yaml"


def test_config_loader_load_returns_none_when_not_found():
    loader = ConfigLoader(discoverer=lambda *_: None)
    data, path = loader.load()
    assert data is None
    assert path is None


def test_config_loader_apply_merges_data():
    parser = Mock(return_value={"log_level": "INFO"})
    mock_config = Mock(spec=Configuration)
    loader = ConfigLoader(
        discoverer=lambda *_: "config.yaml",
        parser=parser,
        transport_loader=Mock(),
        config_instance=mock_config,
    )
    assert loader.apply() is True
    mock_config.update.assert_called_once_with({"log_level": "INFO"})


def test_config_loader_apply_handles_parser_errors():
    parser = Mock(side_effect=ConfigFileError("boom"))
    mock_config = Mock(spec=Configuration)
    loader = ConfigLoader(
        discoverer=lambda *_: "config.yaml",
        parser=parser,
        transport_loader=Mock(),
        config_instance=mock_config,
    )
    assert loader.apply() is False
    mock_config.update.assert_not_called()


def test_config_loader_apply_handles_transport_errors():
    parser = Mock(return_value={"timeout": 5})
    transport_loader = Mock(side_effect=ConfigFileError("bad transport"))
    mock_config = Mock(spec=Configuration)
    loader = ConfigLoader(
        discoverer=lambda *_: "config.yaml",
        parser=parser,
        transport_loader=transport_loader,
        config_instance=mock_config,
    )
    assert loader.apply() is False
    mock_config.update.assert_not_called()


def test_config_loader_load_logs_at_debug_level(config_files):
    """Test that loading configuration logs at DEBUG level."""
    import logging

    with patch("mcp_fuzzer.config.loading.loader.logger") as mock_logger:
        loader = ConfigLoader()
        loader.load(config_path=config_files["yaml_path"])
        # Should log at DEBUG level, not INFO
        mock_logger.debug.assert_called()
        mock_logger.info.assert_not_called()


def test_config_loader_apply_logs_failures():
    """Test that apply() logs failures at DEBUG level."""
    parser = Mock(side_effect=ConfigFileError("test error"))
    mock_config = Mock(spec=Configuration)
    loader = ConfigLoader(
        discoverer=lambda *_: "config.yaml",
        parser=parser,
        transport_loader=Mock(),
        config_instance=mock_config,
    )
    with patch("mcp_fuzzer.config.loading.loader.logger") as mock_logger:
        result = loader.apply()
        assert result is False
        # Should log the failure at DEBUG level
        mock_logger.debug.assert_called()
        # Check that the log message contains the expected text
        call_args_str = str(mock_logger.debug.call_args)
        assert (
            "Failed to apply configuration" in call_args_str
            or "test error" in call_args_str
        )


def test_config_loader_load_from_params():
    """Test ConfigLoader.load_from_params() method."""
    parser = Mock(return_value={"timeout": 30})
    params = ConfigSearchParams(config_path="test.yaml")
    loader = ConfigLoader(
        discoverer=lambda *args, **kwargs: "test.yaml",
        parser=parser,
        transport_loader=Mock(),
    )
    data, path = loader.load_from_params(params)
    assert data == {"timeout": 30}
    assert path == "test.yaml"


def test_config_loader_apply_from_params():
    """Test ConfigLoader.apply_from_params() method."""
    parser = Mock(return_value={"log_level": "DEBUG"})
    mock_config = Mock(spec=Configuration)
    params = ConfigSearchParams(config_path="test.yaml")
    loader = ConfigLoader(
        discoverer=lambda *args, **kwargs: "test.yaml",
        parser=parser,
        transport_loader=Mock(),
        config_instance=mock_config,
    )
    result = loader.apply_from_params(params)
    assert result is True
    mock_config.update.assert_called_once_with({"log_level": "DEBUG"})
