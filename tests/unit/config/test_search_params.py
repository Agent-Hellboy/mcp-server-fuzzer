#!/usr/bin/env python3
"""Unit tests for ConfigSearchParams dataclass."""

from __future__ import annotations

import pytest

from mcp_fuzzer.config.loading.search_params import ConfigSearchParams


def test_config_search_params_defaults():
    """Test that ConfigSearchParams has sensible defaults."""
    params = ConfigSearchParams()
    assert params.config_path is None
    assert params.search_paths is None
    assert params.file_names is None


def test_config_search_params_with_values():
    """Test ConfigSearchParams with provided values."""
    params = ConfigSearchParams(
        config_path="/path/to/config.yaml",
        search_paths=["/dir1", "/dir2"],
        file_names=["config.yml", "config.yaml"],
    )
    assert params.config_path == "/path/to/config.yaml"
    assert params.search_paths == ["/dir1", "/dir2"]
    assert params.file_names == ["config.yml", "config.yaml"]


def test_config_search_params_partial():
    """Test ConfigSearchParams with partial values."""
    params = ConfigSearchParams(config_path="/explicit/path.yaml")
    assert params.config_path == "/explicit/path.yaml"
    assert params.search_paths is None
    assert params.file_names is None


def test_config_search_params_equality():
    """Test that ConfigSearchParams supports equality comparison."""
    params1 = ConfigSearchParams(
        config_path="/path.yaml",
        search_paths=["/dir1"],
        file_names=["config.yaml"],
    )
    params2 = ConfigSearchParams(
        config_path="/path.yaml",
        search_paths=["/dir1"],
        file_names=["config.yaml"],
    )
    params3 = ConfigSearchParams(config_path="/different.yaml")

    assert params1 == params2
    assert params1 != params3


def test_config_search_params_repr():
    """Test that ConfigSearchParams has a useful string representation."""
    params = ConfigSearchParams(config_path="/test.yaml")
    repr_str = repr(params)
    assert "ConfigSearchParams" in repr_str
    assert "/test.yaml" in repr_str
