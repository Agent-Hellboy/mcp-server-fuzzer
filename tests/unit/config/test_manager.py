#!/usr/bin/env python3
"""Unit tests for configuration manager."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from mcp_fuzzer.config.core.manager import (
    Configuration,
    _get_bool_from_env,
    _get_float_from_env,
    config,
)


def test_get_float_from_env_with_value():
    """Test _get_float_from_env with valid environment variable."""
    with patch.dict(os.environ, {"TEST_FLOAT": "42.5"}):
        assert _get_float_from_env("TEST_FLOAT", 0.0) == 42.5


def test_get_float_from_env_with_default():
    """Test _get_float_from_env when variable is not set."""
    with patch.dict(os.environ, {}, clear=True):
        assert _get_float_from_env("TEST_FLOAT", 10.0) == 10.0


def test_get_float_from_env_with_invalid_value():
    """Test _get_float_from_env with invalid value falls back to default."""
    with patch.dict(os.environ, {"TEST_FLOAT": "not_a_number"}):
        assert _get_float_from_env("TEST_FLOAT", 5.0) == 5.0


def test_get_bool_from_env_true_values():
    """Test _get_bool_from_env with various true values."""
    true_values = ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON"]
    for val in true_values:
        with patch.dict(os.environ, {"TEST_BOOL": val}):
            assert _get_bool_from_env("TEST_BOOL", False) is True


def test_get_bool_from_env_false_values():
    """Test _get_bool_from_env with false values."""
    false_values = ["0", "false", "no", "off", "anything_else"]
    for val in false_values:
        with patch.dict(os.environ, {"TEST_BOOL": val}):
            assert _get_bool_from_env("TEST_BOOL", True) is False


def test_get_bool_from_env_with_default():
    """Test _get_bool_from_env when variable is not set."""
    with patch.dict(os.environ, {}, clear=True):
        assert _get_bool_from_env("TEST_BOOL", True) is True
        assert _get_bool_from_env("TEST_BOOL", False) is False


def test_configuration_loads_from_env():
    """Test Configuration loads values from environment variables."""
    env_vars = {
        "MCP_FUZZER_TIMEOUT": "60.0",
        "MCP_FUZZER_LOG_LEVEL": "DEBUG",
        "MCP_FUZZER_SAFETY_ENABLED": "true",
        "MCP_FUZZER_FS_ROOT": "/custom/path",
        "MCP_FUZZER_HTTP_TIMEOUT": "45.0",
        "MCP_FUZZER_SSE_TIMEOUT": "50.0",
        "MCP_FUZZER_STDIO_TIMEOUT": "55.0",
    }
    with patch.dict(os.environ, env_vars):
        cfg = Configuration()
        assert cfg.get("timeout") == 60.0
        assert cfg.get("log_level") == "DEBUG"
        assert cfg.get("safety_enabled") is True
        assert cfg.get("fs_root") == "/custom/path"
        assert cfg.get("http_timeout") == 45.0
        assert cfg.get("sse_timeout") == 50.0
        assert cfg.get("stdio_timeout") == 55.0


def test_configuration_uses_defaults():
    """Test Configuration uses defaults when env vars are not set."""
    with patch.dict(os.environ, {}, clear=True):
        cfg = Configuration()
        assert cfg.get("timeout") == 30.0
        assert cfg.get("log_level") == "INFO"
        assert cfg.get("safety_enabled") is False


def test_configuration_get_with_default():
    """Test Configuration.get() with custom default."""
    cfg = Configuration()
    assert cfg.get("nonexistent_key", "default_value") == "default_value"


def test_configuration_set():
    """Test Configuration.set() method."""
    cfg = Configuration()
    cfg.set("custom_key", "custom_value")
    assert cfg.get("custom_key") == "custom_value"


def test_configuration_update():
    """Test Configuration.update() method."""
    cfg = Configuration()
    cfg.update({"key1": "value1", "key2": "value2"})
    assert cfg.get("key1") == "value1"
    assert cfg.get("key2") == "value2"


def test_global_config_instance():
    """Test that global config instance exists and is usable."""
    assert config is not None
    assert isinstance(config, Configuration)
    # Should have default values
    assert config.get("timeout") is not None
