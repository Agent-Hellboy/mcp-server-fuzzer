#!/usr/bin/env python3
"""
Unit tests for configuration classes and utilities.
"""

import os
from pathlib import Path

import pytest

from mcp_fuzzer.fuzz_engine.runtime.config import (
    ProcessConfig,
    ProcessConfigBuilder,
    WatchdogConfig,
    merge_env,
)


class TestProcessConfig:
    """Test ProcessConfig dataclass."""

    def test_default_values(self):
        """Test ProcessConfig with default values."""
        config = ProcessConfig(command=["test"])
        assert config.command == ["test"]
        assert config.cwd is None
        assert config.env is None
        assert config.timeout == 30.0
        assert config.auto_kill is True
        assert config.name == "unknown"
        assert config.activity_callback is None

    def test_custom_values(self):
        """Test ProcessConfig with custom values."""

        def callback():
            return 1.0

        config = ProcessConfig(
            command=["echo", "test"],
            cwd="/tmp",
            env={"TEST": "value"},
            timeout=60.0,
            auto_kill=False,
            name="custom_process",
            activity_callback=callback,
        )
        assert config.command == ["echo", "test"]
        assert config.cwd == "/tmp"
        assert config.env == {"TEST": "value"}
        assert config.timeout == 60.0
        assert config.auto_kill is False
        assert config.name == "custom_process"
        assert config.activity_callback == callback

    def test_from_config(self):
        """Test ProcessConfig.from_config factory method."""
        config_dict = {"process_timeout": 45.0, "auto_kill": False}
        config = ProcessConfig.from_config(config_dict, command=["test"], name="test")
        assert config.timeout == 45.0
        assert config.auto_kill is False
        assert config.command == ["test"]
        assert config.name == "test"


class TestWatchdogConfig:
    """Test WatchdogConfig dataclass."""

    def test_default_values(self):
        """Test WatchdogConfig with default values."""
        config = WatchdogConfig()
        assert config.check_interval == 1.0
        assert config.process_timeout == 30.0
        assert config.extra_buffer == 5.0
        assert config.max_hang_time == 60.0
        assert config.auto_kill is True

    def test_custom_values(self):
        """Test WatchdogConfig with custom values."""
        config = WatchdogConfig(
            check_interval=2.0,
            process_timeout=60.0,
            extra_buffer=10.0,
            max_hang_time=120.0,
            auto_kill=False,
        )
        assert config.check_interval == 2.0
        assert config.process_timeout == 60.0
        assert config.extra_buffer == 10.0
        assert config.max_hang_time == 120.0
        assert config.auto_kill is False

    def test_from_config(self):
        """Test WatchdogConfig.from_config factory method."""
        config_dict = {
            "watchdog_check_interval": 2.0,
            "watchdog_process_timeout": 60.0,
            "watchdog_extra_buffer": 10.0,
            "watchdog_max_hang_time": 120.0,
            "auto_kill": False,
        }
        config = WatchdogConfig.from_config(config_dict)
        assert config.check_interval == 2.0
        assert config.process_timeout == 60.0
        assert config.extra_buffer == 10.0
        assert config.max_hang_time == 120.0
        assert config.auto_kill is False

    def test_from_config_partial(self):
        """Test WatchdogConfig.from_config with partial config."""
        config_dict = {"watchdog_check_interval": 3.0}
        config = WatchdogConfig.from_config(config_dict)
        assert config.check_interval == 3.0
        # Other values should use defaults
        assert config.process_timeout == 30.0
        assert config.auto_kill is True


class TestProcessConfigBuilder:
    """Test ProcessConfigBuilder."""

    def test_build_with_command(self):
        """Test building a config with command."""
        config = (
            ProcessConfigBuilder()
            .with_command(["echo", "test"])
            .with_name("test_process")
            .build()
        )
        assert config.command == ["echo", "test"]
        assert config.name == "test_process"

    def test_build_without_command_raises(self):
        """Test that building without command raises ValueError."""
        builder = ProcessConfigBuilder()
        with pytest.raises(ValueError, match="non-empty command"):
            builder.build()

    def test_build_with_empty_command_raises(self):
        """Test that building with empty command raises ValueError."""
        builder = ProcessConfigBuilder().with_command([])
        with pytest.raises(ValueError, match="non-empty command"):
            builder.build()

    def test_chainable_methods(self):
        """Test that builder methods are chainable."""
        config = (
            ProcessConfigBuilder()
            .with_command(["test"])
            .with_cwd("/tmp")
            .with_env({"TEST": "value"})
            .with_timeout(60.0)
            .with_auto_kill(False)
            .with_name("test_process")
            .build()
        )
        assert config.command == ["test"]
        assert config.cwd == "/tmp"
        assert config.env == {"TEST": "value"}
        assert config.timeout == 60.0
        assert config.auto_kill is False
        assert config.name == "test_process"

    def test_with_cwd_path_object(self):
        """Test with_cwd accepts Path objects."""
        path = Path("/tmp")
        config = ProcessConfigBuilder().with_command(["test"]).with_cwd(path).build()
        assert config.cwd == path

    def test_with_activity_callback(self):
        """Test with_activity_callback."""

        def callback():
            return 1.0

        config = (
            ProcessConfigBuilder()
            .with_command(["test"])
            .with_activity_callback(callback)
            .build()
        )
        assert config.activity_callback == callback

    def test_with_activity_callback_none(self):
        """Test with_activity_callback(None)."""
        config = (
            ProcessConfigBuilder()
            .with_command(["test"])
            .with_activity_callback(None)
            .build()
        )
        assert config.activity_callback is None


class TestMergeEnv:
    """Test merge_env function."""

    def test_merge_env_with_base(self):
        """Test merging with base environment."""
        base = {"VAR1": "value1", "VAR2": "value2"}
        overrides = {"VAR2": "new_value2", "VAR3": "value3"}
        result = merge_env(base, overrides)
        assert result["VAR1"] == "value1"
        assert result["VAR2"] == "new_value2"  # Override
        assert result["VAR3"] == "value3"

    def test_merge_env_without_base(self):
        """Test merging without base (uses os.environ)."""
        overrides = {"TEST_VAR": "test_value"}
        result = merge_env(None, overrides)
        # Should include OS environment
        assert "TEST_VAR" in result
        assert result["TEST_VAR"] == "test_value"
        # Should include existing OS vars
        if "PATH" in os.environ:
            assert "PATH" in result

    def test_merge_env_without_overrides(self):
        """Test merging without overrides."""
        base = {"VAR1": "value1"}
        result = merge_env(base, None)
        assert result == base

    def test_merge_env_base_not_modified(self):
        """Test that base dict is not modified."""
        base = {"VAR1": "value1"}
        overrides = {"VAR2": "value2"}
        result = merge_env(base, overrides)
        assert "VAR2" in result
        assert "VAR2" not in base  # Base should not be modified

    def test_merge_env_empty_overrides(self):
        """Test merging with empty overrides dict."""
        base = {"VAR1": "value1"}
        result = merge_env(base, {})
        assert result == base
