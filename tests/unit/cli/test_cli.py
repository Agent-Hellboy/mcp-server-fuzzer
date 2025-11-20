#!/usr/bin/env python3
"""
Unit tests for CLI module
"""

import asyncio
import os
import signal
import sys
from unittest.mock import patch, MagicMock, call

import argparse

from rich.console import Console

from mcp_fuzzer.cli import (
    create_argument_parser,
    parse_arguments,
    setup_logging,
    build_unified_client_args,
    print_startup_info,
    validate_arguments,
    get_cli_config,
)
from mcp_fuzzer.config import config as global_config
from mcp_fuzzer.exceptions import ArgumentValidationError
import mcp_fuzzer.cli.runner as runner
from unittest.mock import AsyncMock

import pytest

pytestmark = [
    pytest.mark.skipif(
        sys.version_info < (3, 10),
        reason="CLI modules require Python 3.10+ type syntax",
    ),
    pytest.mark.unit,
    pytest.mark.cli,
    pytest.mark.filterwarnings("ignore:coroutine 'main' was never awaited"),
    pytest.mark.filterwarnings(
        "ignore:coroutine 'AsyncMockMixin._execute_mock_call' was never awaited"
    ),
]


class TestCLI:
    """Test CLI functionality."""

    def test_create_argument_parser(self):
        """Test argument parser creation."""
        parser = create_argument_parser()
        assert isinstance(parser, argparse.ArgumentParser)

        # Test that required arguments are present
        args = parser.parse_args(
            [
                "--mode",
                "tools",
                "--protocol",
                "http",
                "--endpoint",
                "http://localhost:8000",
            ]
        )
        assert args.mode == "tools"
        assert args.protocol == "http"
        assert args.endpoint == "http://localhost:8000"

    def test_parse_arguments(self):
        """Test argument parsing."""
        with patch(
            "sys.argv",
            [
                "script",
                "--mode",
                "tools",
                "--protocol",
                "http",
                "--endpoint",
                "http://localhost:8000",
            ],
        ):
            args = parse_arguments()
            assert args.mode == "tools"
            assert args.protocol == "http"
            assert args.endpoint == "http://localhost:8000"

    def test_setup_logging_verbose(self):
        """Test logging setup with verbose flag."""
        args = argparse.Namespace(verbose=True)
        setup_logging(args)
        # Test that logging level is set correctly
        import logging

        # Check the current logger level (which should be affected by basicConfig)
        current_logger = logging.getLogger(__name__)
        assert current_logger.level <= logging.DEBUG

    def test_setup_logging_non_verbose(self):
        """Test logging setup without verbose flag."""
        args = argparse.Namespace(verbose=False)
        setup_logging(args)
        # Test that logging level is set correctly
        import logging

        assert logging.getLogger().level > logging.DEBUG

    def test_build_unified_client_args_basic(self):
        """Test building client arguments with basic configuration."""
        args = argparse.Namespace(
            mode="tools",
            phase="aggressive",
            protocol="http",
            endpoint="http://localhost:8000",
            timeout=30,
            verbose=False,
            runs=10,
            runs_per_type=5,
            protocol_type=None,
            auth_config=None,
            auth_env=False,
        )

        client_args = build_unified_client_args(args)
        assert client_args["mode"] == "tools"
        assert client_args["protocol"] == "http"
        assert client_args["endpoint"] == "http://localhost:8000"
        assert client_args["timeout"] == 30

    def test_build_unified_client_args_with_auth_config(self):
        """Test building client arguments with auth config."""
        mock_auth_manager = MagicMock()

        with patch("mcp_fuzzer.cli.load_auth_config", return_value=mock_auth_manager):
            args = argparse.Namespace(
                mode="tools",
                phase="aggressive",
                protocol="http",
                endpoint="http://localhost:8000",
                timeout=30,
                verbose=False,
                runs=10,
                runs_per_type=5,
                protocol_type=None,
                auth_config="auth.json",
                auth_env=False,
            )

            client_args = build_unified_client_args(args)
            assert client_args["auth_manager"] == mock_auth_manager

    def test_build_unified_client_args_with_auth_env(self):
        """Test building client arguments with auth from environment."""
        mock_auth_manager = MagicMock()

        with patch(
            "mcp_fuzzer.cli.setup_auth_from_env", return_value=mock_auth_manager
        ):
            args = argparse.Namespace(
                mode="tools",
                phase="aggressive",
                protocol="http",
                endpoint="http://localhost:8000",
                timeout=30,
                verbose=False,
                runs=10,
                runs_per_type=5,
                protocol_type=None,
                auth_config=None,
                auth_env=True,
            )

            client_args = build_unified_client_args(args)
            assert client_args["auth_manager"] == mock_auth_manager

    def test_build_unified_client_args_with_protocol_type(self):
        """Test building client arguments with protocol type."""
        args = argparse.Namespace(
            mode="protocol",
            phase="aggressive",
            protocol="http",
            endpoint="http://localhost:8000",
            timeout=30,
            verbose=False,
            runs=10,
            runs_per_type=5,
            protocol_type="initialize",
            auth_config=None,
            auth_env=False,
        )

        client_args = build_unified_client_args(args)
        assert client_args["protocol_type"] == "initialize"

    def test_print_startup_info(self):
        """Test startup info printing."""
        args = argparse.Namespace(
            mode="tool", protocol="http", endpoint="http://localhost:8000"
        )

        with patch("mcp_fuzzer.cli.Console") as mock_console:
            mock_console_instance = MagicMock()
            mock_console.return_value = mock_console_instance

            print_startup_info(args)

            # Verify console.print was called
            assert mock_console_instance.print.called

    def test_build_unified_client_args_fs_root(self):
        """Exercise fs-root handling."""
        args = argparse.Namespace(
            mode="tools",
            phase="aggressive",
            protocol="http",
            endpoint="http://localhost:8000",
            timeout=30,
            verbose=False,
            runs=10,
            runs_per_type=5,
            protocol_type=None,
            auth_config=None,
            auth_env=False,
            fs_root="/tmp/fuzzer",
            enable_safety_system=False,
            no_safety=True,
        )

        result = build_unified_client_args(args)
        assert result["fs_root"] == "/tmp/fuzzer"
        assert result["safety_enabled"] is False

    def test_build_unified_client_args_safety_default_enabled(self):
        """Ensure safety remains enabled when flag not provided."""
        args = argparse.Namespace(
            mode="tools",
            phase="aggressive",
            protocol="http",
            endpoint="http://localhost:8000",
            timeout=30,
            verbose=False,
            runs=10,
            runs_per_type=5,
            protocol_type=None,
            auth_config=None,
            auth_env=False,
            fs_root=None,
            enable_safety_system=False,
            no_safety=False,
        )

        result = build_unified_client_args(args)
        assert result["safety_enabled"] is True






    def test_validate_arguments_valid(self):
        """Test argument validation with valid arguments."""
        args = argparse.Namespace(
            mode="tool",
            protocol_type=None,
            runs=10,
            runs_per_type=5,
            timeout=30,
            endpoint="http://localhost:8000",
        )

        # Should not raise any exception
        validate_arguments(args)

    def test_validate_arguments_protocol_mode_without_type(self):
        """Test argument validation for protocol mode without type."""
        args = argparse.Namespace(
            mode="protocol",
            protocol_type=None,
            runs=10,
            runs_per_type=5,
            timeout=30,
            endpoint="http://localhost:8000",
        )

        # Should not raise any exception
        validate_arguments(args)

    def test_validate_arguments_protocol_type_without_protocol_mode(self):
        """Test argument validation for protocol type without protocol mode."""
        args = argparse.Namespace(
            mode="tool",
            protocol_type="initialize",
            runs=10,
            runs_per_type=5,
            timeout=30,
            endpoint="http://localhost:8000",
        )

        with pytest.raises(
            ArgumentValidationError,
            match="--protocol-type can only be used with --mode protocol",
        ):
            validate_arguments(args)

    def test_validate_arguments_invalid_runs(self):
        """Test argument validation with invalid runs."""
        args = argparse.Namespace(
            mode="tools",
            protocol_type=None,
            runs=0,
            runs_per_type=5,
            timeout=30,
            endpoint="http://localhost:8000",
        )

        with pytest.raises(ArgumentValidationError, match="--runs must be at least 1"):
            validate_arguments(args)

    def test_validate_arguments_invalid_runs_per_type(self):
        """Test argument validation with invalid runs_per_type."""
        args = argparse.Namespace(
            mode="tools",
            protocol_type=None,
            runs=10,
            runs_per_type=0,
            timeout=30,
            endpoint="http://localhost:8000",
        )

        with pytest.raises(
            ArgumentValidationError, match="--runs-per-type must be at least 1"
        ):
            validate_arguments(args)

    def test_validate_arguments_invalid_timeout(self):
        """Test argument validation with invalid timeout."""
        args = argparse.Namespace(
            mode="tools",
            protocol_type=None,
            runs=10,
            runs_per_type=5,
            timeout=0,
            endpoint="http://localhost:8000",
        )

        with pytest.raises(ArgumentValidationError, match="--timeout must be positive"):
            validate_arguments(args)

    def test_validate_arguments_empty_endpoint(self):
        """Test argument validation with empty endpoint."""
        args = argparse.Namespace(
            mode="tools",
            protocol_type=None,
            runs=10,
            runs_per_type=5,
            timeout=30,
            endpoint="",
        )

        with pytest.raises(
            ArgumentValidationError,
            match="--endpoint is required for fuzzing operations",
        ):
            validate_arguments(args)

    def test_validate_arguments_whitespace_endpoint(self):
        """Test argument validation with whitespace-only endpoint."""
        args = argparse.Namespace(
            mode="tools",
            protocol_type=None,
            runs=10,
            runs_per_type=5,
            timeout=30,
            endpoint="   ",
        )

        with pytest.raises(
            ArgumentValidationError, match="--endpoint cannot be empty"
        ):
            validate_arguments(args)

    def test_get_cli_config(self):
        """Test getting CLI configuration."""
        with (
            patch("mcp_fuzzer.cli.args.create_argument_parser") as mock_create_parser,
            patch("mcp_fuzzer.cli.args._load_config_from_sources") as mock_load_config,
            patch("mcp_fuzzer.cli.args.validate_arguments") as mock_validate,
            patch("mcp_fuzzer.cli.args._sync_global_config") as mock_sync_config,
            patch("mcp_fuzzer.cli.setup_logging") as mock_setup,
        ):
            mock_args = argparse.Namespace()
            mock_args.mode = "tools"
            mock_args.phase = "aggressive"
            mock_args.protocol = "http"
            mock_args.endpoint = "http://localhost:8000"
            mock_args.timeout = 30
            mock_args.verbose = False
            mock_args.runs = 10
            mock_args.runs_per_type = 5
            mock_args.protocol_type = None
            mock_args.tool_timeout = None
            mock_args.tool = None
            mock_args.fs_root = None
            mock_args.no_safety = False
            mock_args.enable_safety_system = False
            mock_args.safety_report = False
            mock_args.export_safety_data = None
            mock_args.output_dir = "reports"
            mock_args.retry_with_safety_on_interrupt = False
            mock_args.log_level = None
            mock_args.no_network = False
            mock_args.allow_hosts = None
            mock_args.validate_config = None
            mock_args.check_env = False
            mock_args.export_csv = None
            mock_args.export_xml = None
            mock_args.export_html = None
            mock_args.export_markdown = None
            mock_args.watchdog_check_interval = 1.0
            mock_args.watchdog_process_timeout = 30.0
            mock_args.watchdog_extra_buffer = 5.0
            mock_args.watchdog_max_hang_time = 60.0
            mock_args.process_max_concurrency = 5
            mock_args.process_retry_count = 1
            mock_args.process_retry_delay = 1.0
            mock_args.output_format = "json"
            mock_args.output_types = None
            mock_args.output_schema = None
            mock_args.output_compress = False
            mock_args.output_session_id = None
            mock_args.config = None
            mock_args.auth_config = None
            mock_args.auth_env = False

            mock_parser = mock_create_parser.return_value
            mock_parser.parse_args.return_value = mock_args

            # Mock the config loading to return expected config dict
            expected_config = {
                "mode": "tools",
                "protocol": "http",
                "endpoint": "http://localhost:8000",
                "timeout": 30,
                "verbose": False,
                "runs": 10,
                "runs_per_type": 5,
                "protocol_type": None,
                "tool": None,
                "auth_manager": None,
            }
            mock_load_config.return_value = expected_config

            config = get_cli_config()

            assert config["mode"] == "tools"
            assert config["protocol"] == "http"
            assert config["endpoint"] == "http://localhost:8000"
            assert config["timeout"] == 30
            assert config["verbose"] is False
            assert config["runs"] == 10
            assert config["runs_per_type"] == 5
            assert config["protocol_type"] is None
            assert "tool" in config
            assert "auth_manager" in config
            assert config["auth_manager"] is None

            mock_create_parser.assert_called_once()
            mock_load_config.assert_called_once_with(mock_args)
            mock_validate.assert_called_once_with(mock_args)
            mock_sync_config.assert_called_once_with(expected_config)
            # Note: setup_logging is not called by get_cli_config() - it violates SRP

