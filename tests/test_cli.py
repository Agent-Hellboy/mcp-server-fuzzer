#!/usr/bin/env python3
"""
Unit tests for CLI module
"""

import pytest
import argparse
import sys
from unittest.mock import patch, MagicMock, mock_open
from mcp_fuzzer.cli import (
    create_argument_parser,
    parse_arguments,
    setup_logging,
    build_unified_client_args,
    print_startup_info,
    validate_arguments,
    get_cli_config,
    run_cli,
)


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

    def test_build_unified_client_args_fs_root_and_no_safety(self):
        """Exercise fs-root setter and disabling safety flags."""
        args = argparse.Namespace(
            mode="tools",
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
            safety_plugin=None,
            no_safety=True,
        )

        with (
            patch("mcp_fuzzer.cli.safety_filter.set_fs_root") as mock_set_root,
            patch("mcp_fuzzer.cli.disable_safety") as mock_disable,
        ):
            build_unified_client_args(args)
            mock_set_root.assert_called_once_with("/tmp/fuzzer")
            mock_disable.assert_called_once()

    def test_build_unified_client_args_safety_plugin_loaded_and_failure(self):
        """Cover both success and failure branches for safety plugin loading."""
        base_args = dict(
            mode="tools",
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
            no_safety=False,
        )

        args_success = argparse.Namespace(**{**base_args, "safety_plugin": "pkg.mod"})
        with patch("mcp_fuzzer.cli.load_safety_plugin") as mock_load:
            build_unified_client_args(args_success)
            mock_load.assert_called_once_with("pkg.mod")

        args_fail = argparse.Namespace(**{**base_args, "safety_plugin": "pkg.bad"})
        with patch(
            "mcp_fuzzer.cli.load_safety_plugin", side_effect=Exception("boom")
        ) as mock_load:
            build_unified_client_args(args_fail)
            mock_load.assert_called_once_with("pkg.bad")

    def test_runner_prepare_inner_argv(self):
        from mcp_fuzzer.cli.runner import prepare_inner_argv

        args = argparse.Namespace(
            mode="tools",
            protocol="http",
            endpoint="http://localhost:8000/mcp/",
            runs=3,
            runs_per_type=2,
            timeout=15,
            tool_timeout=12.5,
            protocol_type="InitializeRequest",
            verbose=True,
        )
        argv = prepare_inner_argv(args)
        assert "--mode" in argv and "tools" in argv
        assert "--protocol" in argv and "http" in argv
        assert "--endpoint" in argv and "http://localhost:8000/mcp/" in argv
        assert "--runs" in argv and "3" in argv
        assert "--runs-per-type" in argv and "2" in argv
        assert "--timeout" in argv and "15" in argv
        assert "--tool-timeout" in argv and "12.5" in argv
        assert "--protocol-type" in argv and "InitializeRequest" in argv
        assert "--verbose" in argv

    def test_runner_start_and_stop_safety(self):
        from mcp_fuzzer.cli.runner import (
            start_safety_if_enabled,
            stop_safety_if_started,
        )

        args_enabled = argparse.Namespace(enable_safety_system=True)
        args_disabled = argparse.Namespace(enable_safety_system=False)

        with (
            patch("mcp_fuzzer.cli.runner.start_system_blocking") as mock_start,
            patch("mcp_fuzzer.cli.runner.stop_system_blocking") as mock_stop,
        ):
            started = start_safety_if_enabled(args_enabled)
            assert started is True
            mock_start.assert_called_once()

            started2 = start_safety_if_enabled(args_disabled)
            assert started2 is False

            stop_safety_if_started(True)
            mock_stop.assert_called_once()

            # No-op when not started
            stop_safety_if_started(False)

    def test_runner_retry_on_interrupt_retries_once(self):
        from mcp_fuzzer.cli.runner import run_with_retry_on_interrupt

        args = argparse.Namespace(
            enable_safety_system=False,
            retry_with_safety_on_interrupt=True,
        )

        call_count = {"n": 0}

        def fake_execute(_args, _main, _argv):
            if call_count["n"] == 0:
                call_count["n"] += 1
                raise KeyboardInterrupt()
            call_count["n"] += 1
            return None

        with (
            patch(
                "mcp_fuzzer.cli.runner.execute_inner_client",
                side_effect=fake_execute,
            ) as mock_exec,
            patch("mcp_fuzzer.cli.runner.start_system_blocking") as mock_start,
            patch("mcp_fuzzer.cli.runner.stop_system_blocking") as mock_stop,
        ):
            run_with_retry_on_interrupt(args, lambda: None, ["prog"])
            assert mock_exec.call_count == 2
            mock_start.assert_called_once()
            mock_stop.assert_called_once()

    def test_runner_retry_on_interrupt_exits_when_no_retry(self):
        from mcp_fuzzer.cli.runner import run_with_retry_on_interrupt

        args = argparse.Namespace(
            enable_safety_system=False,
            retry_with_safety_on_interrupt=False,
        )

        with (
            patch(
                "mcp_fuzzer.cli.runner.execute_inner_client",
                side_effect=KeyboardInterrupt(),
            ),
            patch("mcp_fuzzer.cli.runner.sys.exit") as mock_exit,
        ):
            run_with_retry_on_interrupt(args, lambda: None, ["prog"])
            mock_exit.assert_called_once_with(130)

    def test_runner_execute_inner_client_pytest_branch(self, monkeypatch):
        from mcp_fuzzer.cli.runner import execute_inner_client

        monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")
        try:
            with patch("mcp_fuzzer.cli.runner.asyncio.run") as mock_run:
                execute_inner_client(argparse.Namespace(), lambda: None, ["prog"])
                mock_run.assert_called_once()
        finally:
            monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

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
            ValueError, match="--protocol-type can only be used with --mode protocol"
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

        with pytest.raises(ValueError, match="--runs must be at least 1"):
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

        with pytest.raises(ValueError, match="--runs-per-type must be at least 1"):
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

        with pytest.raises(ValueError, match="--timeout must be positive"):
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

        with pytest.raises(ValueError, match="--endpoint cannot be empty"):
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

        with pytest.raises(ValueError, match="--endpoint cannot be empty"):
            validate_arguments(args)

    def test_get_cli_config(self):
        """Test getting CLI configuration."""
        with (
            patch("mcp_fuzzer.cli.parse_arguments") as mock_parse,
            patch("mcp_fuzzer.cli.validate_arguments") as mock_validate,
            patch("mcp_fuzzer.cli.setup_logging") as mock_setup,
        ):
            mock_args = argparse.Namespace(
                mode="tools",
                protocol="http",
                endpoint="http://localhost:8000",
                timeout=30,
                verbose=False,
                runs=10,
                runs_per_type=5,
                protocol_type=None,
            )
            mock_parse.return_value = mock_args

            config = get_cli_config()

            assert config["mode"] == "tools"
            assert config["protocol"] == "http"
            assert config["endpoint"] == "http://localhost:8000"
            assert config["timeout"] == 30
            assert config["verbose"] is False
            assert config["runs"] == 10
            assert config["runs_per_type"] == 5
            assert config["protocol_type"] is None

            mock_parse.assert_called_once()
            mock_validate.assert_called_once_with(mock_args)
            mock_setup.assert_called_once_with(mock_args)

    @patch("mcp_fuzzer.cli.parse_arguments")
    @patch("mcp_fuzzer.cli.validate_arguments")
    @patch("mcp_fuzzer.cli.setup_logging")
    @patch("mcp_fuzzer.cli.build_unified_client_args")
    @patch("mcp_fuzzer.cli.print_startup_info")
    @patch("mcp_fuzzer.cli.create_transport")
    @patch("mcp_fuzzer.cli.asyncio.run")
    def test_run_cli_success(
        self,
        mock_asyncio_run,
        mock_create_transport,
        mock_print_info,
        mock_build_args,
        mock_setup,
        mock_validate,
        mock_parse,
    ):
        """Test successful CLI execution."""
        mock_args = argparse.Namespace(
            mode="tool",
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
        mock_parse.return_value = mock_args

        mock_client_args = {
            "mode": "tool",
            "protocol": "http",
            "endpoint": "http://localhost:8000",
            "timeout": 30,
            "auth_manager": None,
        }
        mock_build_args.return_value = mock_client_args

        mock_transport = MagicMock()
        mock_create_transport.return_value = mock_transport

        run_cli()

        mock_parse.assert_called_once()
        mock_validate.assert_called_once_with(mock_args)
        mock_setup.assert_called_once_with(mock_args)
        mock_build_args.assert_called_once_with(mock_args)
        mock_print_info.assert_called_once_with(mock_args)
        mock_create_transport.assert_called_once()
        mock_asyncio_run.assert_called_once()

    @patch("mcp_fuzzer.cli.parse_arguments")
    @patch("mcp_fuzzer.cli.validate_arguments")
    @patch("mcp_fuzzer.cli.setup_logging")
    @patch("mcp_fuzzer.cli.build_unified_client_args")
    @patch("mcp_fuzzer.cli.print_startup_info")
    @patch("mcp_fuzzer.cli.create_transport")
    @patch("mcp_fuzzer.cli.sys.exit")
    def test_run_cli_transport_error(
        self,
        mock_exit,
        mock_create_transport,
        mock_print_info,
        mock_build_args,
        mock_setup,
        mock_validate,
        mock_parse,
    ):
        """Test CLI execution with transport error."""
        mock_args = argparse.Namespace(
            mode="tool",
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
        mock_parse.return_value = mock_args

        mock_client_args = {
            "mode": "tool",
            "protocol": "http",
            "endpoint": "http://localhost:8000",
            "timeout": 30,
            "auth_manager": None,
        }
        mock_build_args.return_value = mock_client_args

        mock_create_transport.side_effect = Exception("Transport error")

        run_cli()

        mock_exit.assert_called_once_with(1)

    @patch("mcp_fuzzer.cli.parse_arguments")
    @patch("mcp_fuzzer.cli.validate_arguments")
    @patch("mcp_fuzzer.cli.sys.exit")
    def test_run_cli_validation_error(self, mock_exit, mock_validate, mock_parse):
        """Test CLI execution with validation error."""
        mock_args = argparse.Namespace()
        mock_parse.return_value = mock_args

        mock_validate.side_effect = ValueError("Invalid arguments")

        run_cli()

        mock_exit.assert_called_once_with(1)

    @patch("mcp_fuzzer.cli.parse_arguments")
    @patch("mcp_fuzzer.cli.validate_arguments")
    @patch("mcp_fuzzer.cli.setup_logging")
    @patch("mcp_fuzzer.cli.build_unified_client_args")
    @patch("mcp_fuzzer.cli.print_startup_info")
    @patch("mcp_fuzzer.cli.create_transport")
    @patch("mcp_fuzzer.cli.sys.exit")
    def test_run_cli_keyboard_interrupt(
        self,
        mock_exit,
        mock_create_transport,
        mock_print_info,
        mock_build_args,
        mock_setup,
        mock_validate,
        mock_parse,
    ):
        """Test CLI execution with keyboard interrupt."""
        mock_args = argparse.Namespace(
            mode="tool",
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
        mock_parse.return_value = mock_args

        mock_client_args = {
            "mode": "tool",
            "protocol": "http",
            "endpoint": "http://localhost:8000",
            "timeout": 30,
            "auth_manager": None,
        }
        mock_build_args.return_value = mock_client_args

        mock_transport = MagicMock()
        mock_create_transport.return_value = mock_transport

        mock_build_args.side_effect = KeyboardInterrupt()

        run_cli()

        mock_exit.assert_called_once_with(0)

    @patch("mcp_fuzzer.cli.parse_arguments")
    @patch("mcp_fuzzer.cli.validate_arguments")
    @patch("mcp_fuzzer.cli.setup_logging")
    @patch("mcp_fuzzer.cli.build_unified_client_args")
    @patch("mcp_fuzzer.cli.print_startup_info")
    @patch("mcp_fuzzer.cli.create_transport")
    @patch("mcp_fuzzer.cli.sys.exit")
    def test_run_cli_unexpected_error(
        self,
        mock_exit,
        mock_create_transport,
        mock_print_info,
        mock_build_args,
        mock_setup,
        mock_validate,
        mock_parse,
    ):
        """Test CLI execution with unexpected error."""
        mock_args = argparse.Namespace(
            mode="tools",
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
        mock_parse.return_value = mock_args

        mock_client_args = {
            "mode": "tools",
            "protocol": "http",
            "endpoint": "http://localhost:8000",
            "timeout": 30,
            "auth_manager": None,
        }
        mock_build_args.return_value = mock_client_args

        mock_transport = MagicMock()
        mock_create_transport.return_value = mock_transport

        mock_build_args.side_effect = Exception("Unexpected error")

        run_cli()

        mock_exit.assert_called_once_with(1)

    def test_argument_parser_all_options(self):
        """Test that all command line options are properly configured."""
        parser = create_argument_parser()

        # Test mode options
        args = parser.parse_args(
            [
                "--mode",
                "tools",
                "--protocol",
                "http",
                "--endpoint",
                "http://localhost:8000",
                "--timeout",
                "60",
                "--verbose",
                "--runs",
                "20",
                "--runs-per-type",
                "10",
                "--protocol-type",
                "initialize",
                "--auth-config",
                "auth.json",
            ]
        )

        assert args.mode == "tools"
        assert args.protocol == "http"
        assert args.endpoint == "http://localhost:8000"
        assert args.timeout == 60
        assert args.verbose is True
        assert args.runs == 20
        assert args.runs_per_type == 10
        assert args.protocol_type == "initialize"
        assert args.auth_config == "auth.json"

    def test_argument_parser_defaults(self):
        """Test argument parser default values."""
        parser = create_argument_parser()

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

        assert args.timeout == 30
        assert args.verbose is False
        assert args.runs == 10
        assert args.runs_per_type == 5
        assert args.protocol_type is None
        assert args.auth_config is None
        assert args.auth_env is False
