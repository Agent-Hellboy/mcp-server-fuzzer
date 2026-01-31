"""Unit tests for the refactored CLI modules."""

import argparse
import logging
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

from mcp_fuzzer.cli import (
    create_argument_parser,
    parse_arguments,
    print_startup_info,
    run_cli,
    setup_logging,
    ValidationManager,
    build_cli_config,
)
from mcp_fuzzer.cli.config_merge import CliConfig
from mcp_fuzzer.client.runtime.argv_builder import prepare_inner_argv
from mcp_fuzzer.client.runtime.async_runner import AsyncRunner
from mcp_fuzzer.client.runtime.async_runner import execute_inner_client
from mcp_fuzzer.client.runtime.retry import run_with_retry_on_interrupt
from mcp_fuzzer.client.safety import SafetyController
from mcp_fuzzer.client.transport.factory import build_driver_with_auth
from mcp_fuzzer.env import ValidationType
from mcp_fuzzer.exceptions import ArgumentValidationError, ConfigFileError, MCPError


pytestmark = [pytest.mark.unit, pytest.mark.cli]


def _base_args(**overrides):
    defaults = dict(
        mode="tools",
        phase="aggressive",
        protocol="http",
        endpoint="http://localhost",
        timeout=30.0,
        transport_retries=1,
        transport_retry_delay=0.5,
        transport_retry_backoff=2.0,
        transport_retry_max_delay=5.0,
        transport_retry_jitter=0.1,
        verbose=False,
        runs=10,
        runs_per_type=5,
        protocol_type=None,
        tool_timeout=None,
        tool=None,
        fs_root=None,
        no_safety=False,
        enable_safety_system=False,
        safety_report=False,
        export_safety_data=None,
        output_dir="reports",
        retry_with_safety_on_interrupt=False,
        log_level=None,
        no_network=False,
        allow_hosts=None,
        validate_config=None,
        check_env=False,
        export_csv=None,
        export_xml=None,
        export_html=None,
        export_markdown=None,
        watchdog_check_interval=1.0,
        watchdog_process_timeout=30.0,
        watchdog_extra_buffer=5.0,
        watchdog_max_hang_time=60.0,
        process_max_concurrency=5,
        process_retry_count=1,
        process_retry_delay=1.0,
        output_format="json",
        output_types=None,
        output_schema=None,
        output_compress=False,
        output_session_id=None,
        enable_aiomonitor=False,
        auth_config=None,
        auth_env=False,
        config=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class DummyConsole:
    def __init__(self):
        self.calls = []

    def print(self, *args, **kwargs):
        self.calls.append((args, kwargs))


def test_create_argument_parser_and_defaults():
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
    assert args.mode == "tools"
    assert args.protocol == "http"
    assert args.timeout == 30.0


def test_parse_arguments(monkeypatch):
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
    assert args.endpoint == "http://localhost:8000"


def test_setup_logging_levels():
    import logging

    args = argparse.Namespace(verbose=True, log_level=None)
    setup_logging(args)
    assert logging.getLogger().level == logging.INFO

    args2 = argparse.Namespace(verbose=False, log_level="DEBUG")
    setup_logging(args2)
    assert logging.getLogger().level == logging.DEBUG


def test_validate_arguments_errors():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="tools",
        protocol_type="x",
        runs=0,
        runs_per_type=0,
        timeout=0,
        endpoint="",
        check_env=False,
        validate_config=None,
    )
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(args)


def test_validate_arguments_runs_per_type_invalid_type():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="protocol",
        protocol_type=None,
        runs=1,
        runs_per_type="bad",
        timeout=10,
        endpoint="http://x",
        check_env=False,
        validate_config=None,
    )
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(args)


def test_validate_arguments_timeout_negative():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="tools",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=-1,
        endpoint="http://x",
        check_env=False,
        validate_config=None,
    )
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(args)


def test_validate_arguments_requires_endpoint():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="tools",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=1,
        endpoint=None,
        check_env=False,
        validate_config=None,
    )
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(args)


def test_validate_arguments_whitespace_endpoint():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="tools",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=1,
        endpoint="   ",
        check_env=False,
        validate_config=None,
    )
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(args)


def test_validate_arguments_allows_utility_without_endpoint():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="tools",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=10,
        endpoint=None,
        check_env=True,
        validate_config=None,
        tool="example",
    )
    validator.validate_arguments(args)


def test_validate_arguments_protocol_type_wrong_mode_with_endpoint():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="tools",
        protocol_type="X",
        runs=1,
        runs_per_type=1,
        timeout=10,
        endpoint="http://x",
        check_env=False,
        validate_config=None,
    )
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(args)


def test_validate_arguments_protocol_mode_requires_protocol_type():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="protocol",
        protocol="http",
        protocol_type=None,
        runs=1,
        runs_per_type=5,
        timeout=10,
        endpoint="http://x",
        check_env=False,
        validate_config=None,
    )
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(args)


def test_validate_arguments_runs_not_int():
    validator = ValidationManager()
    args = argparse.Namespace(
        mode="tools",
        protocol_type=None,
        runs="bad",
        runs_per_type=1,
        timeout=10,
        endpoint="http://x",
        check_env=False,
        validate_config=None,
    )
    with pytest.raises(ArgumentValidationError):
        validator.validate_arguments(args)


def test_print_startup_info():
    args = argparse.Namespace(mode="tools", protocol="http", endpoint="http://x")
    with patch("mcp_fuzzer.cli.startup_info.Console") as mock_console:
        mock_console.return_value = MagicMock()
        print_startup_info(args, None)
        assert mock_console.return_value.print.call_count >= 1


def test_build_cli_config_merges_and_returns_cli_config():
    args = _base_args()
    cli_config = build_cli_config(args)
    assert isinstance(cli_config, CliConfig)
    assert cli_config.merged["endpoint"] == "http://localhost"
    assert cli_config.merged["safety_enabled"] is True


def test_handle_validate_config(monkeypatch):
    validator = ValidationManager()
    with patch("mcp_fuzzer.cli.validators.config_mediator.load_file") as mock_load:
        validator.validate_config_file("config.yml")
    mock_load.assert_called_once_with("config.yml")


def test_handle_check_env(monkeypatch):
    validator = ValidationManager()
    monkeypatch.setenv("MCP_FUZZER_LOG_LEVEL", "INFO")
    result = validator.check_environment_variables()
    assert result is True


def test_handle_check_env_invalid_level(monkeypatch):
    validator = ValidationManager()
    monkeypatch.setenv("MCP_FUZZER_LOG_LEVEL", "INVALID")
    with pytest.raises(ArgumentValidationError):
        validator.check_environment_variables()


def test_prepare_inner_argv_roundtrip():
    args = _base_args(
        output_types=["fuzzing_results"],
        output_session_id="abc",
        enable_aiomonitor=True,
        output_compress=True,
        no_network=True,
        allow_hosts=["a", "b"],
        export_safety_data="",
        spec_prompt_name="example_prompt",
        spec_prompt_args='{"query": "probe"}',
    )
    argv = prepare_inner_argv(args)
    assert "--mode" in argv and "--endpoint" in argv
    assert "abc" in argv
    assert "--export-safety-data" in argv
    assert "--spec-prompt-name" in argv
    assert "--spec-prompt-args" in argv


def test_transport_factory_applies_auth_headers():
    args = MagicMock(protocol="http", endpoint="http://example.com", timeout=10.0)
    auth_manager = MagicMock()
    auth_manager.get_default_auth_headers.return_value = {"Authorization": "x"}
    with patch("mcp_fuzzer.client.transport.factory.base_build_driver") as mock_create:
        build_driver_with_auth(args, {"auth_manager": auth_manager})
        mock_create.assert_called_once_with(
            "http",
            "http://example.com",
            timeout=10.0,
            safety_enabled=True,
            auth_headers={"Authorization": "x"},
        )


def test_safety_controller():
    controller = SafetyController()
    with patch(
        "mcp_fuzzer.client.safety.controller.start_system_blocking"
    ) as mock_start:
        controller.start_if_enabled(True)
        mock_start.assert_called_once()
    with patch("mcp_fuzzer.client.safety.controller.stop_system_blocking") as mock_stop:
        controller.stop_if_started()
        mock_stop.assert_called_once()


def test_execute_inner_client_pytest_branch(monkeypatch):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")

    async def dummy_main():
        return None

    with patch("mcp_fuzzer.client.runtime.async_runner.asyncio.run") as mock_run:
        execute_inner_client(argparse.Namespace(), dummy_main, ["prog"])
        mock_run.assert_called_once()
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)


def test_execute_inner_client_network_policy(monkeypatch):
    args = MagicMock(
        retry_with_safety_on_interrupt=False,
        no_network=True,
        allow_hosts=None,
    )
    with patch(
        "mcp_fuzzer.client.runtime.async_runner.asyncio.new_event_loop"
    ) as mock_loop:
        loop = MagicMock()
        mock_loop.return_value = loop
        with patch("mcp_fuzzer.client.runtime.async_runner.asyncio.set_event_loop"):
            with patch.object(
                SafetyController, "configure_network_policy"
            ) as mock_policy:
                with patch.object(loop, "add_signal_handler"):
                    with patch.object(loop, "run_until_complete"):
                        with patch("os.environ.get", return_value=None):
                            execute_inner_client(args, lambda: None, ["prog"])
                            mock_policy.assert_called_once_with(
                                reset_allowed_hosts=True,
                                deny_network_by_default=True,
                                extra_allowed_hosts=None,
                            )


def test_run_with_retry_on_interrupt_retry_path():
    args = MagicMock(enable_safety_system=False, retry_with_safety_on_interrupt=True)
    calls = {"n": 0}

    def fake_execute(_args, _main, _argv):
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyboardInterrupt()

    with (
        patch(
            "mcp_fuzzer.client.runtime.retry.execute_inner_client",
            side_effect=fake_execute,
        ),
        patch("mcp_fuzzer.client.runtime.retry.start_system_blocking") as mock_start,
        patch("mcp_fuzzer.client.runtime.retry.stop_system_blocking") as mock_stop,
    ):
        run_with_retry_on_interrupt(args, lambda: None, ["prog"])
        assert calls["n"] == 2
        mock_start.assert_called_once()
        mock_stop.assert_called_once()


def test_validate_transport_errors():
    validator = ValidationManager()
    args = argparse.Namespace(protocol="http", endpoint="http://x", timeout=1)
    with patch(
        "mcp_fuzzer.cli.validators.build_driver",
        side_effect=Exception("boom"),
    ):
        with pytest.raises(Exception):
            validator.validate_transport(args)


def test_validate_transport_mcp_error_passthrough():
    validator = ValidationManager()
    args = argparse.Namespace(protocol="http", endpoint="http://x", timeout=1)
    with patch(
        "mcp_fuzzer.cli.validators.build_driver",
        side_effect=MCPError("err", code="X"),
    ):
        with pytest.raises(MCPError):
            validator.validate_transport(args)


def test_async_runner_calls_execute_inner_client(monkeypatch):
    args = _base_args()
    runner = AsyncRunner(args, SafetyController())
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "1")

    async def dummy_coro():
        return None

    runner.run(dummy_coro, ["prog"])
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)


def test_run_cli_happy_path():
    args = _base_args()
    with (
        patch("mcp_fuzzer.cli.entrypoint.parse_arguments", return_value=args),
        patch("mcp_fuzzer.cli.entrypoint.setup_logging"),
        patch("mcp_fuzzer.cli.entrypoint.print_startup_info"),
        patch("mcp_fuzzer.cli.entrypoint.ValidationManager") as mock_vm_cls,
        patch("mcp_fuzzer.cli.entrypoint.run_with_retry_on_interrupt"),
        patch("mcp_fuzzer.cli.entrypoint.ClientSettings"),
    ):
        mock_validator = mock_vm_cls.return_value
        mock_validator.validate_arguments.return_value = None
        mock_validator.validate_transport.return_value = None
        run_cli()


def test_run_cli_orchestration_invokes_runner():
    args = _base_args(enable_safety_system=True)
    merged = {"enable_safety_system": True}
    cli_config = CliConfig(args=args, merged=merged)
    with (
        patch("mcp_fuzzer.cli.entrypoint.parse_arguments", return_value=args),
        patch("mcp_fuzzer.cli.entrypoint.setup_logging"),
        patch("mcp_fuzzer.cli.entrypoint.print_startup_info"),
        patch("mcp_fuzzer.cli.entrypoint.build_cli_config", return_value=cli_config),
        patch("mcp_fuzzer.cli.entrypoint.ValidationManager") as mock_vm_cls,
        patch("mcp_fuzzer.cli.entrypoint.prepare_inner_argv", return_value=["prog"]),
        patch("mcp_fuzzer.cli.entrypoint.ClientSettings") as mock_settings_cls,
        patch("mcp_fuzzer.cli.entrypoint.SafetyController") as mock_safety_cls,
        patch("mcp_fuzzer.cli.entrypoint.run_with_retry_on_interrupt") as mock_runner,
    ):
        mock_validator = mock_vm_cls.return_value
        mock_validator.validate_arguments.return_value = None
        mock_validator.validate_transport.return_value = None
        mock_safety = mock_safety_cls.return_value
        run_cli()
        mock_settings_cls.assert_called_once_with(merged)
        mock_safety.start_if_enabled.assert_called_once_with(True)
        mock_runner.assert_called_once()


def test_run_cli_transport_error_exit(monkeypatch):
    args = _base_args()
    with (
        patch("mcp_fuzzer.cli.entrypoint.parse_arguments", return_value=args),
        patch("mcp_fuzzer.cli.entrypoint.setup_logging"),
        patch("mcp_fuzzer.cli.entrypoint.ValidationManager") as mock_vm_cls,
    ):
        mock_validator = mock_vm_cls.return_value
        mock_validator.validate_arguments.return_value = None
        mock_validator.validate_transport.side_effect = Exception("boom")
        with pytest.raises(SystemExit) as exc:
            run_cli()
        assert exc.value.code == 1


def test_run_cli_keyboard_interrupt(monkeypatch):
    with patch(
        "mcp_fuzzer.cli.entrypoint.parse_arguments",
        side_effect=KeyboardInterrupt,
    ):
        with pytest.raises(SystemExit) as exc:
            run_cli()
        assert exc.value.code == 0


def test_run_cli_validate_config_exits(monkeypatch):
    args = _base_args(validate_config="file.yml")
    with (
        patch("mcp_fuzzer.cli.entrypoint.parse_arguments", return_value=args),
        patch("mcp_fuzzer.cli.entrypoint.setup_logging"),
        patch("mcp_fuzzer.cli.entrypoint.ValidationManager") as mock_vm_cls,
    ):
        mock_validator = mock_vm_cls.return_value
        mock_validator.validate_arguments.return_value = None
        mock_validator.validate_config_file.return_value = None
        with pytest.raises(SystemExit) as exc:
            run_cli()
        assert exc.value.code == 0


def test_run_cli_check_env_exits(monkeypatch):
    args = _base_args(check_env=True)
    with (
        patch("mcp_fuzzer.cli.entrypoint.parse_arguments", return_value=args),
        patch("mcp_fuzzer.cli.entrypoint.setup_logging"),
        patch("mcp_fuzzer.cli.entrypoint.ValidationManager") as mock_vm_cls,
    ):
        mock_validator = mock_vm_cls.return_value
        mock_validator.validate_arguments.return_value = None
        mock_validator.check_environment_variables.return_value = True
        with pytest.raises(SystemExit) as exc:
            run_cli()
        assert exc.value.code == 0


def test_run_cli_value_error(monkeypatch):
    args = _base_args()
    with (
        patch("mcp_fuzzer.cli.entrypoint.parse_arguments", return_value=args),
        patch("mcp_fuzzer.cli.entrypoint.ValidationManager") as mock_vm_cls,
    ):
        mock_validator = mock_vm_cls.return_value
        mock_validator.validate_arguments.side_effect = ValueError("bad")
        with pytest.raises(SystemExit) as exc:
            run_cli()
        assert exc.value.code == 1


def test_run_cli_mcp_error(monkeypatch):
    args = _base_args()
    with (
        patch("mcp_fuzzer.cli.entrypoint.parse_arguments", return_value=args),
        patch("mcp_fuzzer.cli.entrypoint.ValidationManager") as mock_vm_cls,
        patch(
            "mcp_fuzzer.cli.entrypoint.run_with_retry_on_interrupt",
            side_effect=MCPError("x", code="err"),
        ),
    ):
        mock_vm_cls.return_value.validate_arguments.return_value = None
        with pytest.raises(SystemExit) as exc:
            run_cli()
        assert exc.value.code == 1


def test_run_cli_unexpected_error_debug(monkeypatch, caplog):
    args = _base_args()
    caplog.set_level(logging.DEBUG)
    with (
        patch("mcp_fuzzer.cli.entrypoint.parse_arguments", return_value=args),
        patch("mcp_fuzzer.cli.entrypoint.setup_logging"),
        patch("mcp_fuzzer.cli.entrypoint.print_startup_info"),
        patch("mcp_fuzzer.cli.entrypoint.ValidationManager") as mock_vm_cls,
    ):
        mock_validator = mock_vm_cls.return_value
        mock_validator.validate_arguments.return_value = None
        mock_validator.validate_transport.side_effect = RuntimeError("boom")
        with pytest.raises(SystemExit) as exc:
            run_cli()
        assert exc.value.code == 1


def test_build_cli_config_uses_config_file(monkeypatch):
    args = _base_args(config="custom.yml", endpoint=None)
    with patch(
        "mcp_fuzzer.cli.config_merge.config_mediator.load_file",
        return_value={
            "endpoint": "http://conf",
            "runs": 42,
            "allow_hosts": ["a.local"],
        },
    ):
        cli_config = build_cli_config(args)
    assert cli_config.merged["endpoint"] == "http://conf"
    assert cli_config.merged["runs"] == 42
    assert cli_config.merged["allow_hosts"] == ["a.local"]


def test_build_cli_config_handles_apply_config_error(caplog):
    caplog.set_level(logging.DEBUG)
    args = _base_args(config=None)
    # apply_file() now returns False instead of raising exceptions
    with patch(
        "mcp_fuzzer.cli.config_merge.config_mediator.apply_file",
        return_value=False,
    ):
        cli_config = build_cli_config(args)
    assert cli_config.merged["endpoint"] == "http://localhost"
    # Check that debug message was logged when config file is not found
    assert "Default configuration file not found" in "".join(caplog.messages)


def test_build_cli_config_raises_config_error():
    args = _base_args(config="bad.yml")
    with patch(
        "mcp_fuzzer.cli.config_merge.config_mediator.load_file",
        side_effect=ValueError("bad"),
    ):
        with pytest.raises(ConfigFileError):
            build_cli_config(args)


def test_validate_env_var_unknown_type_returns_false():
    manager = ValidationManager()

    assert manager._validate_env_var("value", None, {}) is False


def test_get_validation_error_msg_unknown_type():
    manager = ValidationManager()

    msg = manager._get_validation_error_msg("VAR", "x", None, {})
    assert "invalid value" in msg


def test_get_validation_error_msg_boolean():
    manager = ValidationManager()

    msg = manager._get_validation_error_msg(
        "FLAG", "maybe", ValidationType.BOOLEAN, {}
    )
    assert "true" in msg


def test_validate_arguments_tool_empty_raises():
    manager = ValidationManager()
    args = SimpleNamespace(
        mode="tools",
        tool=" ",
        endpoint="server",
        protocol_type=None,
        runs=None,
        runs_per_type=None,
        timeout=None,
    )

    with pytest.raises(ArgumentValidationError):
        manager.validate_arguments(args)


def test_validate_arguments_runs_per_type_invalid():
    manager = ValidationManager()
    args = SimpleNamespace(
        mode="tools",
        tool=None,
        endpoint="server",
        protocol_type=None,
        runs=None,
        runs_per_type=0,
        timeout=None,
    )

    with pytest.raises(ArgumentValidationError):
        manager.validate_arguments(args)


def test_validate_arguments_transport_retry_flags_invalid():
    manager = ValidationManager()

    bad_retries = SimpleNamespace(
        mode="tools",
        tool=None,
        endpoint="server",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=1.0,
        transport_retries=0,
        transport_retry_delay=0.0,
        transport_retry_backoff=1.0,
        transport_retry_max_delay=1.0,
        transport_retry_jitter=0.0,
    )
    with pytest.raises(ArgumentValidationError):
        manager.validate_arguments(bad_retries)

    bad_delay = SimpleNamespace(
        mode="tools",
        tool=None,
        endpoint="server",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=1.0,
        transport_retries=1,
        transport_retry_delay=-0.1,
        transport_retry_backoff=1.0,
        transport_retry_max_delay=1.0,
        transport_retry_jitter=0.0,
    )
    with pytest.raises(ArgumentValidationError):
        manager.validate_arguments(bad_delay)

    bad_backoff = SimpleNamespace(
        mode="tools",
        tool=None,
        endpoint="server",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=1.0,
        transport_retries=1,
        transport_retry_delay=0.0,
        transport_retry_backoff=0.5,
        transport_retry_max_delay=1.0,
        transport_retry_jitter=0.0,
    )
    with pytest.raises(ArgumentValidationError):
        manager.validate_arguments(bad_backoff)

    bad_max_delay = SimpleNamespace(
        mode="tools",
        tool=None,
        endpoint="server",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=1.0,
        transport_retries=1,
        transport_retry_delay=1.0,
        transport_retry_backoff=1.0,
        transport_retry_max_delay=0.5,
        transport_retry_jitter=0.0,
    )
    with pytest.raises(ArgumentValidationError):
        manager.validate_arguments(bad_max_delay)

    bad_jitter = SimpleNamespace(
        mode="tools",
        tool=None,
        endpoint="server",
        protocol_type=None,
        runs=1,
        runs_per_type=1,
        timeout=1.0,
        transport_retries=1,
        transport_retry_delay=0.0,
        transport_retry_backoff=1.0,
        transport_retry_max_delay=1.0,
        transport_retry_jitter=-0.1,
    )
    with pytest.raises(ArgumentValidationError):
        manager.validate_arguments(bad_jitter)


def test_check_environment_variables_raises_on_invalid(monkeypatch):
    manager = ValidationManager()
    manager.console = DummyConsole()

    monkeypatch.setattr(
        "mcp_fuzzer.cli.validators.ENVIRONMENT_VARIABLES",
        [
            {
                "name": "MCP_FUZZER_TIMEOUT",
                "default": "1",
                "validation_type": ValidationType.NUMERIC,
                "validation_params": {},
            }
        ],
    )
    monkeypatch.setenv("MCP_FUZZER_TIMEOUT", "not-a-number")

    with pytest.raises(ArgumentValidationError):
        manager.check_environment_variables()


def test_check_environment_variables_success(monkeypatch):
    manager = ValidationManager()
    manager.console = DummyConsole()

    monkeypatch.setattr(
        "mcp_fuzzer.cli.validators.ENVIRONMENT_VARIABLES",
        [
            {
                "name": "MCP_FUZZER_LOG_LEVEL",
                "default": "INFO",
                "validation_type": ValidationType.CHOICE,
                "validation_params": {"choices": ["INFO", "DEBUG"]},
            }
        ],
    )
    monkeypatch.setenv("MCP_FUZZER_LOG_LEVEL", "DEBUG")

    assert manager.check_environment_variables() is True
