#!/usr/bin/env python3
"""CLI entrypoint wiring the parser, config merge, and runtime execution."""

from __future__ import annotations

import logging
import sys

from rich.console import Console

from ..exceptions import ArgumentValidationError, CLIError, MCPError
from .app import run_fuzz_app
from .runtime import prepare_inner_argv, run_with_retry_on_interrupt
from ..client.safety import SafetyController
from .session_settings import SessionSettings
from .config_merge import build_cli_config
from .validators import ValidationManager
from ..logging import setup_logging
from .parser import parse_arguments
from .startup_info import print_startup_info


def _print_mcp_error(error: MCPError) -> None:
    console = Console()
    console.print(f"[bold red]Error ({error.code}):[/bold red] {error}")
    if error.context:
        console.print(f"[dim]Context: {error.context}[/dim]")


def run_cli() -> None:
    safety: SafetyController | None = None
    try:
        args = parse_arguments()
        setup_logging(args)
        validator = ValidationManager()
        if args.validate_config:
            validator.validate_config_file(args.validate_config)
            sys.exit(0)
        if args.check_env:
            if validator.check_environment_variables():
                sys.exit(0)

        cli_config = build_cli_config(args)
        config = cli_config.merged
        validator.validate_arguments(args)

        is_utility_command = (
            getattr(args, "check_env", False)
            or getattr(args, "validate_config", None) is not None
        )
        if not is_utility_command:
            from .preflight import verify_output_paths

            write_failure = verify_output_paths(
                config.get("output_dir") or "reports",
                config.get("fs_root"),
            )
            if write_failure is not None:
                raise ArgumentValidationError(write_failure.detail)

            print_startup_info(args, config)

        validator.validate_transport(args)

        session_settings = SessionSettings(config)
        safety = SafetyController()
        safety.start_if_enabled(config.get("enable_safety_system", False))

        argv = prepare_inner_argv(args)

        exit_code = run_with_retry_on_interrupt(
            args,
            lambda: run_fuzz_app(session_settings),
            argv,
            safety=safety,
        )
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
        sys.exit(0)
    except MCPError as err:
        _print_mcp_error(err)
        sys.exit(1)
    except ValueError as exc:
        error = ArgumentValidationError(str(exc))
        _print_mcp_error(error)
        sys.exit(1)
    except Exception as exc:
        error = CLIError(
            "Unexpected CLI failure",
            context={"stage": "run_cli", "details": str(exc)},
        )
        _print_mcp_error(error)
        if logging.getLogger().level <= logging.DEBUG:  # pragma: no cover
            import traceback

            Console().print(traceback.format_exc())
        sys.exit(1)
    finally:
        if safety is not None:
            try:
                safety.stop_if_started()
            except Exception:  # pragma: no cover
                pass


__all__ = ["run_cli"]
