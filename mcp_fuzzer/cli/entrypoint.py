#!/usr/bin/env python3
"""CLI entrypoint wiring the parser, config merge, and runtime execution."""

from __future__ import annotations

import logging
import sys
from typing import Any, Callable

from rich.console import Console

from ..exceptions import (
    ArgumentValidationError,
    CLIError,
    MCPError,
    TransportError,
)
from ..transport.factory import create_transport
from ..client.main import unified_client_main
from ..client.runtime import prepare_inner_argv, run_with_retry_on_interrupt
from ..client.safety import SafetyController
from ..client.settings import ClientSettings
from .auth_resolver import resolve_auth_manager
from .config_merge import build_cli_config
from .env_tools import handle_check_env, handle_validate_config
from .logging_setup import setup_logging
from .parser import parse_arguments
from .startup_info import print_startup_info
from .validators import validate_arguments


def _print_mcp_error(error: MCPError) -> None:
    console = Console()
    console.print(f"[bold red]Error ({error.code}):[/bold red] {error}")
    if error.context:
        console.print(f"[dim]Context: {error.context}[/dim]")


def _validate_transport(args: Any) -> None:
    try:
        _ = create_transport(
            args.protocol,
            args.endpoint,
            timeout=args.timeout,
        )
    except MCPError:
        raise
    except Exception as transport_error:
        raise TransportError(
            "Failed to initialize transport",
            context={"protocol": args.protocol, "endpoint": args.endpoint},
        ) from transport_error


def run_cli() -> None:
    safety: SafetyController | None = None
    try:
        args = parse_arguments()
        validate_arguments(args)
        setup_logging(args)

        if getattr(args, "validate_config", None):
            handle_validate_config(args.validate_config)

        if getattr(args, "check_env", False):
            handle_check_env()

        cli_config = build_cli_config(args)
        config = cli_config.merged

        is_utility_command = config.get("check_env") or config.get("validate_config")
        if not is_utility_command:
            print_startup_info(args)
            _validate_transport(args)

        client_settings = ClientSettings(config)
        safety = SafetyController()
        safety.start_if_enabled(config.get("enable_safety_system", False))

        argv = prepare_inner_argv(args)

        def _main_callable() -> Any:
            return unified_client_main(client_settings)

        run_with_retry_on_interrupt(args, _main_callable, argv)
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
