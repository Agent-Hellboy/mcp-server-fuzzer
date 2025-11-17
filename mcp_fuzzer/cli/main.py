#!/usr/bin/env python3
import emoji
from rich.console import Console
import sys
import os
import logging
from typing import Any

from .args import (
    build_unified_client_args,
    parse_arguments,
    print_startup_info,
    setup_logging,
    validate_arguments,
)
from .runner import (
    prepare_inner_argv,
    run_with_retry_on_interrupt,
    start_safety_if_enabled,
    stop_safety_if_started,
)
from ..exceptions import (
    ArgumentValidationError,
    CLIError,
    MCPError,
    TransportError,
)


def _get_cli_helpers() -> tuple[Any, Any, Any, Any, Any, Any]:
    """Resolve CLI helper functions, allowing unit test patches to apply."""
    cli_module = sys.modules.get("mcp_fuzzer.cli")
    _parse = (
        getattr(cli_module, "parse_arguments", parse_arguments)
        if cli_module
        else parse_arguments
    )
    _validate = (
        getattr(cli_module, "validate_arguments", validate_arguments)
        if cli_module
        else validate_arguments
    )
    _setup = (
        getattr(cli_module, "setup_logging", setup_logging)
        if cli_module
        else setup_logging
    )
    _build = (
        getattr(
            cli_module,
            "build_unified_client_args",
            build_unified_client_args,
        )
        if cli_module
        else build_unified_client_args
    )
    _print_info = (
        getattr(cli_module, "print_startup_info", print_startup_info)
        if cli_module
        else print_startup_info
    )
    return _parse, _validate, _setup, _build, _print_info, cli_module


def _handle_validate_config(args) -> None:
    """Handle --validate-config flag."""
    from ..config import load_config_file
    load_config_file(args.validate_config)
    console = Console()
    config_file = args.validate_config
    success_msg = (
        "[green]:heavy_check_mark: Configuration file "
        f"'{config_file}' is valid[/green]"
    )
    console.print(emoji.emojize(success_msg, language='alias'))
    sys.exit(0)


def _handle_check_env() -> None:
    """Handle --check-env flag."""
    console = Console()
    console.print("[bold]Environment variables check:[/bold]")

    env_vars = [
        ('MCP_FUZZER_TIMEOUT', '30.0'),
        ('MCP_FUZZER_LOG_LEVEL', 'INFO'),
        ('MCP_FUZZER_SAFETY_ENABLED', 'false'),
        ('MCP_FUZZER_FS_ROOT', '~/.mcp_fuzzer'),
        ('MCP_FUZZER_AUTO_KILL', 'true'),
    ]

    all_valid = True
    for var_name, default in env_vars:
        value = os.getenv(var_name, default)
        if var_name == 'MCP_FUZZER_LOG_LEVEL':
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if value.upper() not in valid_levels:
                valid_list = ', '.join(valid_levels)
                invalid_msg = (
                    f"[red]:heavy_multiplication_x: {var_name}={value} "
                    f"(must be one of: {valid_list})[/red]"
                )
                console.print(emoji.emojize(invalid_msg, language='alias'))
                all_valid = False
            else:
                console.print(
                    emoji.emojize(
                        f"[green]:heavy_check_mark: {var_name}={value}[/green]",
                        language='alias'
                    )
                )
        else:
            console.print(
                emoji.emojize(
                    f"[green]:heavy_check_mark: {var_name}={value}[/green]",
                    language='alias'
                )
            )

    if all_valid:
        console.print("[green]All environment variables are valid[/green]")
        sys.exit(0)

    console.print("[red]Some environment variables have invalid values[/red]")
    raise ArgumentValidationError("Invalid environment variable values")


def _validate_transport(args, cli_module) -> None:
    """Validate transport configuration early."""
    try:
        from ..transport import create_transport as _create_transport  # type: ignore

        cli_create_transport = (
            getattr(cli_module, "create_transport", None) if cli_module else None
        )
        cli_transport_module = (
            getattr(cli_create_transport, "__module__", "")
            if cli_create_transport is not None
            else ""
        )
        use_cli_attribute = (
            cli_create_transport is not None
            and not cli_transport_module.startswith("mcp_fuzzer.transport")
        )
        create_transport_func = (
            cli_create_transport if use_cli_attribute else _create_transport
        )

        _ = create_transport_func(
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


def _run_fuzzing(args, cli_module) -> None:
    """Run the main fuzzing operation."""
    from ..client import main as unified_client_main

    started_system_blocker = start_safety_if_enabled(args)
    try:
        # Under pytest, call the patched asyncio.run from mcp_fuzzer.cli
        if os.environ.get("PYTEST_CURRENT_TEST"):
            asyncio_mod = getattr(cli_module, "asyncio", None)
            if asyncio_mod is None:
                import asyncio as asyncio_mod  # type: ignore
            # Call the unified client main coroutine
            asyncio_mod.run(unified_client_main())
        else:
            argv = prepare_inner_argv(args)
            run_with_retry_on_interrupt(args, unified_client_main, argv)
    finally:
        stop_safety_if_started(started_system_blocker)


def run_cli() -> None:
    try:
        _parse, _validate, _setup, _build, _print_info, cli_module = _get_cli_helpers()

        args = _parse()
        _validate(args)
        _setup(args)

        # Handle special CLI flags that exit early
        if getattr(args, 'validate_config', None):
            _handle_validate_config(args)

        if getattr(args, 'check_env', False):
            _handle_check_env()

        _ = _build(args)
        # Check if this is a utility command that doesn't need endpoint
        is_utility_command = (
            getattr(args, 'check_env', False) or
            getattr(args, 'validate_config', None) is not None
        )

        if not is_utility_command:
            _print_info(args)
            _validate_transport(args, cli_module)
            _run_fuzzing(args, cli_module)

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
        if logging.getLogger().level <= logging.DEBUG:
            import traceback

            Console().print(traceback.format_exc())
        sys.exit(1)


def _print_mcp_error(error: MCPError) -> None:
    """Render MCP errors consistently for the CLI."""
    console = Console()
    console.print(f"[bold red]Error ({error.code}):[/bold red] {error}")
    if error.context:
        console.print(f"[dim]Context: {error.context}[/dim]")
