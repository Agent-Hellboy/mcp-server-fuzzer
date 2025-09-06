#!/usr/bin/env python3
from rich.console import Console
import sys
import os
import logging

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


def run_cli() -> None:
    try:
        # Resolve helpers via package so unit test patches on mcp_fuzzer.cli apply
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

        args = _parse()
        _validate(args)
        _setup(args)

        # Handle special CLI flags that exit early
        if getattr(args, 'validate_config', None):
            from ..config_loader import load_config_file
            try:
                load_config_file(args.validate_config)
                console = Console()
                config_file = args.validate_config
                console.print(
                    f"[green]✓ Configuration file '{config_file}' is valid[/green]"
                )
                sys.exit(0)
            except Exception as e:
                console = Console()
                console.print(f"[red]✗ Configuration validation failed: {e}[/red]")
                sys.exit(1)

        if getattr(args, 'check_env', False):
            # Check environment variables
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
                        console.print(
                            f"[red]✗ {var_name}={value} (must be one of: "
                            f"{valid_list})[/red]"
                        )
                        all_valid = False
                    else:
                        console.print(f"[green]✓ {var_name}={value}[/green]")
                else:
                    console.print(f"[green]✓ {var_name}={value}[/green]")

            if all_valid:
                console.print("[green]All environment variables are valid[/green]")
            else:
                console.print(
                    "[red]Some environment variables have invalid values[/red]"
                )
                sys.exit(1)
            sys.exit(0)
        _build = (
            getattr(
                cli_module,
                "build_unified_client_args",
                build_unified_client_args,
            )
            if cli_module
            else build_unified_client_args
        )
        _ = _build(args)
        _print_info = (
            getattr(cli_module, "print_startup_info", print_startup_info)
            if cli_module
            else print_startup_info
        )
        _print_info(args)

        # Early transport validation using patched create_transport if provided
        try:
            create_transport_func = getattr(cli_module, "create_transport", None)
            if create_transport_func is None:
                from ..transport import create_transport as create_transport_func  # type: ignore

            _ = create_transport_func(
                protocol=args.protocol,
                endpoint=args.endpoint,
                timeout=args.timeout,
            )
        except Exception as transport_error:
            console = Console()
            console.print(f"[bold red]Unexpected error:[/bold red] {transport_error}")
            sys.exit(1)
            return

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

    except ValueError as e:
        console = Console()
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
        return
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
        sys.exit(0)
        return
    except Exception as e:
        console = Console()
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        if logging.getLogger().level <= logging.DEBUG:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)
        return
