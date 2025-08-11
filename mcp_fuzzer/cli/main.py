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
        _build = (
            getattr(cli_module, "build_unified_client_args", build_unified_client_args)
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
