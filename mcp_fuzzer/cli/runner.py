#!/usr/bin/env python3
import asyncio
import os
import signal
import sys
from typing import Any, Dict, List

from rich.console import Console

from ..transport import create_transport
from ..safety_system import start_system_blocking, stop_system_blocking


def create_transport_with_auth(args, client_args: Dict[str, Any]):
    try:
        auth_headers = None
        if client_args.get("auth_manager"):
            auth_headers = client_args["auth_manager"].get_auth_headers_for_tool("")

        factory_kwargs = {"timeout": args.timeout}
        if args.protocol == "http" and auth_headers:
            factory_kwargs["auth_headers"] = auth_headers

        transport = create_transport(
            protocol=args.protocol,
            endpoint=args.endpoint,
            **factory_kwargs,
        )
        return transport
    except Exception as transport_error:
        console = Console()
        console.print(f"[bold red]Unexpected error:[/bold red] {transport_error}")
        sys.exit(1)


def prepare_inner_argv(args) -> List[str]:
    argv: List[str] = [sys.argv[0]]
    mode = args.mode
    argv += ["--mode", mode]
    argv += ["--protocol", args.protocol]
    argv += ["--endpoint", args.endpoint]
    if args.runs is not None:
        argv += ["--runs", str(args.runs)]
    if args.runs_per_type is not None:
        argv += ["--runs-per-type", str(args.runs_per_type)]
    if args.timeout is not None:
        argv += ["--timeout", str(args.timeout)]
    if getattr(args, "tool_timeout", None) is not None:
        argv += ["--tool-timeout", str(args.tool_timeout)]
    if args.protocol_type:
        argv += ["--protocol-type", args.protocol_type]
    if args.verbose:
        argv += ["--verbose"]
    return argv


def start_safety_if_enabled(args) -> bool:
    if getattr(args, "enable_safety_system", False):
        start_system_blocking()
        return True
    return False


def stop_safety_if_started(started: bool) -> None:
    if started:
        try:
            stop_system_blocking()
        except Exception:
            pass


def execute_inner_client(args, unified_client_main, argv):
    old_argv = sys.argv
    sys.argv = argv
    should_exit = False
    try:
        if os.environ.get("PYTEST_CURRENT_TEST"):
            asyncio.run(unified_client_main())
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Print an immediate notice on first SIGINT/SIGTERM, then cancel tasks
        _signal_notice = {"printed": False}

        def _cancel_all_tasks():  # pragma: no cover
            if not _signal_notice["printed"]:
                try:
                    Console().print(
                        "\n[yellow]Received Ctrl+C from user; stopping now[/yellow]"
                    )
                except Exception:
                    pass
                _signal_notice["printed"] = True
            for task in asyncio.all_tasks(loop):
                task.cancel()

        if not getattr(args, "retry_with_safety_on_interrupt", False):
            try:
                loop.add_signal_handler(signal.SIGINT, _cancel_all_tasks)
                loop.add_signal_handler(signal.SIGTERM, _cancel_all_tasks)
            except NotImplementedError:
                pass
        try:
            loop.run_until_complete(unified_client_main())
        except asyncio.CancelledError:
            Console().print("\n[yellow]Fuzzing interrupted by user[/yellow]")
            should_exit = True
        finally:
            try:
                # Cancel all remaining tasks more aggressively
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for t in pending:
                    t.cancel()

                # Wait for cancellation with a short timeout
                if pending:
                    gathered = asyncio.gather(*pending, return_exceptions=True)
                    try:
                        loop.run_until_complete(asyncio.wait_for(gathered, timeout=2.0))
                    except asyncio.TimeoutError:
                        # Force kill any remaining tasks
                        for t in pending:
                            if not t.done():
                                t.cancel()
            except Exception:
                pass
            loop.close()
    finally:
        sys.argv = old_argv
        if should_exit:
            raise SystemExit(130)


def run_with_retry_on_interrupt(args, unified_client_main, argv) -> None:
    try:
        execute_inner_client(args, unified_client_main, argv)
    except KeyboardInterrupt:
        console = Console()
        if (not getattr(args, "enable_safety_system", False)) and getattr(
            args, "retry_with_safety_on_interrupt", False
        ):
            console.print(
                "\n[yellow]Interrupted. Retrying once with safety system "
                "enabled...[/yellow]"
            )
            started = False
            try:
                start_system_blocking()
                started = True
            except Exception:
                pass
            try:
                execute_inner_client(args, unified_client_main, argv)
            finally:
                stop_safety_if_started(started)
        else:
            console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
            sys.exit(130)
