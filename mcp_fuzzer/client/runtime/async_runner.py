#!/usr/bin/env python3
"""Async runtime orchestration for the client."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from typing import Any, Callable, Awaitable

from rich.console import Console

from ...safety_system.policy import configure_network_policy


class AsyncRunner:
    """Simple wrapper to run the unified client inside a managed event loop."""

    def __init__(self, args: Any):
        self.args = args

    def run(self, main_coro: Callable[[], Awaitable[object]], argv: list[str]) -> None:
        execute_inner_client(self.args, main_coro, argv)


def execute_inner_client(args: Any, unified_client_main, argv: list[str]) -> None:
    old_argv = sys.argv
    sys.argv = argv
    should_exit = False
    try:
        if os.environ.get("PYTEST_CURRENT_TEST"):
            asyncio.run(unified_client_main())
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        enable_aiomonitor = getattr(args, "enable_aiomonitor", False)
        if enable_aiomonitor:  # pragma: no cover
            try:
                import aiomonitor  # type: ignore
                print("AIOMonitor enabled! Connect with: telnet localhost 20101")
                print("Try commands: ps, where <task_id>, console, monitor")
                print("=" * 60)
            except ImportError:
                print(
                    "AIOMonitor requested but not installed. "
                    "Install with: pip install aiomonitor"
                )
                enable_aiomonitor = False

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

        if not getattr(args, "retry_with_safety_on_interrupt", False):  # pragma: no cover
            try:
                loop.add_signal_handler(signal.SIGINT, _cancel_all_tasks)
                loop.add_signal_handler(signal.SIGTERM, _cancel_all_tasks)
            except NotImplementedError:
                pass
        try:
            deny = True if getattr(args, "no_network", False) else None
            extra = getattr(args, "allow_hosts", None)
            configure_network_policy(reset_allowed_hosts=True, deny_network_by_default=None)
            configure_network_policy(deny_network_by_default=deny, extra_allowed_hosts=extra)

            if enable_aiomonitor:
                import aiomonitor  # type: ignore

                with aiomonitor.start_monitor(
                    loop,
                    console_enabled=True,
                    locals=True,
                ):
                    loop.run_until_complete(unified_client_main())
            else:
                loop.run_until_complete(unified_client_main())
        except asyncio.CancelledError:  # pragma: no cover
            Console().print("\n[yellow]Fuzzing interrupted by user[/yellow]")
            should_exit = True
        finally:
            try:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]  # pragma: no cover
                for t in pending:
                    t.cancel()
                if pending:
                    gathered = asyncio.gather(*pending, return_exceptions=True)
                    try:
                        loop.run_until_complete(asyncio.wait_for(gathered, timeout=2.0))
                    except asyncio.TimeoutError:  # pragma: no cover
                        for t in pending:
                            if not t.done():
                                t.cancel()
            except Exception:  # pragma: no cover
                pass
            loop.close()
    finally:
        sys.argv = old_argv
        if should_exit:  # pragma: no cover
            raise SystemExit(130)


__all__ = ["AsyncRunner", "execute_inner_client"]
