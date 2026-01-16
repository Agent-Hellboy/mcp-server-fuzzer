#!/usr/bin/env python3
"""Async runtime orchestration for the client."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from typing import Any, Awaitable, Callable

import importlib.util

from rich.console import Console

from ...client.safety.controller import SafetyController


class AsyncRunner:
    """Manages async execution with proper event loop handling and cleanup."""

    def __init__(self, args: Any, safety: SafetyController):
        self.args = args
        self.old_argv = None
        self.should_exit = False
        self.loop = None
        self._signal_notice_printed = False
        self.safety = safety

    def run(self, main_coro: Callable[[], Awaitable[object]], argv: list[str]) -> None:
        """Main execution method that orchestrates the entire async runtime."""
        self._setup_environment(argv)

        try:
            if self._is_pytest_environment():
                asyncio.run(main_coro())
                return

            self._setup_event_loop()
            self._setup_aiomonitor()
            self._setup_signal_handlers()

            try:
                self._configure_network_policy()
                self._execute_main_coroutine(main_coro)
            except asyncio.CancelledError:
                self._handle_cancellation()
            finally:
                self._cleanup_pending_tasks()

        finally:
            self._final_cleanup()

    def _setup_environment(self, argv: list[str]) -> None:
        """Setup environment variables and argv."""
        self.old_argv = sys.argv
        sys.argv = argv

    def _is_pytest_environment(self) -> bool:
        """Check if running in pytest environment."""
        return os.environ.get("PYTEST_CURRENT_TEST") is not None

    def _setup_event_loop(self) -> None:
        """Create and setup the event loop."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def _setup_aiomonitor(self) -> None:
        """Setup AIOMonitor if enabled."""
        enable_aiomonitor = getattr(self.args, "enable_aiomonitor", False)
        if enable_aiomonitor:
            spec = importlib.util.find_spec("aiomonitor")
            if spec:
                print("AIOMonitor enabled! Connect with: telnet localhost 20101")
                print("Try commands: ps, where <task_id>, console, monitor")
                print("=" * 60)
            else:
                print(
                    "AIOMonitor requested but not installed. "
                    "Install with: pip install aiomonitor"
                )
                self.args.enable_aiomonitor = False

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        should_retry_with_safety = getattr(
            self.args, "retry_with_safety_on_interrupt", False
        )
        if not should_retry_with_safety:
            try:
                self.loop.add_signal_handler(signal.SIGINT, self._cancel_all_tasks)
                self.loop.add_signal_handler(signal.SIGTERM, self._cancel_all_tasks)
                self.loop.add_signal_handler(signal.SIGQUIT, self._cancel_all_tasks)
            except NotImplementedError:
                pass

    def _cancel_all_tasks(self) -> None:
        """Cancel all running tasks gracefully."""
        if not self._signal_notice_printed:
            try:
                Console().print(
                    "\n[yellow]Received Ctrl+C from user; stopping now[/yellow]"
                )
            except Exception:
                pass
            self._signal_notice_printed = True
        for task in asyncio.all_tasks(self.loop):
            task.cancel()

    def _configure_network_policy(self) -> None:
        """Configure network safety policies."""
        deny = True if getattr(self.args, "no_network", False) else None
        extra = getattr(self.args, "allow_hosts", None)

        # Reset allowed hosts before applying the desired policy in one call to
        # avoid intermediate state changes.
        self.safety.configure_network_policy(
            reset_allowed_hosts=True,
            deny_network_by_default=deny,
            extra_allowed_hosts=extra,
        )

    def _execute_main_coroutine(
        self, main_coro: Callable[[], Awaitable[object]]
    ) -> None:
        """Execute the main coroutine with optional monitoring."""
        enable_aiomonitor = getattr(self.args, "enable_aiomonitor", False)

        if enable_aiomonitor:
            import aiomonitor

            with aiomonitor.start_monitor(
                self.loop,
                console_enabled=True,
                locals=True,
            ):
                self.loop.run_until_complete(main_coro())
        else:
            self.loop.run_until_complete(main_coro())

    def _handle_cancellation(self) -> None:
        """Handle cancellation from signal interruption."""
        Console().print("\n[yellow]Fuzzing interrupted by user[/yellow]")
        self.should_exit = True

    def _cleanup_pending_tasks(self) -> None:
        """Clean up any pending tasks."""
        try:
            pending = [t for t in asyncio.all_tasks(self.loop) if not t.done()]
            for t in pending:
                t.cancel()
            if pending:
                gathered = asyncio.gather(*pending, return_exceptions=True)
                try:
                    self.loop.run_until_complete(
                        asyncio.wait_for(gathered, timeout=2.0)
                    )
                except asyncio.TimeoutError:
                    for t in pending:
                        if not t.done():
                            t.cancel()
        except Exception:
            pass

    def _final_cleanup(self) -> None:
        """Final cleanup and resource restoration."""
        if self.loop:
            self.loop.close()
        sys.argv = self.old_argv
        if self.should_exit:
            raise SystemExit(130)


def execute_inner_client(args: Any, unified_client_main, argv: list[str]) -> None:
    """Simple wrapper that creates a runner and executes."""
    safety = SafetyController()
    runner = AsyncRunner(args, safety)
    runner.run(unified_client_main, argv)


__all__ = ["AsyncRunner", "execute_inner_client"]
