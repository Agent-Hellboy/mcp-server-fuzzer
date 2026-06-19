#!/usr/bin/env python3
"""Retry helper around the async runner."""

from __future__ import annotations

from typing import Any, Callable

from rich.console import Console

from ...client.safety import SafetyController
from ...safety_system import start_system_blocking, stop_system_blocking
from ..exit_codes import INTERRUPTED
from .async_runner import execute_inner_client


def run_with_retry_on_interrupt(
    args: Any,
    unified_client_main: Callable,
    argv: list[str],
    *,
    safety: SafetyController | None = None,
) -> int:
    """Execute the client, retrying once with safety after interrupt when configured."""
    try:
        return execute_inner_client(
            args, unified_client_main, argv, safety=safety
        )
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
            except Exception:  # pragma: no cover
                pass
            try:
                return execute_inner_client(
                    args, unified_client_main, argv, safety=safety
                )
            finally:
                if started:
                    stop_system_blocking()
        else:
            console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
            return INTERRUPTED


__all__ = ["run_with_retry_on_interrupt"]
