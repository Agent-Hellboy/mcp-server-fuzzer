#!/usr/bin/env python3
"""User-facing startup output for the CLI."""

from __future__ import annotations

import argparse

from rich.console import Console


def print_startup_info(args: argparse.Namespace) -> None:
    console = Console()
    console.print(f"[bold blue]MCP Fuzzer - {args.mode.upper()} Mode[/bold blue]")
    console.print(f"Protocol: {args.protocol.upper()}")
    console.print(f"Endpoint: {args.endpoint}")


__all__ = ["print_startup_info"]
