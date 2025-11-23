#!/usr/bin/env python3
"""Utility handlers for environment/config checks."""

from __future__ import annotations

import os
import sys

import emoji
from rich.console import Console

from ..exceptions import ArgumentValidationError
from ..config import load_config_file


def handle_validate_config(path: str) -> None:
    """Validate a config file and exit."""
    load_config_file(path)
    console = Console()
    success_msg = (
        "[green]:heavy_check_mark: Configuration file "
        f"'{path}' is valid[/green]"
    )
    console.print(emoji.emojize(success_msg, language="alias"))
    sys.exit(0)


def handle_check_env() -> None:
    """Print environment variable status and exit."""
    console = Console()
    console.print("[bold]Environment variables check:[/bold]")

    env_vars = [
        ("MCP_FUZZER_TIMEOUT", "30.0"),
        ("MCP_FUZZER_LOG_LEVEL", "INFO"),
        ("MCP_FUZZER_SAFETY_ENABLED", "false"),
        ("MCP_FUZZER_FS_ROOT", "~/.mcp_fuzzer"),
        ("MCP_FUZZER_AUTO_KILL", "true"),
    ]

    all_valid = True
    for var_name, default in env_vars:
        value = os.getenv(var_name, default)
        if var_name == "MCP_FUZZER_LOG_LEVEL":
            valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            if value.upper() not in valid_levels:
                invalid_msg = (
                    f"[red]:heavy_multiplication_x: {var_name}={value} "
                    f"(must be one of: {', '.join(valid_levels)})[/red]"
                )
                console.print(emoji.emojize(invalid_msg, language="alias"))
                all_valid = False
            else:
                console.print(
                    emoji.emojize(
                        f"[green]:heavy_check_mark: {var_name}={value}[/green]",
                        language="alias",
                    )
                )
        else:
            console.print(
                emoji.emojize(
                    f"[green]:heavy_check_mark: {var_name}={value}[/green]",
                    language="alias",
                )
            )

    if all_valid:
        console.print("[green]All environment variables are valid[/green]")
        sys.exit(0)

    console.print("[red]Some environment variables have invalid values[/red]")
    raise ArgumentValidationError("Invalid environment variable values")


__all__ = ["handle_check_env", "handle_validate_config"]
