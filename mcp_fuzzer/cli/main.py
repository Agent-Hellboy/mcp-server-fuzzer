#!/usr/bin/env python3
"""Clean CLI entry point using SOLID principles."""

import logging
import sys
from typing import Any

from rich.console import Console

from .args import parse_arguments, validate_arguments, get_cli_config
from .commands import get_cli_commands, get_execution_strategies
from ..exceptions import ArgumentValidationError, CLIError, MCPError


def _execute_command(commands, args) -> None:
    """Execute the first command that can handle the arguments."""
    for command in commands:
        if command.can_handle(args):
            command.execute(args)
            return

    # No command handled the arguments, this is a fuzzing operation
    raise ValueError("No command found for arguments")


def _execute_fuzzing_operation(strategies, args, config: dict[str, Any]) -> int:
    """Execute fuzzing using the appropriate strategy."""
    for strategy in strategies:
        if strategy.can_handle(args):
            return strategy.execute(args, config)

    raise ValueError("No execution strategy found for arguments")


def run_cli() -> None:
    """Clean CLI entry point using SOLID principles and Command Pattern."""
    try:
        # Parse and validate arguments
        args = parse_arguments()
        validate_arguments(args)

        # Get available commands and strategies
        commands = get_cli_commands()
        strategies = get_execution_strategies()

        # Try to execute a utility command first
        try:
            _execute_command(commands, args)
            # If we reach here, a command was executed and exited
            return
        except ValueError:
            # No command handled it, proceed with fuzzing
            pass

        # Load configuration for fuzzing operations
        config = get_cli_config()

        # Execute fuzzing operation
        exit_code = _execute_fuzzing_operation(strategies, args, config)
        sys.exit(exit_code)

    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user")
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
