#!/usr/bin/env python3
"""CLI Command implementations using Command Pattern."""

import os
import sys
from typing import Any

import emoji
from rich.console import Console

from .interfaces import CLICommand
from ..exceptions import ArgumentValidationError


class ValidateConfigCommand:
    """Command for validating configuration files."""

    def can_handle(self, args) -> bool:
        """Check if this command handles --validate-config."""
        return getattr(args, 'validate_config', None) is not None

    def execute(self, args) -> None:
        """Validate configuration file and exit."""
        from ..config import (
            load_config_file,
            normalize_config_data,
            validate_config_data,
        )

        config_file = args.validate_config
        try:
            raw = load_config_file(config_file)
            normalized = normalize_config_data(raw)
            validate_config_data(normalized)

            console = Console()
            success_msg = (
                "[green]:heavy_check_mark: Configuration file "
                f"'{config_file}' is valid[/green]"
            )
            console.print(emoji.emojize(success_msg, language='alias'))
            sys.exit(0)

        except Exception as e:
            console = Console()
            error_msg = (
                f"[red]:heavy_multiplication_x: Configuration file "
                f"'{config_file}' is invalid: {e}[/red]"
            )
            console.print(emoji.emojize(error_msg, language='alias'))
            sys.exit(1)


class CheckEnvironmentCommand:
    """Command for checking environment variables."""

    def can_handle(self, args) -> bool:
        """Check if this command handles --check-env."""
        return getattr(args, 'check_env', False)

    def execute(self, args) -> None:
        """Check environment variables and exit."""
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


class FuzzingExecutionStrategy:
    """Strategy for executing fuzzing operations."""

    def can_handle(self, args) -> bool:
        """Check if this handles fuzzing operations (not utility commands)."""
        # This handles all non-utility operations
        return not (
            getattr(args, 'validate_config', None) is not None or
            getattr(args, 'check_env', False)
        )

    def execute(self, args, config: dict[str, Any]) -> int:
        """Execute fuzzing operation using clean client architecture."""
        import asyncio
        from .args import print_startup_info
        from ..client import main as client_main

        # Print startup info
        print_startup_info(args)

        # Execute client with proper async handling
        try:
            # Check if running under pytest
            if os.environ.get("PYTEST_CURRENT_TEST"):
                asyncio.run(client_main())
            else:
                asyncio.run(client_main())
            return 0
        except KeyboardInterrupt:
            print("\nFuzzing interrupted by user")
            return 0
        except Exception as e:
            print(f"Fuzzing failed: {e}")
            return 1


def get_cli_commands() -> list[CLICommand]:
    """Get all available CLI commands."""
    return [
        ValidateConfigCommand(),
        CheckEnvironmentCommand(),
    ]


def get_execution_strategies() -> list:
    """Get all available execution strategies."""
    return [
        FuzzingExecutionStrategy(),
    ]
