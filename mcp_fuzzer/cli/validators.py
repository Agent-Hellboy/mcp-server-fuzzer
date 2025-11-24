#!/usr/bin/env python3
"""Unified validation system for CLI arguments and environment checks."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

import emoji
from rich.console import Console

from ..exceptions import ArgumentValidationError
from ..config import load_config_file
from ..transport.factory import create_transport
from ..exceptions import MCPError, TransportError


class ValidationManager:
    """Unified validation system for CLI arguments and environment checks."""

    def __init__(self):
        self.console = Console()

    def validate_arguments(self, args: argparse.Namespace) -> None:
        """Validate CLI arguments for fuzzing operations."""
        is_utility_command = getattr(args, "check_env", False) or getattr(
            args, "validate_config", None
        ) is not None

        if not is_utility_command and not getattr(args, "endpoint", None):
            raise ArgumentValidationError(
                "--endpoint is required for fuzzing operations"
            )

        if args.mode == "protocol" and not args.protocol_type:
            pass

        if args.protocol_type and args.mode != "protocol":
            raise ArgumentValidationError(
                "--protocol-type can only be used with --mode protocol"
            )

        if args.mode == "tool" and not getattr(args, "tool", None):
            raise ArgumentValidationError("--tool is required when --mode tool")

        if hasattr(args, "runs") and args.runs is not None:
            if not isinstance(args.runs, int) or args.runs < 1:
                raise ArgumentValidationError("--runs must be at least 1")

        if hasattr(args, "runs_per_type") and args.runs_per_type is not None:
            if not isinstance(args.runs_per_type, int) or args.runs_per_type < 1:
                raise ArgumentValidationError("--runs-per-type must be at least 1")

        if hasattr(args, "timeout") and args.timeout is not None:
            if not isinstance(args.timeout, (int, float)) or args.timeout <= 0:
                raise ArgumentValidationError("--timeout must be positive")

        if hasattr(args, "endpoint") and args.endpoint is not None:
            if not args.endpoint.strip():
                raise ArgumentValidationError("--endpoint cannot be empty")

    def validate_config_file(self, path: str) -> None:
        """Validate a config file and exit with success message."""
        load_config_file(path)
        success_msg = (
            "[green]:heavy_check_mark: Configuration file "
            f"'{path}' is valid[/green]"
        )
        self.console.print(emoji.emojize(success_msg, language="alias"))
        sys.exit(0)


    def check_environment_variables(self) -> None:
        """Print environment variable status and exit."""
        self.console.print("[bold]Environment variables check:[/bold]")

        from ..env import ENVIRONMENT_VARIABLES

        all_valid = True
        for env_var in ENVIRONMENT_VARIABLES:
            name = env_var["name"]
            default = env_var["default"]
            validation_type = env_var["validation_type"]
            validation_params = env_var["validation_params"]

            value = os.getenv(name, default)
            is_valid = self._validate_env_var(value, validation_type, validation_params)

            if is_valid:
                self.console.print(
                    emoji.emojize(
                        f"[green]:heavy_check_mark: {name}={value}[/green]",
                        language="alias",
                    )
                )
            else:
                error_msg = self._get_validation_error_msg(
                    name, value, validation_type, validation_params
                )
                self.console.print(emoji.emojize(error_msg, language="alias"))
                all_valid = False

        if all_valid:
            self.console.print("[green]All environment variables are valid[/green]")
            sys.exit(0)

        self.console.print("[red]Some environment variables have invalid values[/red]")
        raise ArgumentValidationError("Invalid environment variable values")

    def _validate_env_var(
        self, value: str, validation_type: str, params: dict
    ) -> bool:
        """Validate a single environment variable."""
        if validation_type == "choice":
            return value.upper() in [c.upper() for c in params.get("choices", [])]
        elif validation_type == "boolean":
            return value.lower() in ["true", "false"]
        elif validation_type == "numeric":
            try:
                float(value)
                return True
            except ValueError:
                return False
        if validation_type == "string":
            return True
        return False

    def _get_validation_error_msg(
        self, name: str, value: str, validation_type: str, params: dict
    ) -> str:
        """Generate validation error message."""
        if validation_type == "choice":
            choices = params.get("choices", [])
            choices_str = ", ".join(choices)
            return (
                "[red]:heavy_multiplication_x: "
                f"{name}={value} (must be one of: {choices_str})[/red]"
            )
        if validation_type == "boolean":
            return (
                "[red]:heavy_multiplication_x: "
                f"{name}={value} (must be 'true' or 'false')[/red]"
            )
        if validation_type == "numeric":
            return (
                "[red]:heavy_multiplication_x: "
                f"{name}={value} (must be numeric)[/red]"
            )
        return (
            "[red]:heavy_multiplication_x: "
            f"{name}={value} (invalid value)[/red]"
        )

    def validate_transport(self, args: Any) -> None:
        try:
            _ = create_transport(
                args.protocol,
                args.endpoint,
                timeout=args.timeout,
            )
        except MCPError:
            raise
        except Exception as transport_error:
            raise TransportError(
                "Failed to initialize transport",
                context={"protocol": args.protocol, "endpoint": args.endpoint},
            ) from transport_error


__all__ = ["ValidationManager"]
