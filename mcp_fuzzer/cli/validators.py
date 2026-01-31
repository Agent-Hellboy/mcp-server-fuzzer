#!/usr/bin/env python3
"""Unified validation system for CLI arguments and environment checks."""

from __future__ import annotations

import argparse
import os
from typing import Any

import emoji
from rich.console import Console

from ..exceptions import ArgumentValidationError
from ..client.adapters import config_mediator
from ..transport.catalog import build_driver
from ..exceptions import MCPError, TransportError
from ..env import ENVIRONMENT_VARIABLES, ValidationType


class ValidationManager:
    """Unified validation system for CLI arguments and environment checks."""

    def __init__(self):
        self.console = Console()

    def validate_arguments(self, args: argparse.Namespace) -> None:
        """Validate CLI arguments for fuzzing operations."""
        is_utility_command = (
            getattr(args, "check_env", False)
            or getattr(args, "validate_config", None) is not None
        )

        if not is_utility_command and not getattr(args, "endpoint", None):
            raise ArgumentValidationError(
                "--endpoint is required for fuzzing operations"
            )

        if args.mode == "protocol" and not args.protocol_type:
            raise ArgumentValidationError(
                "--protocol-type is required when --mode protocol"
            )

        if args.protocol_type and args.mode != "protocol":
            raise ArgumentValidationError(
                "--protocol-type can only be used with --mode protocol"
            )

        if args.mode == "tools" and getattr(args, "tool", None):
            if not args.tool.strip():
                raise ArgumentValidationError("--tool cannot be empty")

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

        if hasattr(args, "transport_retries") and args.transport_retries is not None:
            if (
                not isinstance(args.transport_retries, int)
                or args.transport_retries < 1
            ):
                raise ArgumentValidationError(
                    "--transport-retries must be at least 1"
                )

        if (
            hasattr(args, "transport_retry_delay")
            and args.transport_retry_delay is not None
        ):
            if (
                not isinstance(args.transport_retry_delay, (int, float))
                or args.transport_retry_delay < 0
            ):
                raise ArgumentValidationError(
                    "--transport-retry-delay must be >= 0"
                )

        if (
            hasattr(args, "transport_retry_backoff")
            and args.transport_retry_backoff is not None
        ):
            if (
                not isinstance(args.transport_retry_backoff, (int, float))
                or args.transport_retry_backoff < 1
            ):
                raise ArgumentValidationError(
                    "--transport-retry-backoff must be >= 1"
                )

        if (
            hasattr(args, "transport_retry_max_delay")
            and args.transport_retry_max_delay is not None
        ):
            if (
                not isinstance(args.transport_retry_max_delay, (int, float))
                or args.transport_retry_max_delay < 0
            ):
                raise ArgumentValidationError(
                    "--transport-retry-max-delay must be >= 0"
                )

        if (
            hasattr(args, "transport_retry_max_delay")
            and args.transport_retry_max_delay is not None
            and hasattr(args, "transport_retry_delay")
            and args.transport_retry_delay is not None
        ):
            if args.transport_retry_max_delay < args.transport_retry_delay:
                raise ArgumentValidationError(
                    "--transport-retry-max-delay must be >= --transport-retry-delay"
                )

        if (
            hasattr(args, "transport_retry_jitter")
            and args.transport_retry_jitter is not None
        ):
            if (
                not isinstance(args.transport_retry_jitter, (int, float))
                or args.transport_retry_jitter < 0
            ):
                raise ArgumentValidationError(
                    "--transport-retry-jitter must be >= 0"
                )

    def validate_config_file(self, path: str) -> None:
        """Validate a config file and print success message."""
        config_mediator.load_file(path)
        success_msg = (
            f"[green]:heavy_check_mark: Configuration file '{path}' is valid[/green]"
        )
        self.console.print(emoji.emojize(success_msg, language="alias"))

    def check_environment_variables(self) -> bool:
        """Print environment variable status and return validation result."""
        self.console.print("[bold]Environment variables check:[/bold]")

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
            return True

        self.console.print("[red]Some environment variables have invalid values[/red]")
        raise ArgumentValidationError("Invalid environment variable values")

    def _validate_env_var(
        self, value: str, validation_type: ValidationType, params: dict
    ) -> bool:
        """Validate a single environment variable."""
        if validation_type == ValidationType.CHOICE:
            return value.upper() in [c.upper() for c in params.get("choices", [])]
        elif validation_type == ValidationType.BOOLEAN:
            return value.lower() in [
                "true",
                "false",
                "1",
                "0",
                "yes",
                "no",
                "on",
                "off",
            ]
        elif validation_type == ValidationType.NUMERIC:
            try:
                float(value)
                return True
            except ValueError:
                return False
        elif validation_type == ValidationType.STRING:
            return True
        return False

    def _get_validation_error_msg(
        self, name: str, value: str, validation_type: ValidationType, params: dict
    ) -> str:
        """Generate validation error message."""
        if validation_type == ValidationType.CHOICE:
            choices = params.get("choices", [])
            choices_str = ", ".join(choices)
            return (
                "[red]:heavy_multiplication_x: "
                f"{name}={value} (must be one of: {choices_str})[/red]"
            )
        elif validation_type == ValidationType.BOOLEAN:
            return (
                "[red]:heavy_multiplication_x: "
                f"{name}={value} (must be 'true' or 'false')[/red]"
            )
        elif validation_type == ValidationType.NUMERIC:
            return (
                f"[red]:heavy_multiplication_x: {name}={value} (must be numeric)[/red]"
            )
        return f"[red]:heavy_multiplication_x: {name}={value} (invalid value)[/red]"

    def validate_transport(self, args: Any) -> None:
        try:
            _ = build_driver(
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
