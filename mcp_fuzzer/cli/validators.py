#!/usr/bin/env python3
"""Unified validation system for CLI arguments and environment checks."""

from __future__ import annotations

import argparse
import os
from typing import Any

from rich.console import Console

from ..exceptions import ArgumentValidationError
from ..config import config_mediator
from ..transport.catalog import build_driver
from ..exceptions import MCPError, TransportError
from ..config.env import ENVIRONMENT_VARIABLES, ValidationType
from ..icons import CHECK, CROSS


# Numeric bound rules: (attr, accepted types, bound, bound is exclusive, message).
# Grouped so the checks keep firing in the same order as the surrounding
# non-numeric checks in ``validate_arguments``.
_NumericRule = tuple[str, tuple[type, ...], float, bool, str]

_RUN_BOUND_RULES: tuple[_NumericRule, ...] = (
    ("runs", (int,), 1, False, "--runs must be at least 1"),
    ("runs_per_type", (int,), 1, False, "--runs-per-type must be at least 1"),
    ("timeout", (int, float), 0, True, "--timeout must be positive"),
)

_RETRY_BOUND_RULES: tuple[_NumericRule, ...] = (
    ("transport_retries", (int,), 1, False, "--transport-retries must be at least 1"),
    (
        "transport_retry_delay",
        (int, float),
        0,
        False,
        "--transport-retry-delay must be >= 0",
    ),
    (
        "transport_retry_backoff",
        (int, float),
        1,
        False,
        "--transport-retry-backoff must be >= 1",
    ),
    (
        "transport_retry_max_delay",
        (int, float),
        0,
        False,
        "--transport-retry-max-delay must be >= 0",
    ),
)

_JITTER_BOUND_RULES: tuple[_NumericRule, ...] = (
    (
        "transport_retry_jitter",
        (int, float),
        0,
        False,
        "--transport-retry-jitter must be >= 0",
    ),
)


def _check_numeric_bounds(
    args: argparse.Namespace, rules: tuple[_NumericRule, ...]
) -> None:
    """Raise ``ArgumentValidationError`` for any out-of-range numeric argument."""
    for attr, types, bound, exclusive, message in rules:
        value = getattr(args, attr, None)
        if value is None:
            continue
        if not isinstance(value, types) or (
            value <= bound if exclusive else value < bound
        ):
            raise ArgumentValidationError(message)


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

        if args.mode == "protocol" and args.protocol_type:
            from ..protocol_registry import FUZZABLE_PROTOCOL_TYPES

            requested = [
                part.strip()
                for part in str(args.protocol_type).split("|")
                if part.strip()
            ]
            if not requested:
                raise ArgumentValidationError(
                    "--protocol-type cannot be empty when provided"
                )
            unsupported = [
                name
                for name in requested
                if name not in FUZZABLE_PROTOCOL_TYPES
            ]
            if unsupported:
                supported = ", ".join(FUZZABLE_PROTOCOL_TYPES)
                raise ArgumentValidationError(
                    "Unsupported protocol type(s): "
                    f"{', '.join(unsupported)}. Supported: {supported}"
                )

        if args.protocol_type and args.mode != "protocol":
            raise ArgumentValidationError(
                "--protocol-type can only be used with --mode protocol"
            )

        if getattr(args, "auth_audit_intrusive", False) and not getattr(
            args, "auth_audit", False
        ):
            raise ArgumentValidationError(
                "--auth-audit-intrusive requires --auth-audit"
            )

        if getattr(args, "security_audit_intrusive", False) and not getattr(
            args, "security_audit", False
        ):
            raise ArgumentValidationError(
                "--security-audit-intrusive requires --security-audit"
            )

        if args.mode == "tools" and getattr(args, "tool", None):
            if not args.tool.strip():
                raise ArgumentValidationError("--tool cannot be empty")

        _check_numeric_bounds(args, _RUN_BOUND_RULES)

        if hasattr(args, "endpoint") and args.endpoint is not None:
            if not args.endpoint.strip():
                raise ArgumentValidationError("--endpoint cannot be empty")

        _check_numeric_bounds(args, _RETRY_BOUND_RULES)

        max_delay = getattr(args, "transport_retry_max_delay", None)
        delay = getattr(args, "transport_retry_delay", None)
        if max_delay is not None and delay is not None and max_delay < delay:
            raise ArgumentValidationError(
                "--transport-retry-max-delay must be >= --transport-retry-delay"
            )

        _check_numeric_bounds(args, _JITTER_BOUND_RULES)

    def validate_config_file(self, path: str) -> None:
        """Validate a config file and print success message."""
        config_mediator.load_file(path)
        success_msg = f"[green]{CHECK} Configuration file '{path}' is valid[/green]"
        self.console.print(success_msg)

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
                self.console.print(f"[green]{CHECK} {name}={value}[/green]")
            else:
                error_msg = self._get_validation_error_msg(
                    name, value, validation_type, validation_params
                )
                self.console.print(error_msg)
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
            choices = params.get("choices", [])
            return value in choices
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
            return f"[red]{CROSS} {name}={value} (must be one of: {choices_str})[/red]"
        elif validation_type == ValidationType.BOOLEAN:
            return f"[red]{CROSS} {name}={value} (must be 'true' or 'false')[/red]"
        elif validation_type == ValidationType.NUMERIC:
            return f"[red]{CROSS} {name}={value} (must be numeric)[/red]"
        return f"[red]{CROSS} {name}={value} (invalid value)[/red]"

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
