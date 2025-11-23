#!/usr/bin/env python3
"""Validation helpers for parsed CLI arguments."""

from __future__ import annotations

import argparse

from ..exceptions import ArgumentValidationError


def validate_arguments(args: argparse.Namespace) -> None:
    is_utility_command = getattr(args, "check_env", False) or getattr(
        args, "validate_config", None
    ) is not None

    if not is_utility_command and not getattr(args, "endpoint", None):
        raise ArgumentValidationError("--endpoint is required for fuzzing operations")

    if args.mode == "protocol" and not args.protocol_type:
        pass

    if args.protocol_type and args.mode != "protocol":
        raise ArgumentValidationError(
            "--protocol-type can only be used with --mode protocol"
        )

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


__all__ = ["validate_arguments"]
