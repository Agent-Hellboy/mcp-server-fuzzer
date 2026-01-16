#!/usr/bin/env python3
"""
Result Builder

This module contains logic for building standardized fuzzing results.
"""

from typing import Any

from ...types import FuzzDataResult


class ResultBuilder:
    """Builds standardized fuzzing results."""

    def build_tool_result(
        self,
        tool_name: str,
        run_index: int,
        args: dict[str, Any] | None = None,
        original_args: dict[str, Any] | None = None,
        success: bool = True,
        exception: str | None = None,
        safety_blocked: bool = False,
        safety_reason: str | None = None,
        safety_sanitized: bool = False,
    ) -> dict[str, Any]:
        """
        Create standardized tool fuzzing result.

        Args:
            tool_name: Name of the tool
            run_index: Run index (0-based)
            args: Fuzzed arguments (sanitized if applicable)
            original_args: Original arguments before sanitization
            success: Whether the run was successful
            exception: Exception message if any
            safety_blocked: Whether the operation was blocked by safety system
            safety_reason: Reason for safety blocking
            safety_sanitized: Whether arguments were sanitized

        Returns:
            Standardized tool result dictionary
        """
        result: dict[str, Any] = {
            "tool_name": tool_name,
            "run": run_index + 1,
            "success": success,
        }

        result.update(
            {
                key: value
                for key, value in {
                    "args": args,
                    "original_args": original_args,
                    "exception": exception,
                }.items()
                if value is not None
            }
        )

        if safety_blocked:
            result["safety_blocked"] = True
            if safety_reason:
                result["safety_reason"] = safety_reason

        if safety_sanitized:
            result["safety_sanitized"] = safety_sanitized

        return result

    def build_protocol_result(
        self,
        protocol_type: str,
        run_index: int,
        fuzz_data: dict[str, Any],
        server_response: dict[str, Any] | list[dict[str, Any]] | None = None,
        server_error: str | None = None,
        invariant_violations: list[str] | None = None,
        spec_checks: list[dict[str, Any]] | None = None,
        spec_scope: str | None = None,
    ) -> FuzzDataResult:
        """
        Create standardized protocol fuzzing result.

        Args:
            protocol_type: Protocol type being fuzzed
            run_index: Run index (0-based)
            fuzz_data: Generated fuzz data
            server_response: Response from server, if any
            server_error: Error from server, if any
            invariant_violations: List of invariant violations, if any
            spec_checks: List of spec guard check results, if any
            spec_scope: Scope identifier for spec checks, if any

        Returns:
            Standardized protocol result dictionary
        """
        result: FuzzDataResult = {
            "protocol_type": protocol_type,
            "run": run_index + 1,
            "fuzz_data": fuzz_data,
            "success": server_error is None,
            "server_response": server_response,
            "server_error": server_error,
            "server_rejected_input": server_error is not None,
            "invariant_violations": invariant_violations or [],
        }
        if spec_checks is not None:
            result["spec_checks"] = spec_checks
        if spec_scope:
            result["spec_scope"] = spec_scope

        return result

    def build_batch_result(
        self,
        run_index: int,
        batch_request: list[dict[str, Any]],
        server_response: dict[str, Any] | list[dict[str, Any]] | None = None,
        server_error: str | None = None,
        invariant_violations: list[str] | None = None,
    ) -> FuzzDataResult:
        """
        Create standardized batch fuzzing result.

        Args:
            run_index: Run index (0-based)
            batch_request: Generated batch request
            server_response: Response from server, if any
            server_error: Error from server, if any
            invariant_violations: List of invariant violations, if any

        Returns:
            Standardized batch result dictionary
        """
        result: FuzzDataResult = {
            "protocol_type": "BatchRequest",
            "run": run_index + 1,
            "fuzz_data": batch_request,
            "success": server_error is None,
            "server_response": server_response,
            "server_error": server_error,
            "server_rejected_input": server_error is not None,
            "batch_size": len(batch_request),
            "invariant_violations": invariant_violations or [],
        }

        return result
