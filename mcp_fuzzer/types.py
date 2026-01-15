#!/usr/bin/env python3
"""
Common type definitions for MCP Fuzzer

This module provides TypedDict definitions and other type structures
to improve type safety throughout the codebase.
"""

from typing import Any, TypedDict

# JSON container types
JSONContainer = dict[str, Any] | list[Any]


class FuzzDataResult(TypedDict, total=False):
    """TypedDict for fuzzing results data structure."""

    fuzz_data: dict[str, Any]
    success: bool
    # Absent when no response was captured; None when explicitly captured as null
    server_response: JSONContainer | None
    server_error: str | None
    server_rejected_input: bool
    spec_checks: list[dict[str, Any]]
    spec_scope: str
    run: int
    protocol_type: str
    exception: str | None
    invariant_violations: list[str]


class ProtocolFuzzResult(TypedDict, total=False):
    """TypedDict for protocol fuzzing results."""

    fuzz_data: dict[str, Any]
    result: dict[str, Any]
    spec_checks: list[dict[str, Any]]
    spec_scope: str
    safety_blocked: bool
    safety_sanitized: bool
    success: bool
    exception: str | None
    traceback: str | None


class ToolFuzzResult(TypedDict, total=False):
    """TypedDict for tool fuzzing results."""

    args: dict[str, Any]
    result: dict[str, Any]
    spec_checks: list[dict[str, Any]]
    spec_scope: str
    safety_blocked: bool
    safety_sanitized: bool
    success: bool
    exception: str | None
    traceback: str | None
    error: str | None


class BatchExecutionResult(TypedDict):
    """TypedDict for batch execution results."""

    results: list[dict[str, Any]]
    errors: list[Exception]
    execution_time: float
    completed: int
    failed: int


class SafetyCheckResult(TypedDict):
    """TypedDict for safety check results."""

    blocked: bool
    sanitized: bool
    blocking_reason: str | None
    data: Any


class TransportStats(TypedDict, total=False):
    """TypedDict for transport statistics."""

    requests_sent: int
    successful_responses: int
    error_responses: int
    timeouts: int
    network_errors: int
    average_response_time: float
    last_activity: float
    process_id: int | None
    active: bool


# Constants for timeouts and other magic numbers
DEFAULT_TIMEOUT = 30.0  # seconds
DEFAULT_CONCURRENCY = 5
PREVIEW_LENGTH = 200  # characters for data previews
MAX_RETRIES = 3
RETRY_DELAY = 0.1  # seconds
BUFFER_SIZE = 4096  # bytes

# Standard HTTP status codes with semantic names
HTTP_OK = 200
HTTP_ACCEPTED = 202
HTTP_REDIRECT_TEMPORARY = 307
HTTP_REDIRECT_PERMANENT = 308
HTTP_NOT_FOUND = 404
