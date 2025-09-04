#!/usr/bin/env python3
"""
Common type definitions for MCP Fuzzer

This module provides TypedDict definitions and other type structures
to improve type safety throughout the codebase.
"""

from typing import Any, Dict, List, Optional, TypedDict, Union

# JSON container types
JSONContainer = Union[Dict[str, Any], List[Any]]


class FuzzDataResult(TypedDict, total=False):
    """TypedDict for fuzzing results data structure."""

    fuzz_data: Dict[str, Any]
    success: bool
    # Absent when no response was captured; None when explicitly captured as null
    server_response: Optional[JSONContainer]
    server_error: Optional[str]
    server_rejected_input: bool
    run: int
    protocol_type: str
    exception: Optional[str]
    invariant_violations: List[str]


class ProtocolFuzzResult(TypedDict, total=False):
    """TypedDict for protocol fuzzing results."""

    fuzz_data: Dict[str, Any]
    result: Dict[str, Any]
    safety_blocked: bool
    safety_sanitized: bool
    success: bool
    exception: Optional[str]
    traceback: Optional[str]


class ToolFuzzResult(TypedDict, total=False):
    """TypedDict for tool fuzzing results."""

    args: Dict[str, Any]
    result: Dict[str, Any]
    safety_blocked: bool
    safety_sanitized: bool
    success: bool
    exception: Optional[str]
    traceback: Optional[str]
    error: Optional[str]


class BatchExecutionResult(TypedDict):
    """TypedDict for batch execution results."""

    results: List[Dict[str, Any]]
    errors: List[Exception]
    execution_time: float
    completed: int
    failed: int


class SafetyCheckResult(TypedDict):
    """TypedDict for safety check results."""

    blocked: bool
    sanitized: bool
    blocking_reason: Optional[str]
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
    process_id: Optional[int]
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
