#!/usr/bin/env python3
"""Tests for fuzz outcome classification."""

from __future__ import annotations

import pytest

from mcp_fuzzer.exceptions import ServerError
from mcp_fuzzer.outcomes import (
    FuzzOutcome,
    classify_protocol_run,
    classify_tool_run,
    is_server_rejection_error,
    outcome_to_error_type,
)
from mcp_fuzzer.types import ErrorType


def test_is_server_rejection_error_non_server_error():
    assert is_server_rejection_error(ValueError("nope")) is False


def test_is_server_rejection_error_without_error_payload():
    exc = ServerError("bad", context={})
    assert is_server_rejection_error(exc) is True


def test_is_server_rejection_error_with_jsonrpc_code():
    exc = ServerError(
        "bad",
        context={"error": {"code": -32602, "message": "invalid"}},
    )
    assert is_server_rejection_error(exc) is True


def test_is_server_rejection_error_with_non_rejection_code():
    exc = ServerError(
        "bad",
        context={"error": {"code": -32000, "message": "app"}},
    )
    assert is_server_rejection_error(exc) is False


@pytest.mark.parametrize(
    "kwargs,expected_success,expected_outcome",
    [
        (
            {"safety_blocked": True},
            False,
            FuzzOutcome.SAFETY_BLOCKED,
        ),
        (
            {"mutation_failed": True},
            False,
            FuzzOutcome.MUTATION_FAILED,
        ),
        (
            {"timeout": True},
            False,
            FuzzOutcome.TIMEOUT,
        ),
        (
            {"result": {"isError": True}},
            True,
            FuzzOutcome.SERVER_REJECTED,
        ),
        (
            {"result": {"content": []}},
            False,
            FuzzOutcome.ACCEPTED_MALFORMED,
        ),
        (
            {},
            False,
            FuzzOutcome.TRANSPORT_ERROR,
        ),
    ],
)
def test_classify_tool_run_branches(kwargs, expected_success, expected_outcome):
    success, outcome = classify_tool_run(**kwargs)
    assert success is expected_success
    assert outcome == expected_outcome


def test_classify_protocol_run_rejection_exception():
    exc = ServerError("bad", context={"error": {"code": -32602}})
    success, outcome = classify_protocol_run(exception=exc)
    assert success is True
    assert outcome == FuzzOutcome.SERVER_REJECTED


def test_classify_tool_run_rejection_exception():
    exc = ServerError("bad", context={"error": {"code": -32601}})
    success, outcome = classify_tool_run(exception=exc)
    assert success is True
    assert outcome == FuzzOutcome.SERVER_REJECTED

    success, outcome = classify_tool_run(exception=RuntimeError("boom"))
    assert success is False
    assert outcome == FuzzOutcome.TRANSPORT_ERROR


def test_classify_protocol_run_safety_blocked():
    success, outcome = classify_protocol_run(safety_blocked=True)
    assert success is False
    assert outcome == FuzzOutcome.SAFETY_BLOCKED


def test_classify_protocol_run_server_error_string():
    success, outcome = classify_protocol_run(server_error="invalid params")
    assert success is True
    assert outcome == FuzzOutcome.SERVER_REJECTED


def test_classify_protocol_run_jsonrpc_rejection_code():
    success, outcome = classify_protocol_run(
        server_response={"error": {"code": -32600, "message": "bad"}}
    )
    assert success is True
    assert outcome == FuzzOutcome.SERVER_REJECTED


def test_classify_protocol_run_jsonrpc_non_rejection_code():
    success, outcome = classify_protocol_run(
        server_response={"error": {"code": -32000, "message": "app"}}
    )
    assert success is False
    assert outcome == FuzzOutcome.TRANSPORT_ERROR


def test_classify_protocol_run_accepted_malformed_result():
    success, outcome = classify_protocol_run(server_response={"result": {}})
    assert success is False
    assert outcome == FuzzOutcome.ACCEPTED_MALFORMED


def test_classify_protocol_run_error_without_code():
    success, outcome = classify_protocol_run(
        server_response={"error": {"message": "failed"}}
    )
    assert success is True
    assert outcome == FuzzOutcome.SERVER_REJECTED


def test_classify_protocol_run_non_dict_response():
    success, outcome = classify_protocol_run(server_response=["not", "a", "dict"])
    assert success is False
    assert outcome == FuzzOutcome.TRANSPORT_ERROR


@pytest.mark.parametrize(
    "outcome,expected",
    [
        (FuzzOutcome.ACCEPTED_MALFORMED, ErrorType.TOOL_CALL_FAILED),
        (FuzzOutcome.TRANSPORT_ERROR, ErrorType.TOOL_CALL_FAILED),
        (FuzzOutcome.TIMEOUT, ErrorType.TOOL_TIMEOUT),
        (FuzzOutcome.MUTATION_FAILED, ErrorType.TOOL_MUTATION_FAILED),
        (FuzzOutcome.PHASE_FAILED, ErrorType.PHASE_EXECUTION_FAILED),
        (FuzzOutcome.SERVER_REJECTED, None),
    ],
)
def test_outcome_to_error_type(outcome, expected):
    assert outcome_to_error_type(outcome) == expected
