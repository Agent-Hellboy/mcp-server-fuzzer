#!/usr/bin/env python3
"""
Unit tests for invariants module.
"""

import pytest
from pytest import raises
from unittest.mock import patch

from mcp_fuzzer.fuzz_engine.invariants import (
    InvariantViolation,
    check_response_validity,
    check_error_type_correctness,
    check_response_schema_conformity,
    verify_response_invariants,
    verify_batch_responses,
    check_state_consistency,
)

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine]


def test_check_response_validity_valid_result():
    """Test that a valid JSON-RPC result response passes validation."""
    response = {"jsonrpc": "2.0", "id": 1, "result": "success"}
    assert check_response_validity(response)


def test_check_response_validity_valid_error():
    """Test that a valid JSON-RPC error response passes validation."""
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32600, "message": "Invalid Request"},
    }
    assert check_response_validity(response)


def test_check_response_validity_valid_notification():
    """Test that a valid JSON-RPC notification passes validation."""
    response = {"jsonrpc": "2.0"}
    assert check_response_validity(response)


def test_check_response_validity_none():
    """Test that None response raises an exception."""
    with raises(InvariantViolation):
        check_response_validity(None)


def test_check_response_validity_invalid_version():
    """Test that an invalid JSON-RPC version raises an exception."""
    response = {"jsonrpc": "1.0", "id": 1, "result": "success"}
    with raises(InvariantViolation):
        check_response_validity(response)


def test_check_response_validity_missing_id_with_error():
    """Test that a missing ID in an error response raises an exception."""
    response = {
        "jsonrpc": "2.0",
        "error": {"code": -32600, "message": "Invalid Request"},
    }
    with raises(InvariantViolation):
        check_response_validity(response)


def test_check_response_validity_both_result_and_error():
    """Test that having both result and error raises an exception."""
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": "success",
        "error": {"code": -32600, "message": "Invalid Request"},
    }
    with raises(InvariantViolation):
        check_response_validity(response)


def test_check_response_validity_neither_result_nor_error():
    """Test that having neither result nor error raises an exception."""
    response = {"jsonrpc": "2.0", "id": 1}
    with raises(InvariantViolation):
        check_response_validity(response)


def test_check_error_type_correctness_valid():
    """Test that a valid error passes validation."""
    error = {"code": -32600, "message": "Invalid Request"}
    assert check_error_type_correctness(error)


def test_check_error_type_correctness_none():
    """Test that None error raises an exception."""
    with raises(InvariantViolation):
        check_error_type_correctness(None)


def test_check_error_type_correctness_missing_code():
    """Test that a missing code raises an exception."""
    error = {"message": "Invalid Request"}
    with raises(InvariantViolation):
        check_error_type_correctness(error)


def test_check_error_type_correctness_missing_message():
    """Test that a missing message raises an exception."""
    error = {"code": -32600}
    with raises(InvariantViolation):
        check_error_type_correctness(error)


def test_check_error_type_correctness_invalid_code_type():
    """Test that an invalid code type raises an exception."""
    error = {"code": "invalid", "message": "Invalid Request"}
    with raises(InvariantViolation):
        check_error_type_correctness(error)


def test_check_error_type_correctness_invalid_message_type():
    """Test that an invalid message type raises an exception."""
    error = {"code": -32600, "message": 123}
    with raises(InvariantViolation):
        check_error_type_correctness(error)


def test_check_error_type_correctness_unexpected_code():
    """Test that an unexpected error code raises an exception."""
    error = {"code": -32600, "message": "Invalid Request"}
    expected_codes = [-32700, -32601]
    with raises(InvariantViolation):
        check_error_type_correctness(error, expected_codes)


def test_check_response_schema_conformity_valid():
    """Test that a valid response passes schema validation."""
    response = {"name": "test", "age": 30}
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
        },
        "required": ["name", "age"],
    }

    with patch("mcp_fuzzer.fuzz_engine.invariants.HAVE_JSONSCHEMA", True):
        with patch(
            "mcp_fuzzer.fuzz_engine.invariants.jsonschema_validate"
        ) as mock_validate:
            assert check_response_schema_conformity(response, schema)
            mock_validate.assert_called_once()


def test_check_response_schema_conformity_invalid():
    """Test that an invalid response raises an exception."""
    response = {"name": "test", "age": "thirty"}
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
        },
        "required": ["name", "age"],
    }

    with patch("mcp_fuzzer.fuzz_engine.invariants.HAVE_JSONSCHEMA", True):
        with patch(
            "mcp_fuzzer.fuzz_engine.invariants.jsonschema_validate"
        ) as mock_validate:
            mock_validate.side_effect = Exception("Validation error")
            with raises(InvariantViolation):
                check_response_schema_conformity(response, schema)


def test_check_response_schema_conformity_import_error(caplog):
    """Test that an import error is handled gracefully."""
    response = {"name": "test", "age": 30}
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
        },
        "required": ["name", "age"],
    }

    with patch("mcp_fuzzer.fuzz_engine.invariants.HAVE_JSONSCHEMA", False):
        assert check_response_schema_conformity(response, schema)
        assert any(
            "jsonschema package not installed" in record.message
            for record in caplog.records
        )


def test_verify_response_invariants_all_pass():
    """Test that all invariants pass for a valid response."""
    response = {"jsonrpc": "2.0", "id": 1, "result": "success"}

    with (
        patch(
            "mcp_fuzzer.fuzz_engine.invariants.check_response_validity"
        ) as mock_validity,
        patch(
            "mcp_fuzzer.fuzz_engine.invariants.check_response_schema_conformity"
        ) as mock_schema,
    ):
        mock_validity.return_value = True
        mock_schema.return_value = True

        assert verify_response_invariants(response, schema={})
        mock_validity.assert_called_once_with(response)
        mock_schema.assert_called_once()


def test_verify_response_invariants_with_error():
    """Test that error type is checked for error responses."""
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32600, "message": "Invalid Request"},
    }
    expected_error_codes = [-32600, -32700]

    with (
        patch(
            "mcp_fuzzer.fuzz_engine.invariants.check_response_validity"
        ) as mock_validity,
        patch(
            "mcp_fuzzer.fuzz_engine.invariants.check_error_type_correctness"
        ) as mock_error,
    ):
        mock_validity.return_value = True
        mock_error.return_value = True

        assert verify_response_invariants(response, expected_error_codes)
        mock_validity.assert_called_once_with(response)
        mock_error.assert_called_once_with(response["error"], expected_error_codes)


@pytest.mark.asyncio
async def test_verify_batch_responses_all_valid():
    """Test that all responses in a batch are validated."""
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": "success"},
        {"jsonrpc": "2.0", "id": 2, "result": "success"},
    ]

    with patch(
        "mcp_fuzzer.fuzz_engine.invariants.verify_response_invariants"
    ) as mock_verify:
        mock_verify.return_value = True

        results = await verify_batch_responses(responses)
        assert len(results) == 2
        assert all(results.values())
        assert mock_verify.call_count == 2


@pytest.mark.asyncio
async def test_verify_batch_responses_some_invalid():
    """Test that invalid responses in a batch are reported."""
    responses = [
        {"jsonrpc": "2.0", "id": 1, "result": "success"},
        {"jsonrpc": "1.0", "id": 2, "result": "success"},
    ]

    with patch(
        "mcp_fuzzer.fuzz_engine.invariants.verify_response_invariants"
    ) as mock_verify:
        mock_verify.side_effect = [True, InvariantViolation("Invalid version")]

        results = await verify_batch_responses(responses)
        assert len(results) == 2
        assert results[0] is True
        assert results[1] == "Invalid version"
        assert mock_verify.call_count == 2


def test_check_state_consistency_valid():
    """Test that consistent states pass validation."""
    before_state = {"a": 1, "b": 2, "c": 3}
    after_state = {"a": 1, "b": 2, "c": 3, "d": 4}
    expected_changes = ["d"]
    assert check_state_consistency(before_state, after_state, expected_changes)


def test_check_state_consistency_with_allowed_changes():
    """Test that allowed changes pass validation."""
    before_state = {"a": 1, "b": 2, "c": 3}
    after_state = {"a": 1, "b": 5, "c": 3}
    allowed_changes = ["b"]
    assert check_state_consistency(before_state, after_state, allowed_changes)


def test_check_state_consistency_missing_key():
    """Test that missing keys raise an exception."""
    before_state = {"a": 1, "b": 2, "c": 3}
    after_state = {"a": 1, "b": 2}
    with raises(InvariantViolation):
        check_state_consistency(before_state, after_state)


def test_check_state_consistency_unexpected_change():
    """Test that unexpected changes raise an exception."""
    before_state = {"a": 1, "b": 2, "c": 3}
    after_state = {"a": 1, "b": 5, "c": 3}
    with raises(InvariantViolation):
        check_state_consistency(before_state, after_state)
