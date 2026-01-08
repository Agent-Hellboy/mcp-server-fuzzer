#!/usr/bin/env python3
"""
Unit tests for invariants module.
"""

import unittest
import pytest
from unittest.mock import patch

from mcp_fuzzer.fuzz_engine.executor import (
    InvariantViolation,
    check_response_validity,
    check_error_type_correctness,
    check_response_schema_conformity,
    verify_response_invariants,
    verify_batch_responses,
    check_state_consistency,
)


class TestInvariants(unittest.TestCase):
    """Test cases for invariants module."""

    def test_check_response_validity_valid_result(self):
        """Test that a valid JSON-RPC result response passes validation."""
        response = {"jsonrpc": "2.0", "id": 1, "result": "success"}
        self.assertTrue(check_response_validity(response))

    def test_check_response_validity_valid_error(self):
        """Test that a valid JSON-RPC error response passes validation."""
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"},
        }
        self.assertTrue(check_response_validity(response))

    def test_check_response_validity_valid_notification(self):
        """Test that a valid JSON-RPC notification passes validation."""
        response = {"jsonrpc": "2.0", "method": "notify", "params": {}}
        self.assertTrue(check_response_validity(response))

    def test_check_response_validity_none(self):
        """Test that None response raises an exception."""
        with self.assertRaises(InvariantViolation):
            check_response_validity(None)

    def test_check_response_validity_invalid_version(self):
        """Test that an invalid JSON-RPC version raises an exception."""
        response = {"jsonrpc": "1.0", "id": 1, "result": "success"}
        with self.assertRaises(InvariantViolation):
            check_response_validity(response)

    def test_check_response_validity_missing_id_with_error(self):
        """Test that a missing ID in an error response raises an exception."""
        response = {
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid Request"},
        }
        with self.assertRaises(InvariantViolation):
            check_response_validity(response)

    def test_check_response_validity_both_result_and_error(self):
        """Test that having both result and error raises an exception."""
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": "success",
            "error": {"code": -32600, "message": "Invalid Request"},
        }
        with self.assertRaises(InvariantViolation):
            check_response_validity(response)

    def test_check_response_validity_neither_result_nor_error(self):
        """Test that having neither result nor error raises an exception."""
        response = {"jsonrpc": "2.0", "id": 1}
        with self.assertRaises(InvariantViolation):
            check_response_validity(response)

    def test_check_error_type_correctness_valid(self):
        """Test that a valid error passes validation."""
        error = {"code": -32600, "message": "Invalid Request"}
        self.assertTrue(check_error_type_correctness(error))

    def test_check_error_type_correctness_none(self):
        """Test that None error raises an exception."""
        with self.assertRaises(InvariantViolation):
            check_error_type_correctness(None)

    def test_check_error_type_correctness_missing_code(self):
        """Test that a missing code raises an exception."""
        error = {"message": "Invalid Request"}
        with self.assertRaises(InvariantViolation):
            check_error_type_correctness(error)

    def test_check_error_type_correctness_missing_message(self):
        """Test that a missing message raises an exception."""
        error = {"code": -32600}
        with self.assertRaises(InvariantViolation):
            check_error_type_correctness(error)

    def test_check_error_type_correctness_invalid_code_type(self):
        """Test that an invalid code type raises an exception."""
        error = {"code": "invalid", "message": "Invalid Request"}
        with self.assertRaises(InvariantViolation):
            check_error_type_correctness(error)

    def test_check_error_type_correctness_invalid_message_type(self):
        """Test that an invalid message type raises an exception."""
        error = {"code": -32600, "message": 123}
        with self.assertRaises(InvariantViolation):
            check_error_type_correctness(error)

    def test_check_error_type_correctness_unexpected_code(self):
        """Test that an unexpected error code raises an exception."""
        error = {"code": -32600, "message": "Invalid Request"}
        expected_codes = [-32700, -32601]
        with self.assertRaises(InvariantViolation):
            check_error_type_correctness(error, expected_codes)

    def test_check_response_schema_conformity_valid(self):
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

        with patch("mcp_fuzzer.fuzz_engine.executor.invariants.HAVE_JSONSCHEMA", True):
            with patch(
                "mcp_fuzzer.fuzz_engine.executor.invariants.jsonschema_validate"
            ) as mock_validate:
                self.assertTrue(check_response_schema_conformity(response, schema))
                mock_validate.assert_called_once()

    def test_check_response_schema_conformity_invalid(self):
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

        with patch("mcp_fuzzer.fuzz_engine.executor.invariants.HAVE_JSONSCHEMA", True):
            with patch(
                "mcp_fuzzer.fuzz_engine.executor.invariants.jsonschema_validate"
            ) as mock_validate:
                mock_validate.side_effect = Exception("Validation error")
                with self.assertRaises(InvariantViolation):
                    check_response_schema_conformity(response, schema)

    def test_check_response_schema_conformity_import_error(self):
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

        with patch("mcp_fuzzer.fuzz_engine.executor.invariants.HAVE_JSONSCHEMA", False):
            with self.assertLogs(level="WARNING") as cm:
                self.assertTrue(check_response_schema_conformity(response, schema))
                self.assertIn("jsonschema package not installed", cm.output[0])

    def test_verify_response_invariants_all_pass(self):
        """Test that all invariants pass for a valid response."""
        response = {"jsonrpc": "2.0", "id": 1, "result": "success"}

        with (
            patch(
                "mcp_fuzzer.fuzz_engine.executor.invariants.check_response_validity"
            ) as mock_validity,
            patch(
                "mcp_fuzzer.fuzz_engine.executor.invariants.check_response_schema_conformity"
            ) as mock_schema,
        ):
            mock_validity.return_value = True
            mock_schema.return_value = True

            self.assertTrue(verify_response_invariants(response, schema={}))
            mock_validity.assert_called_once_with(response)
            mock_schema.assert_called_once()

    def test_verify_response_invariants_with_error(self):
        """Test that error type is checked for error responses."""
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"},
        }
        expected_error_codes = [-32600, -32700]

        with (
            patch(
                "mcp_fuzzer.fuzz_engine.executor.invariants.check_response_validity"
            ) as mock_validity,
            patch(
                "mcp_fuzzer.fuzz_engine.executor.invariants.check_error_type_correctness"
            ) as mock_error,
        ):
            mock_validity.return_value = True
            mock_error.return_value = True

            self.assertTrue(verify_response_invariants(response, expected_error_codes))
            mock_validity.assert_called_once_with(response)
            mock_error.assert_called_once_with(response["error"], expected_error_codes)

    @pytest.mark.asyncio
    async def test_verify_batch_responses_all_valid(self):
        """Test that all responses in a batch are validated."""
        responses = [
            {"jsonrpc": "2.0", "id": 1, "result": "success"},
            {"jsonrpc": "2.0", "id": 2, "result": "success"},
        ]

        with patch(
            "mcp_fuzzer.fuzz_engine.executor.invariants.verify_response_invariants"
        ) as mock_verify:
            mock_verify.return_value = True

            results = await verify_batch_responses(responses)
            self.assertEqual(len(results), 2)
            self.assertTrue(all(results.values()))
            self.assertEqual(mock_verify.call_count, 2)

    @pytest.mark.asyncio
    async def test_verify_batch_responses_some_invalid(self):
        """Test that invalid responses in a batch are reported."""
        responses = [
            {"jsonrpc": "2.0", "id": 1, "result": "success"},
            {"jsonrpc": "1.0", "id": 2, "result": "success"},
        ]

        with patch(
            "mcp_fuzzer.fuzz_engine.executor.invariants.verify_response_invariants"
        ) as mock_verify:
            mock_verify.side_effect = [True, InvariantViolation("Invalid version")]

            results = await verify_batch_responses(responses)
            self.assertEqual(len(results), 2)
            self.assertTrue(results[0])
            self.assertEqual(results[1], "Invalid version")
            self.assertEqual(mock_verify.call_count, 2)

    def test_check_state_consistency_valid(self):
        """Test that consistent states pass validation."""
        before_state = {"a": 1, "b": 2, "c": 3}
        after_state = {"a": 1, "b": 2, "c": 3, "d": 4}
        expected_changes = ["d"]
        self.assertTrue(
            check_state_consistency(before_state, after_state, expected_changes)
        )

    def test_check_state_consistency_with_allowed_changes(self):
        """Test that allowed changes pass validation."""
        before_state = {"a": 1, "b": 2, "c": 3}
        after_state = {"a": 1, "b": 5, "c": 3}
        allowed_changes = ["b"]
        self.assertTrue(
            check_state_consistency(before_state, after_state, allowed_changes)
        )

    def test_check_state_consistency_missing_key(self):
        """Test that missing keys raise an exception."""
        before_state = {"a": 1, "b": 2, "c": 3}
        after_state = {"a": 1, "b": 2}
        with self.assertRaises(InvariantViolation):
            check_state_consistency(before_state, after_state)

    def test_check_state_consistency_unexpected_change(self):
        """Test that unexpected changes raise an exception."""
        before_state = {"a": 1, "b": 2, "c": 3}
        after_state = {"a": 1, "b": 5, "c": 3}
        with self.assertRaises(InvariantViolation):
            check_state_consistency(before_state, after_state)


if __name__ == "__main__":
    unittest.main()
