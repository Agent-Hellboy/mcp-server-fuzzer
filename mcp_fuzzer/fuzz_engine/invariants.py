#!/usr/bin/env python3
"""
Property-based invariants and checks for fuzz testing.

This module provides functions to verify response validity, error type correctness,
and prevention of unintended crashes or unexpected states during fuzzing.

Implements property-based testing concepts to ensure that server responses conform
to expected formats and contain valid data, errors returned are appropriate, and
the server does not enter unexpected states during fuzzing operations.

These invariants serve as runtime assertions that can be used to validate the
behavior of the server being tested, helping to identify potential issues that
might not be caught by simple error checking.

This module addresses issue #10 by implementing runtime invariant checks for
response validity and correctness, complementing the JSON Schema validation
from issue #12.
"""

import logging
from typing import Any, Dict, List, Optional, Union

# Optional jsonschema validation support
try:
    from jsonschema import validate as jsonschema_validate

    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

    # Define a placeholder function when jsonschema is not available
    def jsonschema_validate(instance, schema):
        """Placeholder when jsonschema is not available."""
        pass


logger = logging.getLogger(__name__)


class InvariantViolation(Exception):
    """Exception raised when an invariant is violated."""

    def __init__(self, message: str, response: Any = None):
        self.message = message
        self.response = response
        super().__init__(message)


def check_response_validity(response: Any) -> bool:
    """
    Check if a response is valid according to expected formats.

    Args:
        response: The response to check

    Returns:
        bool: True if the response is valid, False otherwise

    Raises:
        InvariantViolation: If the response is invalid
    """
    # Check if response is None
    if response is None:
        raise InvariantViolation("Response is None")

    # For JSON-RPC responses, check if they have the required fields
    if isinstance(response, dict):
        if "jsonrpc" in response:
            # This appears to be a JSON-RPC response
            if response.get("jsonrpc") != "2.0":
                raise InvariantViolation(
                    f"Invalid JSON-RPC version: {response.get('jsonrpc')}", response
                )

            # Check for id if it's not a notification
            if "id" not in response and "error" in response:
                raise InvariantViolation(
                    "JSON-RPC error response missing 'id' field", response
                )

            # Check that response has either result or error, but not both
            has_result = "result" in response
            has_error = "error" in response

            if has_result and has_error:
                raise InvariantViolation(
                    "JSON-RPC response cannot have both 'result' and 'error'", response
                )

            if not has_result and not has_error:
                # Notifications don't require result or error
                if "id" in response:
                    raise InvariantViolation(
                        "JSON-RPC response must have either 'result' or 'error'",
                        response,
                    )

    return True


def check_error_type_correctness(
    error: Any, expected_codes: Optional[List[int]] = None
) -> bool:
    """
    Check if an error is of the correct type and has the expected code.

    Args:
        error: The error to check
        expected_codes: Optional list of expected error codes

    Returns:
        bool: True if the error is of the correct type, False otherwise

    Raises:
        InvariantViolation: If the error is not of the correct type
    """
    # Check if error is None
    if error is None:
        return True

    # For JSON-RPC errors, check if they have the required fields
    if isinstance(error, dict):
        if "code" not in error:
            raise InvariantViolation("JSON-RPC error missing 'code' field", error)

        if "message" not in error:
            raise InvariantViolation("JSON-RPC error missing 'message' field", error)

        if not isinstance(error["code"], int):
            raise InvariantViolation(
                (f"JSON-RPC error code must be an integer, got {type(error['code'])}"),
                error,
            )

        if not isinstance(error["message"], str):
            raise InvariantViolation(
                (
                    f"JSON-RPC error message must be a string, "
                    f"got {type(error['message'])}"
                ),
                error,
            )

        # Check if error code is in expected codes
        if expected_codes and error["code"] not in expected_codes:
            raise InvariantViolation(
                (
                    f"Unexpected error code: {error['code']}, "
                    f"expected one of {expected_codes}"
                ),
                error,
            )

    return True


def check_response_schema_conformity(response: Any, schema: Dict[str, Any]) -> bool:
    """
    Check if a response conforms to a given schema.

    Args:
        response: The response to check
        schema: The schema to check against

    Returns:
        bool: True if the response conforms to the schema, False otherwise

    Raises:
        InvariantViolation: If the response does not conform to the schema
    """
    if HAVE_JSONSCHEMA:
        try:
            jsonschema_validate(instance=response, schema=schema)
            return True
        except Exception as e:
            raise InvariantViolation(
                f"Response does not conform to schema: {e}", response
            )
    else:
        logger.warning("jsonschema package not installed, skipping schema validation")
        return True


def verify_response_invariants(
    response: Any,
    expected_error_codes: Optional[List[int]] = None,
    schema: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Verify all invariants for a response.

    Args:
        response: The response to verify
        expected_error_codes: Optional list of expected error codes
        schema: Optional schema to validate against

    Returns:
        bool: True if all invariants are satisfied, False otherwise

    Raises:
        InvariantViolation: If any invariant is violated
    """
    # Check response validity
    check_response_validity(response)

    # Check error type correctness if response has an error
    if isinstance(response, dict) and "error" in response:
        check_error_type_correctness(response["error"], expected_error_codes)

    # Check schema conformity if schema is provided
    if schema is not None:
        check_response_schema_conformity(response, schema)

    return True


def verify_batch_responses(
    responses: List[Any],
    expected_error_codes: Optional[List[int]] = None,
    schema: Optional[Dict[str, Any]] = None,
) -> Dict[int, Union[bool, str]]:
    """
    Verify invariants for a batch of responses.

    Args:
        responses: The responses to verify
        expected_error_codes: Optional list of expected error codes
        schema: Optional schema to validate against

    Returns:
        Dict[int, Union[bool, str]]: A dictionary mapping response indices to
            verification results (True if valid, error message if invalid)
    """
    results = {}

    for i, response in enumerate(responses):
        try:
            verify_response_invariants(response, expected_error_codes, schema)
            results[i] = True
        except InvariantViolation as e:
            results[i] = str(e)

    return results


def check_state_consistency(
    before_state: Dict[str, Any],
    after_state: Dict[str, Any],
    allowed_changes: Optional[List[str]] = None,
) -> bool:
    """
    Check if the state is consistent before and after an operation.

    Args:
        before_state: The state before the operation
        after_state: The state after the operation
        allowed_changes: Optional list of keys that are allowed to change

    Returns:
        bool: True if the state is consistent, False otherwise

    Raises:
        InvariantViolation: If the state is inconsistent
    """
    allowed_changes = allowed_changes or []

    # Check that all keys in before_state are also in after_state
    for key in before_state:
        if key not in after_state:
            raise InvariantViolation(f"Key '{key}' missing from after_state")

    # Check that values for keys not in allowed_changes are the same
    for key in before_state:
        if key not in allowed_changes and before_state[key] != after_state[key]:
            raise InvariantViolation(
                f"Key '{key}' changed unexpectedly: {before_state[key]} -> "
                f"{after_state[key]}"
            )

    return True
