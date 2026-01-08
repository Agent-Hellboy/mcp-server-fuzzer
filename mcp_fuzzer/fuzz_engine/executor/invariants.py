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
from typing import Any

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

    # For JSON-RPC responses, check required fields
    if isinstance(response, dict):
        if "jsonrpc" in response:
            # This appears to be a JSON-RPC response
            if response.get("jsonrpc") != "2.0":
                raise InvariantViolation(
                    f"Invalid JSON-RPC version: {response.get('jsonrpc')}", response
                )

            # Check that response has either result or error, but not both
            has_result = "result" in response
            has_error = "error" in response

            if has_result and has_error:
                raise InvariantViolation(
                    "JSON-RPC response cannot have both 'result' and 'error'", response
                )

            # Determine if this is a notification, request, or response
            has_id = "id" in response
            has_method = "method" in response

            # If it has method but no id, it's a notification (valid)
            if has_method and not has_id:
                # Notifications don't need result/error
                return True

            # If it has id but no method, it's a response and needs result or error
            if not has_result and not has_error and has_id and not has_method:
                # Responses must have result or error
                raise InvariantViolation(
                    "JSON-RPC response must have either 'result' or 'error'",
                    response,
                )

            # If it has both method and id, this is a request; reject here
            if has_method and has_id and not (has_result or has_error):
                raise InvariantViolation(
                    "Received a JSON-RPC request where a response was expected",
                    response,
                )

            # id is required for any response (result or error)
            # but not for notifications (which have method but no id)
            if (has_result or has_error) and not has_method:
                if "id" not in response:
                    raise InvariantViolation("JSON-RPC response missing 'id'", response)
                if (
                    not isinstance(response["id"], (int, str))
                    and response["id"] is not None
                ):
                    raise InvariantViolation(
                        f"JSON-RPC id must be int, str, or null; "
                        f"got {type(response['id'])}",
                        response,
                    )
        else:
            # If dict but not a JSON-RPC envelope, optionally treat as invalid
            raise InvariantViolation(
                "Unexpected non JSON-RPC response object", response
            )
    else:
        raise InvariantViolation(
            f"Unexpected response type: {type(response)}", response
        )

    return True


def check_error_type_correctness(
    error: Any, expected_codes: list[int] | None = None
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
    # 'error' must be an object when present per JSON-RPC 2.0
    if error is None:
        raise InvariantViolation("JSON-RPC error must be an object; got null", error)

    # For JSON-RPC errors, check required fields
    if isinstance(error, dict):
        if "code" not in error:
            raise InvariantViolation("JSON-RPC error missing 'code' field", error)

        if "message" not in error:
            raise InvariantViolation("JSON-RPC error missing 'message' field", error)

        code = error["code"]
        if isinstance(code, bool) or not isinstance(code, int):
            raise InvariantViolation(
                "JSON-RPC error code must be an integer (bool not allowed)",
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
    else:
        raise InvariantViolation("JSON-RPC error must be an object", error)

    return True


def check_response_schema_conformity(response: Any, schema: dict[str, Any]) -> bool:
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
    expected_error_codes: list[int] | None = None,
    schema: dict[str, Any] | None = None,
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


async def verify_batch_responses(
    responses: list[Any],
    expected_error_codes: list[int] | None = None,
    schema: dict[str, Any] | None = None,
) -> dict[int, bool | str]:
    """
    Verify invariants for a batch of responses asynchronously.

    Args:
        responses: The responses to verify
        expected_error_codes: Optional list of expected error codes
        schema: Optional schema to validate against

    Returns:
        dict[int, bool | str]: A dictionary mapping response indices to
            verification results (True if valid, error message if invalid)
    """
    import asyncio

    results = {}

    # Guard against None
    if responses is None:
        return results

    # Guard against non-list responses
    if not isinstance(responses, list):
        results[0] = f"Expected a list of responses, got {type(responses)}"
        return results

    # Guard against empty list
    if len(responses) == 0:
        return results

    # Process responses in parallel using asyncio
    async def _verify_single_response(idx, resp):
        try:
            # Use to_thread to avoid blocking the event loop
            await asyncio.to_thread(
                verify_response_invariants, resp, expected_error_codes, schema
            )
            return idx, True
        except InvariantViolation as e:
            return idx, str(e)
        except Exception as e:
            return idx, f"Unexpected error: {str(e)}"

    # Create tasks for all responses
    tasks = [_verify_single_response(i, resp) for i, resp in enumerate(responses)]

    # Gather results
    for idx, result in await asyncio.gather(*tasks, return_exceptions=False):
        results[idx] = result

    return results


def check_state_consistency(
    before_state: dict[str, Any],
    after_state: dict[str, Any],
    expected_changes: list[str] | None = None,
) -> bool:
    """
    Check if the state is consistent before and after an operation.

    Args:
        before_state: State before the operation
        after_state: State after the operation
        expected_changes: Optional list of keys that are expected to change

    Returns:
        bool: True if the state is consistent, False otherwise

    Raises:
        InvariantViolation: If the state is inconsistent
    """
    # Check if all keys in before_state are still in after_state
    for key in before_state:
        if key not in after_state:
            raise InvariantViolation(f"Key '{key}' missing in after_state")

    # Check if any unexpected keys were added
    for key in after_state:
        if key not in before_state:
            if not expected_changes or key not in expected_changes:
                raise InvariantViolation(f"Unexpected key '{key}' added to after_state")

    # Check if any values changed unexpectedly
    for key in before_state:
        if key in after_state:
            if before_state[key] != after_state[key]:
                if not expected_changes or key not in expected_changes:
                    raise InvariantViolation(
                        f"Unexpected change in '{key}': "
                        f"{before_state[key]} -> {after_state[key]}"
                    )

    return True
