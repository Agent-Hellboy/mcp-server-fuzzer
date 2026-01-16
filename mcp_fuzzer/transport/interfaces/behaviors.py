"""
Transport mixins providing shared functionality to reduce code duplication.

This module contains mixins that provide common functionality for all transport
classes, addressing the code duplication issues identified in GitHub issue #41.
"""

import json
import logging
import time
from abc import ABC
from typing import Any, TypedDict, Iterator, Literal
import httpx

try:
    from typing import NotRequired
except ImportError:  # pragma: no cover
    from typing_extensions import NotRequired

from ...exceptions import TransportError, NetworkError, PayloadValidationError
from ... import spec_guard
from ...safety_system import policy as safety_policy
from .states import DriverState


class JSONRPCRequest(TypedDict):
    """Type definition for JSON-RPC request structure."""

    jsonrpc: Literal["2.0"]
    method: str
    params: NotRequired[list[Any] | dict[str, Any]]
    id: str | int | None


class JSONRPCNotification(TypedDict):
    """Type definition for JSON-RPC notification structure."""

    jsonrpc: Literal["2.0"]
    method: str
    params: NotRequired[list[Any] | dict[str, Any]]


class JSONRPCErrorObject(TypedDict):
    """Type definition for JSON-RPC error object."""

    code: int
    message: str
    data: NotRequired[Any]


class JSONRPCSuccessResponse(TypedDict):
    """Type definition for JSON-RPC success response."""

    jsonrpc: Literal["2.0"]
    result: Any
    id: str | int | None


class JSONRPCErrorResponse(TypedDict):
    """Type definition for JSON-RPC error response."""

    jsonrpc: Literal["2.0"]
    error: JSONRPCErrorObject
    id: str | int | None


JSONRPCResponse = JSONRPCSuccessResponse | JSONRPCErrorResponse


class DriverBaseBehavior(ABC):
    """Base behavior providing common transport functionality."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = logging.getLogger(self.__class__.__name__)

    def _create_jsonrpc_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        request_id: str | int | None = None,
    ) -> JSONRPCRequest:
        """Create a JSON-RPC request payload.

        Args:
            method: The method name to call
            params: Optional parameters for the method
            request_id: Optional request ID (generated if not provided)

        Returns:
            JSON-RPC request payload

        Raises:
            PayloadValidationError: If method is empty or invalid
        """
        if not method or not isinstance(method, str):
            raise PayloadValidationError("Method must be a non-empty string")

        payload: JSONRPCRequest = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }

        if request_id is not None:
            payload["id"] = request_id

        return payload

    def _create_jsonrpc_notification(
        self, method: str, params: dict[str, Any] | None = None
    ) -> JSONRPCNotification:
        """Create a JSON-RPC notification payload.

        Args:
            method: The method name to call
            params: Optional parameters for the method

        Returns:
            JSON-RPC notification payload

        Raises:
            PayloadValidationError: If method is empty or invalid
        """
        if not method or not isinstance(method, str):
            raise PayloadValidationError("Method must be a non-empty string")

        return {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }

    def _validate_jsonrpc_payload(
        self, payload: dict[str, Any], strict: bool = False
    ) -> None:
        """Validate JSON-RPC 2.0 payload structure.

        Args:
            payload: The payload to validate
            strict: If True, validates all required fields

        Raises:
            PayloadValidationError: If payload is invalid
        """
        if not isinstance(payload, dict):
            raise PayloadValidationError("Payload must be a dictionary")

        if payload.get("jsonrpc") != "2.0":
            raise PayloadValidationError("Invalid jsonrpc version")

        is_request_like = "method" in payload
        has_result = "result" in payload
        has_error = "error" in payload

        if is_request_like:
            if not isinstance(payload["method"], str) or not payload["method"]:
                raise PayloadValidationError("'method' must be a non-empty string")
            if "params" in payload and not isinstance(payload["params"], (list, dict)):
                raise PayloadValidationError("'params' must be array or object")
            if (
                "id" in payload
                and not isinstance(payload["id"], (str, int))
                and payload["id"] is not None
            ):
                raise PayloadValidationError("'id' must be string, number, or null")
            if strict and "id" not in payload:
                # In strict mode treat request-like payloads without id as invalid
                raise PayloadValidationError("Missing required field: id")
        else:
            if has_result == has_error:
                raise PayloadValidationError(
                    "Response must have exactly one of result or error"
                )
            if "id" not in payload:
                raise PayloadValidationError("Response must include 'id'")
            if not isinstance(payload["id"], (str, int)) and payload["id"] is not None:
                raise PayloadValidationError("'id' must be string, number, or null")
            if has_error:
                err = payload["error"]
                if (
                    not isinstance(err, dict)
                    or "code" not in err
                    or "message" not in err
                ):
                    raise PayloadValidationError("Invalid error object")
                if not isinstance(err["code"], int) or not isinstance(
                    err["message"], str
                ):
                    raise PayloadValidationError("Invalid error fields")

    def _validate_payload_serializable(self, payload: dict[str, Any]) -> None:
        """Validate that payload can be serialized to JSON.

        Args:
            payload: The payload to validate

        Raises:
            PayloadValidationError: If payload cannot be serialized
        """
        try:
            json.dumps(payload)
        except (TypeError, ValueError) as e:
            raise PayloadValidationError(f"Payload is not JSON serializable: {e}")

    def _log_error_and_raise(self, message: str, error_data: Any = None) -> None:
        """Log error and raise TransportError with consistent formatting.

        Args:
            message: Error message to log and include in exception
            error_data: Optional error data to include in log

        Raises:
            TransportError: Always raises with the provided message
        """
        if error_data:
            self._logger.error("%s: %s", message, error_data)
        else:
            self._logger.error(message)
        raise TransportError(message)

    def _extract_result_from_response(
        self, data: Any, normalize_non_dict: bool = True
    ) -> Any:
        """Extract result from JSON-RPC response.

        Args:
            data: Response data to process
            normalize_non_dict: If True, wraps non-dict responses in {"result": data}

        Returns:
            Extracted result data

        Raises:
            TransportError: If response contains an error
        """
        if isinstance(data, dict):
            if "error" in data:
                error_msg = f"Server error: {data['error']}"
                self._log_error_and_raise(error_msg, data["error"])

            return data.get("result", data)

        if normalize_non_dict:
            return {"result": data}

        return data


class HttpClientBehavior(DriverBaseBehavior):
    """Behavior mix-in for network-based transports (HTTP, SSE, WebSocket)."""

    def _validate_network_request(self, url: str) -> None:
        """Validate network request against safety policies.

        Args:
            url: URL to validate

        Raises:
            NetworkError: If URL violates safety policies
        """
        if not safety_policy.is_host_allowed(url):
            raise NetworkError(
                "Network to non-local host is disallowed by safety policy"
            )

    def _prepare_safe_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Prepare headers with safety sanitization.

        Args:
            headers: Headers to sanitize

        Returns:
            Sanitized headers safe for network transmission
        """
        return safety_policy.sanitize_headers(headers)

    def _create_http_client(self, timeout: float) -> httpx.AsyncClient:
        """Create configured HTTP client.

        Args:
            timeout: Request timeout in seconds

        Returns:
            Configured httpx.AsyncClient
        """
        return httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    def _handle_http_response_error(self, response: httpx.Response) -> None:
        """Handle HTTP response errors with consistent logging.

        Args:
            response: HTTP response to check

        Raises:
            NetworkError: If response indicates an error
        """
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
            self._logger.error(error_msg)
            raise NetworkError(error_msg)

    def _parse_http_response_json(
        self, response: httpx.Response, fallback_to_sse: bool = True
    ) -> dict[str, Any]:
        """Parse HTTP response as JSON with SSE fallback.

        Args:
            response: HTTP response to parse
            fallback_to_sse: If True, attempts SSE parsing on JSON failure

        Returns:
            Parsed JSON data

        Raises:
            TransportError: If parsing fails
        """
        try:
            data = response.json()
            return self._extract_result_from_response(data)
        except json.JSONDecodeError:
            if not fallback_to_sse:
                raise TransportError("Response is not valid JSON")

            # Try SSE format parsing
            self._logger.debug("Response is not JSON, trying to parse as SSE")
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[len("data:") :].strip())
                        return self._extract_result_from_response(data)
                    except json.JSONDecodeError:
                        self._logger.error("Failed to parse SSE data line as JSON")
                        continue
                elif line.strip():  # Non-empty non-data line
                    try:
                        data = json.loads(line)
                        return self._extract_result_from_response(data)
                    except json.JSONDecodeError:
                        continue

            raise TransportError("No valid JSON data found in response")


class ResponseParserBehavior(DriverBaseBehavior):
    """Behavior providing shared response parsing functionality."""

    def _flush_sse_buffer(self, buffer: list[str]) -> dict[str, Any] | None:
        event_text = "\n".join(buffer)
        parsed = self.parse_sse_event(event_text)
        return parsed

    def parse_sse_event(self, event_text: str) -> dict[str, Any | None]:
        """Parse a single SSE event text into a JSON object.

        The input may contain multiple lines such as "event:", "data:", or
        control fields like "retry:". Only the JSON payload from one or more
        "data:" lines is considered. Multiple data lines are concatenated.

        Args:
            event_text: SSE event text to parse

        Returns:
            Parsed JSON object or None if no data payload

        Raises:
            json.JSONDecodeError: If data payload is present but cannot be
                parsed as JSON
        """
        if not event_text:
            return None

        data_parts = []
        warnings = spec_guard.check_sse_event_text(event_text)
        if warnings:
            for warning in warnings:
                self._logger.warning(
                    "SSE spec warning (%s): %s",
                    warning.get("id"),
                    warning.get("message"),
                )
        for raw_line in event_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("data:"):
                data_parts.append(line[len("data:") :].strip())
            # Ignore other fields such as "event:" and "retry:"

        if not data_parts:
            return None

        data_str = "\n".join(data_parts)
        # May raise JSONDecodeError if invalid, as intended by tests
        return json.loads(data_str)

    def parse_streaming_response(
        self, lines: list[str], buffer_size: int = 1000
    ) -> Iterator[dict[str, Any]]:
        """Parse streaming response lines and yield JSON objects.

        Args:
            lines: List of response lines to parse
            buffer_size: Maximum buffer size to prevent memory issues

        Yields:
            Parsed JSON objects from the stream
        """
        buffer = []
        for line in lines:
            if not line.strip():
                # Empty line marks end of event
                if buffer:
                    try:
                        parsed = self._flush_sse_buffer(buffer)
                        if parsed is not None:
                            yield parsed
                    except json.JSONDecodeError:
                        self._logger.error("Failed to parse SSE event payload as JSON")
                    finally:
                        buffer = []
                continue

            buffer.append(line)

            # Prevent memory issues with large buffers
            if len(buffer) > buffer_size:
                self._logger.warning("Buffer size exceeded, clearing buffer")
                buffer = []

        # Process any remaining buffered data
        if buffer:
            try:
                parsed = self._flush_sse_buffer(buffer)
                if parsed is not None:
                    yield parsed
            except json.JSONDecodeError:
                self._logger.error("Failed to parse SSE event payload as JSON")


class LifecycleBehavior(DriverBaseBehavior):
    """Behavior providing connection lifecycle management and activity tracking.

    This mixin adds connection state management, activity tracking for timeouts,
    and resource cleanup patterns that can be used by all transport types.
    """

    def __init__(self, *args, **kwargs):
        """Initialize connection lifecycle management."""
        super().__init__(*args, **kwargs)
        self._connection_state = DriverState.INIT
        self._last_activity = time.time()
        self._connection_start_time: float | None = None
        self._connection_end_time: float | None = None
        self._activity_callbacks: list = []

    @property
    def connection_state(self) -> DriverState:
        """Get current connection state."""
        return self._connection_state

    @property
    def last_activity(self) -> float:
        """Get timestamp of last activity."""
        return self._last_activity

    @property
    def connection_duration(self) -> float | None:
        """Get duration of connection in seconds, or None if not connected."""
        if self._connection_start_time is None:
            return None
        end_time = self._connection_end_time or time.time()
        return end_time - self._connection_start_time

    def is_connected(self) -> bool:
        """Check if transport is in connected state."""
        return self._connection_state == DriverState.CONNECTED

    def is_closed(self) -> bool:
        """Check if transport is in closed state."""
        return self._connection_state == DriverState.CLOSED

    def is_error(self) -> bool:
        """Check if transport is in error state."""
        return self._connection_state == DriverState.ERROR

    def _touch_activity(self) -> None:
        """Update the last activity timestamp."""
        self._last_activity = time.time()

        # Notify activity callbacks
        for callback in self._activity_callbacks:
            try:
                callback(self._last_activity)
            except Exception as e:
                self._logger.warning(f"Activity callback failed: {e}")

    def _set_connection_state(self, state: DriverState) -> None:
        """Set the connection state.

        Args:
            state: New connection state
        """
        old_state = self._connection_state
        self._connection_state = state

        # Track connection timing
        if state == DriverState.CONNECTED and old_state != DriverState.CONNECTED:
            self._connection_start_time = time.time()
            self._connection_end_time = None
        elif (
            state in (DriverState.CLOSED, DriverState.ERROR)
            and old_state == DriverState.CONNECTED
        ):
            self._connection_end_time = time.time()

        self._logger.debug(
            f"Connection state changed: {old_state.value} -> {state.value}"
        )

    def register_activity_callback(self, callback) -> None:
        """Register a callback to be notified on activity updates.

        Args:
            callback: Callable that takes timestamp as argument
        """
        self._activity_callbacks.append(callback)

    def time_since_last_activity(self) -> float:
        """Get time in seconds since last activity."""
        return time.time() - self._last_activity

    async def _lifecycle_connect(self) -> None:
        """Mark connection as starting and update state."""
        self._set_connection_state(DriverState.CONNECTING)
        self._touch_activity()

    async def _lifecycle_connected(self) -> None:
        """Mark connection as established and update state."""
        self._set_connection_state(DriverState.CONNECTED)
        self._touch_activity()

    async def _lifecycle_disconnect(self) -> None:
        """Mark connection as disconnecting and update state."""
        if self._connection_state == DriverState.CONNECTED:
            self._set_connection_state(DriverState.DISCONNECTING)
        self._touch_activity()

    async def _lifecycle_closed(self) -> None:
        """Mark connection as closed and update state."""
        self._set_connection_state(DriverState.CLOSED)
        self._touch_activity()

    async def _lifecycle_error(self, error: Exception | None = None) -> None:
        """Mark connection as in error state.

        Args:
            error: Optional exception that caused the error
        """
        self._set_connection_state(DriverState.ERROR)
        if error:
            self._logger.error(f"Connection error: {error}")
        self._touch_activity()

    async def _cleanup_resources(self) -> None:
        """Cleanup any resources held by the transport.

        Subclasses should override this to implement specific cleanup logic.
        """
        pass
