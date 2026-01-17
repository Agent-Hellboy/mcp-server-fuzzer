import json
import logging
import uuid
import time
import inspect
from typing import Any, AsyncIterator, TYPE_CHECKING

import httpx

from ..interfaces.driver import TransportDriver
from ..interfaces.behaviors import (
    HttpClientBehavior,
    ResponseParserBehavior,
    LifecycleBehavior,
)

if TYPE_CHECKING:
    from ...fuzz_engine.runtime import ProcessManager, WatchdogConfig
else:
    ProcessManager = Any
    WatchdogConfig = Any
from ...config import (
    JSON_CONTENT_TYPE,
    DEFAULT_HTTP_ACCEPT,
)
from ...safety_system import policy as safety_policy
from ...spec_version import maybe_update_spec_version_from_result


class HttpDriver(
    TransportDriver,
    HttpClientBehavior,
    ResponseParserBehavior,
    LifecycleBehavior,
):
    """
    HTTP transport implementation with reduced code duplication.

    This implementation uses mixins to provide shared functionality,
    addressing the code duplication issues identified in GitHub issue #41.

    Behavior Composition:
    - TransportDriver (ABC): Defines the core interface (send_request, send_raw, etc.)
    - HttpClientBehavior: Provides shared network functionality including:
      - Connection management and HTTP client creation
      - Header preparation and validation
      - Timeout handling and activity tracking
      - Network request validation and error handling
    - ResponseParserBehavior: Handles HTTP-specific response processing:
      - JSON-RPC payload creation and validation
      - HTTP response error handling (status codes, timeouts)
      - Redirect resolution with safety policies
      - Response parsing and serialization checks

    This composition allows HttpDriver to focus on HTTP-specific logic while
    reusing common network and response handling code. Future HTTP transports
    (e.g., WebSocket over HTTP) can inherit from the same mixins to stay consistent.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        auth_headers: dict[str, str | None] | None = None,
        safety_enabled: bool = True,
        process_manager: ProcessManager | None = None,
    ):
        super().__init__()
        self.url = url
        self.timeout = timeout
        self.safety_enabled = safety_enabled
        self.headers = {
            "Accept": DEFAULT_HTTP_ACCEPT,
            "Content-Type": JSON_CONTENT_TYPE,
        }
        self.auth_headers = {
            k: v for k, v in (auth_headers or {}).items() if v is not None
        }

        # Track last activity for process management
        self._last_activity = time.time()

        # Initialize process manager for any subprocesses (like proxy servers)
        self._owns_process_manager = process_manager is None
        if process_manager is None:
            from ...fuzz_engine.runtime import ProcessManager, WatchdogConfig
            watchdog_config = WatchdogConfig(
                check_interval=1.0,
                process_timeout=timeout,
                extra_buffer=5.0,
                max_hang_time=timeout + 10.0,
                auto_kill=True,
            )
            self.process_manager = ProcessManager.from_config(watchdog_config)
        else:
            self.process_manager = process_manager

    def _prepare_headers_with_auth(self, headers: dict[str, str]) -> dict[str, str]:
        """Prepare headers with optional safety sanitization and auth headers."""
        if self.safety_enabled:
            safe_headers = self._prepare_safe_headers(headers)
        else:
            safe_headers = headers.copy()
        # Add auth headers after sanitization (they are user-configured and safe)
        safe_headers.update(self.auth_headers)
        return safe_headers

    async def _update_activity(self):
        """Update last activity timestamp."""
        self._last_activity = time.time()

    def _resolve_redirect_url(self, response: httpx.Response) -> str | None:
        """
        Resolve redirect target for 307/308 while enforcing same-origin and
        host policy.
        """
        if response.status_code not in (307, 308):
            return None
        location = response.headers.get("location")
        if not location:
            return None
        resolved = safety_policy.resolve_redirect_safely(self.url, location)
        if not resolved:
            logging.warning("Refusing redirect that violates policy from %s", self.url)
        return resolved

    async def send_request(
        self, method: str, params: dict[str, Any | None] | None = None
    ) -> Any:
        """Send a JSON-RPC request and return the response.

        Args:
            method: The method name to call
            params: Optional parameters for the method

        Returns:
            Response data from the server

        Raises:
            TransportError: If the request fails or server returns an error
            NetworkError: If network-related issues occur
            PayloadValidationError: If the payload is invalid
        """
        request_id = str(uuid.uuid4())
        payload = self._create_jsonrpc_request(method, params, request_id)

        # Validate payload before sending
        self._validate_jsonrpc_payload(payload, strict=True)
        self._validate_payload_serializable(payload)

        await self._update_activity()

        # Use shared network functionality
        if self.safety_enabled:
            self._validate_network_request(self.url)
        safe_headers = self._prepare_headers_with_auth(self.headers)

        async with self._create_http_client(self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=safe_headers)

            # Handle redirects
            redirect_url = self._resolve_redirect_url(response)
            if redirect_url:
                response = await client.post(
                    redirect_url, json=payload, headers=safe_headers
                )

            # Use shared response handling
            self._handle_http_response_error(response)
            result = self._parse_http_response_json(response)
            if method == "initialize":
                maybe_update_spec_version_from_result(result)
            return result

    async def send_raw(self, payload: dict[str, Any]) -> Any:
        """Send raw payload and return the response.

        Args:
            payload: Raw payload to send (should be JSON-RPC compatible)

        Returns:
            Response data from the server

        Raises:
            TransportError: If the request fails or server returns an error
            NetworkError: If network-related issues occur
            PayloadValidationError: If the payload is invalid
        """
        # Optional validation - can be disabled for fuzzing
        try:
            self._validate_jsonrpc_payload(payload, strict=False)
            self._validate_payload_serializable(payload)
        except Exception as e:
            logging.getLogger(self.__class__.__name__).warning(
                "Payload validation failed: %s", e
            )
            # Continue for fuzzing purposes, but log the issue

        await self._update_activity()

        # Use shared network functionality
        if self.safety_enabled:
            self._validate_network_request(self.url)
        safe_headers = self._prepare_headers_with_auth(self.headers)

        async with self._create_http_client(self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=safe_headers)

            # Handle redirects
            redirect_url = self._resolve_redirect_url(response)
            if redirect_url:
                response = await client.post(
                    redirect_url, json=payload, headers=safe_headers
                )

            # Use shared response handling
            self._handle_http_response_error(response)
            result = self._parse_http_response_json(response)
            if payload.get("method") == "initialize":
                maybe_update_spec_version_from_result(result)
            return result

    async def send_notification(
        self, method: str, params: dict[str, Any | None] | None = None
    ) -> None:
        """Send a JSON-RPC notification (fire-and-forget).

        Args:
            method: The method name to call
            params: Optional parameters for the method

        Raises:
            TransportError: If the request fails
            NetworkError: If network-related issues occur
            PayloadValidationError: If the payload is invalid
        """
        payload = self._create_jsonrpc_notification(method, params)

        # Validate payload before sending
        self._validate_jsonrpc_payload(payload, strict=True)
        self._validate_payload_serializable(payload)

        await self._update_activity()

        # Use shared network functionality
        if self.safety_enabled:
            self._validate_network_request(self.url)
        safe_headers = self._prepare_headers_with_auth(self.headers)

        async with self._create_http_client(self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=safe_headers)

            # Handle redirects
            redirect_url = self._resolve_redirect_url(response)
            if redirect_url:
                response = await client.post(
                    redirect_url, json=payload, headers=safe_headers
                )

            # Use shared response handling (notifications don't expect response data)
            self._handle_http_response_error(response)

    async def get_process_stats(self) -> dict[str, Any]:
        """Get statistics about any managed processes."""
        return await self.process_manager.get_stats()

    async def send_timeout_signal_to_all(
        self, signal_type: str = "timeout"
    ) -> dict[int, bool]:
        """Send timeout signals to all managed processes."""
        return await self.process_manager.send_timeout_signal_to_all(signal_type)

    async def _stream_request(
        self, payload: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a request to the transport.

        Args:
            payload: The request payload

        Yields:
            Response chunks from the transport
        """
        await self._update_activity()

        # Use shared network functionality
        if self.safety_enabled:
            self._validate_network_request(self.url)
        safe_headers = self._prepare_headers_with_auth(self.headers)

        async with self._create_http_client(self.timeout) as client:
            # First request
            response = await client.post(
                self.url, json=payload, headers=safe_headers, stream=True
            )

            # Handle redirect if needed
            redirect_url = self._resolve_redirect_url(response)
            if redirect_url:
                await response.aclose()  # Close the first response
                response = await client.post(
                    redirect_url, json=payload, headers=safe_headers, stream=True
                )

            try:
                self._handle_http_response_error(response)

                # Iterate over streamed lines; support coroutine-returning aiter_lines
                lines_iter = response.aiter_lines()
                if inspect.iscoroutine(lines_iter):
                    lines_iter = await lines_iter

                async for line in lines_iter:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            yield data
                        except json.JSONDecodeError:
                            # Try to handle SSE format using shared parsing
                            if line.startswith("data:"):
                                try:
                                    data = json.loads(line[len("data:") :].strip())
                                    yield data
                                except json.JSONDecodeError:
                                    self._logger.error(
                                        "Failed to parse SSE data as JSON"
                                    )
                                    continue
            finally:
                await response.aclose()  # Ensure response is closed

    async def close(self):
        """Close the transport and cleanup resources."""
        try:
            if hasattr(self, "process_manager") and self._owns_process_manager:
                await self.process_manager.shutdown()
        except Exception as e:
            logging.warning(f"Error shutting down HTTP transport process manager: {e}")

    def __del__(self):
        """Cleanup when the object is destroyed."""
        # Don't try to call async methods in destructor
        # The object will be cleaned up by Python's garbage collector
        pass
