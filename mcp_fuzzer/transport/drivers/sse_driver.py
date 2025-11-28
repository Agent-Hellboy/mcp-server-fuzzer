"""Server-Sent Events (SSE) transport implementation.

This transport implementation uses mixins to provide shared functionality,
reducing code duplication significantly (~100 lines).
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from ..interfaces.driver import TransportDriver
from ..interfaces.behaviors import HttpClientBehavior, ResponseParserBehavior
from ...exceptions import TransportError


class SseDriver(TransportDriver, HttpClientBehavior, ResponseParserBehavior):
    """SSE transport implementation using mixins.

    This implementation leverages mixins to share common network and parsing
    functionality with other HTTP-based transports, reducing code duplication.

    Mixin Composition:
    - TransportDriver: Core interface
    - HttpClientBehavior: Network validation, header sanitization, HTTP client
    - ResponseParserBehavior: SSE event parsing
    """

    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        auth_headers: dict[str, str | None] | None = None,
    ):
        """Initialize SSE transport.

        Args:
            url: Server URL for SSE connection
            timeout: Request timeout in seconds
            auth_headers: Optional authentication headers
        """
        super().__init__()
        self.url = url
        self.timeout = timeout
        self.headers = {
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        }
        if auth_headers:
            self.headers.update(auth_headers)

    async def send_request(
        self, method: str, params: dict[str, Any | None] | None = None
    ) -> dict[str, Any]:
        """SSE transport does not support non-streaming requests.

        Use stream-based APIs instead (e.g., _stream_request).

        Raises:
            NotImplementedError: SSE transport only supports streaming
        """
        raise NotImplementedError("SseDriver does not support send_request")

    async def send_raw(self, payload: dict[str, Any]) -> Any:
        """Send a raw payload and return the first SSE response.

        Args:
            payload: JSON-RPC payload to send

        Returns:
            Parsed response from server

        Raises:
            TransportError: If request fails or no valid response
            ServerError: If server returns an error
        """
        # Use shared network functionality
        self._validate_network_request(self.url)
        safe_headers = self._prepare_safe_headers(self.headers)

        async with self._create_http_client(self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=safe_headers)
            self._handle_http_response_error(response)

            # Process response text as SSE stream
            buffer: list[str] = []

            def flush_once() -> dict[str, Any] | None:
                """Flush buffer and parse as SSE event."""
                if not buffer:
                    return None
                event_text = "\n".join(buffer)
                buffer.clear()
                try:
                    data = self.parse_sse_event(event_text)
                except json.JSONDecodeError:
                    self._logger.error("Failed to parse SSE data as JSON")
                    return None
                if data is None:
                    return None
                # Use shared result extraction
                return self._extract_result_from_response(data)

            # Parse response text line by line
            for line in response.text.splitlines():
                if not line.strip():
                    result = flush_once()
                    if result is not None:
                        return result
                    continue
                buffer.append(line)

            # Flush remaining buffer
            result = flush_once()
            if result is not None:
                return result

            # Try parsing entire response as JSON
            try:
                data = response.json()
                return self._extract_result_from_response(data)
            except json.JSONDecodeError:
                pass

            raise TransportError(
                "No valid SSE response received",
                context={"url": self.url},
            )

    async def send_notification(
        self, method: str, params: dict[str, Any | None] | None = None
    ) -> None:
        """Send a JSON-RPC notification via SSE.

        Args:
            method: Method name
            params: Optional parameters

        Raises:
            TransportError: If notification fails to send
        """
        payload = self._create_jsonrpc_notification(method, params)

        # Use shared network functionality
        self._validate_network_request(self.url)
        safe_headers = self._prepare_safe_headers(self.headers)

        async with self._create_http_client(self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=safe_headers)
            self._handle_http_response_error(response)

    async def _stream_request(
        self, payload: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a request via SSE and yield parsed events.

        Args:
            payload: Request payload with method/params

        Yields:
            Parsed JSON objects from SSE events

        Raises:
            TransportError: If streaming fails
        """
        # Use shared network functionality
        self._validate_network_request(self.url)
        safe_headers = self._prepare_safe_headers(self.headers)

        async with self._create_http_client(self.timeout) as client:
            async with client.stream(
                "POST",
                self.url,
                json=payload,
                headers=safe_headers,
            ) as response:
                self._handle_http_response_error(response)

                chunks = response.aiter_text()
                buffer = []  # Buffer to accumulate SSE event data

                # Support both async and sync iterables (tests may provide a list)
                if hasattr(chunks, "__aiter__"):
                    async for chunk in chunks:  # type: ignore[func-returns-value]
                        if not chunk:
                            continue

                        # Process each line in the chunk
                        for line in chunk.splitlines():
                            if line.strip():
                                # Non-empty line: add to current event buffer
                                buffer.append(line)
                            else:
                                # Empty line: marks end of an event, process the buffer
                                if buffer:
                                    try:
                                        event_text = "\n".join(buffer)
                                        parsed = self.parse_sse_event(event_text)
                                        if parsed is not None:
                                            yield parsed
                                    except json.JSONDecodeError:
                                        self._logger.error(
                                            "Failed to parse SSE event payload as JSON"
                                        )
                                    finally:
                                        buffer = []  # Clear buffer for next event
                else:
                    for chunk in chunks:  # type: ignore[assignment]
                        if not chunk:
                            continue

                        # Process each line in the chunk
                        for line in chunk.splitlines():
                            if line.strip():
                                # Non-empty line: add to current event buffer
                                buffer.append(line)
                            else:
                                # Empty line: marks end of an event, process the buffer
                                if buffer:
                                    try:
                                        event_text = "\n".join(buffer)
                                        parsed = self.parse_sse_event(event_text)
                                        if parsed is not None:
                                            yield parsed
                                    except json.JSONDecodeError:
                                        self._logger.error(
                                            "Failed to parse SSE event payload as JSON"
                                        )
                                    finally:
                                        buffer = []  # Clear buffer for next event

                # Process any remaining buffered data at the end of the stream
                if buffer:
                    try:
                        event_text = "\n".join(buffer)
                        parsed = self.parse_sse_event(event_text)
                        if parsed is not None:
                            yield parsed
                    except json.JSONDecodeError:
                        self._logger.error("Failed to parse SSE event payload as JSON")
