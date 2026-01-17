"""Stream HTTP driver with SSE support and session headers.

This transport implementation uses mixins to reduce code duplication significantly
(~150 lines), sharing network validation, header handling, and response parsing
with other HTTP-based transports.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator

import httpx

from ..interfaces.driver import TransportDriver
from ..interfaces.behaviors import (
    HttpClientBehavior,
    ResponseParserBehavior,
    NetworkError as DriverNetworkError,
)
from ..interfaces.server_requests import (
    build_sampling_create_message_response,
    is_server_request,
)
from ...config import (
    DEFAULT_PROTOCOL_VERSION,
    CONTENT_TYPE_HEADER,
    JSON_CONTENT_TYPE,
    SSE_CONTENT_TYPE,
    MCP_SESSION_ID_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    DEFAULT_HTTP_ACCEPT,
)
from ...types import (
    HTTP_ACCEPTED,
    HTTP_REDIRECT_TEMPORARY,
    HTTP_REDIRECT_PERMANENT,
    HTTP_NOT_FOUND,
    DEFAULT_TIMEOUT,
    RETRY_DELAY,
)
from ...exceptions import TransportError
from ...safety_system.policy import resolve_redirect_safely
from ...spec_version import maybe_update_spec_version

# Back-compat local aliases (referenced by tests)
MCP_SESSION_ID = MCP_SESSION_ID_HEADER
MCP_PROTOCOL_VERSION = MCP_PROTOCOL_VERSION_HEADER
CONTENT_TYPE = CONTENT_TYPE_HEADER
JSON_CT = JSON_CONTENT_TYPE
SSE_CT = SSE_CONTENT_TYPE


class StreamHttpDriver(TransportDriver, HttpClientBehavior, ResponseParserBehavior):
    """Streamable HTTP transport with MCP session management.

    This mirrors the MCP SDK's StreamableHTTP semantics for fuzzing:
    - Sends Accept: application/json, text/event-stream
    - Parses JSON or SSE responses
    - Tracks and propagates mcp-session-id and mcp-protocol-version headers

    Mixin Composition:
    - TransportDriver: Core interface
    - HttpClientBehavior: Network validation, header sanitization, HTTP client
    - ResponseParserBehavior: Response parsing (JSON and SSE)
    """

    def __init__(
        self,
        url: str,
        timeout: float = DEFAULT_TIMEOUT,
        auth_headers: dict[str, str | None] = None,
        safety_enabled: bool = True,
    ):
        """Initialize streamable HTTP transport.

        Args:
            url: Server URL
            timeout: Request timeout in seconds
            auth_headers: Optional authentication headers
        """
        super().__init__()
        self.url = url
        self.timeout = timeout
        self.safety_enabled = safety_enabled
        self.headers: dict[str, str] = {
            "Accept": DEFAULT_HTTP_ACCEPT,
            "Content-Type": JSON_CT,
        }
        self.auth_headers = {
            k: v for k, v in (auth_headers or {}).items() if v is not None
        }

        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self._initialized: bool = False
        self._init_lock: asyncio.Lock = asyncio.Lock()
        self._initializing: bool = False

    def _prepare_headers_with_auth(self, headers: dict[str, str]) -> dict[str, str]:
        """Prepare headers with optional safety sanitization and auth headers."""
        if self.safety_enabled:
            safe_headers = self._prepare_safe_headers(headers)
        else:
            safe_headers = headers.copy()
        # Add auth headers after sanitization (they are user-configured and safe)
        safe_headers.update(self.auth_headers)
        return safe_headers

    def _prepare_headers(self) -> dict[str, str]:
        """Prepare headers with session information.

        Returns:
            Headers dict with session information
        """
        headers = dict(self.headers)
        if self.session_id:
            headers[MCP_SESSION_ID] = self.session_id
        if self.protocol_version:
            headers[MCP_PROTOCOL_VERSION] = self.protocol_version
        return headers

    def _maybe_extract_session_headers(self, response: httpx.Response) -> None:
        """Extract session ID from response headers.

        Args:
            response: HTTP response to extract from
        """
        sid = response.headers.get(MCP_SESSION_ID)
        if sid:
            self.session_id = sid
            self._logger.debug("Received session id: %s", sid)

        protocol_header = response.headers.get(MCP_PROTOCOL_VERSION)
        if protocol_header:
            self.protocol_version = protocol_header
            self._logger.debug("Received protocol version header: %s", protocol_header)
            maybe_update_spec_version(protocol_header)

    def _maybe_extract_protocol_version_from_result(self, result: Any) -> None:
        """Extract protocol version from result.

        Args:
            result: Result dict that may contain protocolVersion
        """
        try:
            if isinstance(result, dict) and "protocolVersion" in result:
                pv = result.get("protocolVersion")
                if pv is not None:
                    self.protocol_version = str(pv)
                    self._logger.debug("Negotiated protocol version: %s", pv)
                    maybe_update_spec_version(pv)
        except Exception:
            pass

    def _resolve_redirect(self, response: httpx.Response) -> str | None:
        """Resolve redirect target with safety checks.

        Args:
            response: HTTP response to check for redirects

        Returns:
            Resolved redirect URL or None
        """
        redirect_codes = (HTTP_REDIRECT_TEMPORARY, HTTP_REDIRECT_PERMANENT)
        if response.status_code not in redirect_codes:
            return None

        location = response.headers.get("location")
        if not location and not self.url.endswith("/"):
            location = self.url + "/"
        if not location:
            return None

        resolved = resolve_redirect_safely(self.url, location)
        if not resolved:
            self._logger.warning(
                "Refusing redirect that violates policy from %s", self.url
            )
        return resolved

    def _extract_content_type(self, response: httpx.Response) -> str:
        """Extract content type from response.

        Args:
            response: HTTP response

        Returns:
            Content type string (lowercase)
        """
        return response.headers.get(CONTENT_TYPE, "").lower()

    async def _parse_sse_response_for_result(self, response: httpx.Response) -> Any:
        """Parse SSE stream and return first JSON-RPC response/error.

        Args:
            response: HTTP response with SSE content

        Returns:
            First parsed result from SSE stream
        """
        # Basic SSE parser: accumulate fields until blank line
        event: dict[str, Any] = {"event": "message", "data": []}
        async for line in response.aiter_lines():
            if line == "":
                # dispatch event
                data_text = "\n".join(event.get("data", []))
                try:
                    payload = json.loads(data_text) if data_text else None
                except json.JSONDecodeError:
                    payload = None

                if isinstance(payload, dict):
                    if is_server_request(payload):
                        handled = await self._handle_server_request(payload)
                        if handled:
                            event = {"event": "message", "data": []}
                            continue
                    # JSON-RPC error passthrough
                    if "error" in payload:
                        return payload
                    # JSON-RPC response with result
                    if "result" in payload:
                        result = payload["result"]
                        # For initialize, extract protocolVersion if present
                        self._maybe_extract_protocol_version_from_result(result)
                        return result
                # reset event
                event = {"event": "message", "data": []}
                continue

            if line.startswith(":"):
                # Comment, ignore
                continue
            if line.startswith("event:"):
                event["event"] = line[len("event:") :].strip()
                continue
            if line.startswith("id:"):
                event["id"] = line[len("id:") :].strip()
                continue
            if line.startswith("data:"):
                event.setdefault("data", []).append(line[len("data:") :].lstrip())
                continue
            # Unknown field: ignore per SSE spec
            continue

        # If we exit loop without a response, return None
        return None

    async def _handle_server_request(self, payload: dict[str, Any]) -> bool:
        """Handle server->client requests delivered over SSE."""
        method = payload.get("method")
        request_id = payload.get("id")
        if method == "sampling/createMessage" and request_id is not None:
            response_payload = build_sampling_create_message_response(request_id)
            await self._send_client_response(response_payload)
            return True
        return False

    async def _send_client_response(self, payload: dict[str, Any]) -> None:
        """Send a JSON-RPC response back to the server."""
        headers = self._prepare_headers()

        if self.safety_enabled:
            self._validate_network_request(self.url)
        safe_headers = self._prepare_headers_with_auth(headers)

        async with self._create_http_client(self.timeout) as client:
            response = await self._post_with_retries(
                client, self.url, payload, safe_headers
            )
            self._maybe_extract_session_headers(response)
            redirect_url = self._resolve_redirect(response)
            if redirect_url:
                response = await self._post_with_retries(
                    client, redirect_url, payload, safe_headers
                )
                self._maybe_extract_session_headers(response)
            self._handle_http_response_error(response)

    async def _post_with_retries(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        retries: int = 2,
    ) -> httpx.Response:
        """POST with exponential backoff for transient network errors.

        Args:
            client: HTTP client
            url: URL to post to
            payload: JSON payload
            headers: Request headers
            retries: Maximum retry attempts

        Returns:
            HTTP response

        Raises:
            TransportError: If all retries fail
        """
        delay = RETRY_DELAY
        attempt = 0
        while True:
            try:
                return await client.post(url, json=payload, headers=headers)
            except (
                httpx.ConnectError,
                httpx.ReadTimeout,
                httpx.WriteTimeout,
                httpx.PoolTimeout,
            ) as e:
                # Only retry for safe, idempotent, or initialization-like methods
                method = None
                try:
                    method = payload.get("method")
                except Exception:
                    pass
                safe = method in (
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "prompts/list",
                    "resources/list",
                )
                if attempt >= retries or not safe:
                    context = {
                        "url": url,
                        "error_type": type(e).__name__,
                        "attempts": attempt + 1,
                    }
                    if method:
                        context["method"] = method
                    raise TransportError(
                        "Connection failed while contacting server", context=context
                    ) from e
                self._logger.debug(
                    "POST retry %d for %s due to %s",
                    attempt + 1,
                    url,
                    type(e).__name__,
                )
                await asyncio.sleep(delay)
                delay *= 2
                attempt += 1

    async def send_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> Any:
        """Send a JSON-RPC request and return the response.

        Args:
            method: Method name
            params: Optional parameters

        Returns:
            Response from server
        """
        request_id = str(asyncio.get_running_loop().time())
        payload = self._create_jsonrpc_request(method, params, request_id)
        return await self.send_raw(payload)

    async def send_raw(self, payload: dict[str, Any]) -> Any:
        """Send raw payload and return the response.

        Args:
            payload: Raw JSON-RPC payload

        Returns:
            Response from server

        Raises:
            TransportError: If request fails
        """
        # Ensure MCP initialization handshake once per session
        try:
            method = payload.get("method")
        except AttributeError:
            method = None
        if not self._initialized and method != "initialize":
            async with self._init_lock:
                if not self._initialized and not self._initializing:
                    self._initializing = True
                    try:
                        await self._do_initialize()
                    finally:
                        self._initializing = False

        headers = self._prepare_headers()

        # Use shared network functionality
        if self.safety_enabled:
            self._validate_network_request(self.url)
        safe_headers = self._prepare_headers_with_auth(headers)

        async with self._create_http_client(self.timeout) as client:
            response = await self._post_with_retries(
                client, self.url, payload, safe_headers
            )

            # Handle redirect
            redirect_url = self._resolve_redirect(response)
            if redirect_url:
                # Follow at most one redirect to avoid unbounded chains.
                self._logger.debug("Following redirect to %s", redirect_url)
                response = await self._post_with_retries(
                    client, redirect_url, payload, safe_headers
                )

            # Update session headers if available
            self._maybe_extract_session_headers(response)

            # Handle special status codes
            if response.status_code == HTTP_ACCEPTED:
                return {}
            if response.status_code == HTTP_NOT_FOUND:
                raise TransportError(
                    "Session terminated or endpoint not found",
                    context={"url": self.url, "status": response.status_code},
                )

            # Use shared error handling
            try:
                self._handle_http_response_error(response)
            except DriverNetworkError as exc:
                context = {
                    "url": self.url,
                    "status": response.status_code,
                }
                raise TransportError(str(exc), context=context) from exc

            ct = self._extract_content_type(response)

            if ct.startswith(JSON_CT):
                # Use shared JSON parsing (returns JSON-RPC result payload)
                data = self._parse_http_response_json(response, fallback_to_sse=False)

                self._maybe_extract_protocol_version_from_result(data)
                if method == "initialize":
                    self._initialized = True

                return data if isinstance(data, dict) else {"result": data}

            if ct.startswith(SSE_CT):
                parsed = await self._parse_sse_response_for_result(response)
                if method == "initialize":
                    self._initialized = True
                if parsed is None:
                    return {}
                return self._extract_result_from_response(parsed)

            raise TransportError(
                f"Unexpected content type: {ct}",
                context={"url": self.url, "content_type": ct},
            )

    async def send_notification(
        self, method: str, params: dict[str, Any] | None = None
    ) -> None:
        """Send a JSON-RPC notification.

        Args:
            method: Method name
            params: Optional parameters
        """
        payload = self._create_jsonrpc_notification(method, params)
        headers = self._prepare_headers()

        # Use shared network functionality
        if self.safety_enabled:
            self._validate_network_request(self.url)
        safe_headers = self._prepare_headers_with_auth(headers)

        async with self._create_http_client(self.timeout) as client:
            response = await self._post_with_retries(
                client, self.url, payload, safe_headers
            )
            redirect_url = self._resolve_redirect(response)
            if redirect_url:
                # Follow at most one redirect to avoid unbounded chains.
                response = await self._post_with_retries(
                    client, redirect_url, payload, safe_headers
                )
            self._handle_http_response_error(response)

    async def _do_initialize(self) -> None:
        """Perform MCP initialize + initialized notification."""
        init_payload = {
            "jsonrpc": "2.0",
            "id": str(asyncio.get_running_loop().time()),
            "method": "initialize",
            "params": {
                "protocolVersion": self.protocol_version or DEFAULT_PROTOCOL_VERSION,
                "capabilities": {
                    "elicitation": {},
                    "experimental": {},
                    "sampling": {},
                },
                "clientInfo": {"name": "mcp-fuzzer", "version": "0.1"},
            },
        }
        try:
            await self.send_raw(init_payload)
            self._initialized = True
            # Send initialized notification (best-effort)
            try:
                await self.send_notification("notifications/initialized", {})
            except Exception:
                pass
        except Exception:
            # Surface the failure; leave _initialized False
            raise

    async def _stream_request(
        self, payload: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a request and yield parsed data lines.

        Args:
            payload: Request payload

        Yields:
            Parsed JSON objects from stream
        """
        headers = self._prepare_headers()

        # Use shared network functionality
        if self.safety_enabled:
            self._validate_network_request(self.url)
        safe_headers = self._prepare_headers_with_auth(headers)

        async with self._create_http_client(self.timeout) as client:
            async with client.stream(
                "POST", self.url, json=payload, headers=safe_headers
            ) as response:
                redirect_url = self._resolve_redirect(response)
                if redirect_url:
                    # Follow at most one redirect to avoid unbounded chains.
                    await response.aclose()
                    async with client.stream(
                        "POST", redirect_url, json=payload, headers=safe_headers
                    ) as redirected:
                        async for item in self._yield_streamed_lines(redirected):
                            yield item
                    return

                async for item in self._yield_streamed_lines(response):
                    yield item

    async def _yield_streamed_lines(
        self, response: httpx.Response
    ) -> AsyncIterator[dict[str, Any]]:
        """Parse streaming response lines into JSON objects."""
        self._handle_http_response_error(response)
        # Update session headers from streaming response
        self._maybe_extract_session_headers(response)

        async for line in response.aiter_lines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                yield data
            except json.JSONDecodeError:
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[len("data:") :].strip())
                        yield data
                    except json.JSONDecodeError:
                        self._logger.error("Failed to parse SSE data as JSON")
