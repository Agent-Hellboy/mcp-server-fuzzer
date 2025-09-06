import asyncio
import json
import logging
from typing import Any, Dict, Optional

import httpx
from ..config import (
    DEFAULT_PROTOCOL_VERSION,
    CONTENT_TYPE_HEADER,
    JSON_CONTENT_TYPE,
    SSE_CONTENT_TYPE,
    MCP_SESSION_ID_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    DEFAULT_HTTP_ACCEPT,
)
from ..types import (
    HTTP_ACCEPTED,
    HTTP_REDIRECT_TEMPORARY,
    HTTP_REDIRECT_PERMANENT,
    HTTP_NOT_FOUND,
    DEFAULT_TIMEOUT,
    RETRY_DELAY,
)

from .base import TransportProtocol
from ..safety_system.policy import (
    is_host_allowed,
    resolve_redirect_safely,
    sanitize_headers,
)


# Back-compat local aliases (referenced by tests)
MCP_SESSION_ID = MCP_SESSION_ID_HEADER
MCP_PROTOCOL_VERSION = MCP_PROTOCOL_VERSION_HEADER
CONTENT_TYPE = CONTENT_TYPE_HEADER
JSON_CT = JSON_CONTENT_TYPE
SSE_CT = SSE_CONTENT_TYPE


class StreamableHTTPTransport(TransportProtocol):
    """Streamable HTTP transport with basic SSE support and session headers.

    This mirrors the MCP SDK's StreamableHTTP semantics enough for fuzzing:
    - Sends Accept: application/json, text/event-stream
    - Parses JSON or SSE responses
    - Tracks and propagates mcp-session-id and mcp-protocol-version headers
    """

    def __init__(
        self,
        url: str,
        timeout: float = DEFAULT_TIMEOUT,
        auth_headers: Optional[Dict[str, str]] = None,
    ):
        self.url = url
        self.timeout = timeout
        self.headers: Dict[str, str] = {
            "Accept": DEFAULT_HTTP_ACCEPT,
            "Content-Type": JSON_CT,
        }
        if auth_headers:
            self.headers.update(auth_headers)

        self._logger = logging.getLogger(__name__)
        self.session_id: Optional[str] = None
        self.protocol_version: Optional[str] = None
        self._initialized: bool = False
        self._init_lock: asyncio.Lock = asyncio.Lock()
        self._initializing: bool = False

    def _prepare_headers(self) -> Dict[str, str]:
        headers = dict(self.headers)
        if self.session_id:
            headers[MCP_SESSION_ID] = self.session_id
        if self.protocol_version:
            headers[MCP_PROTOCOL_VERSION] = self.protocol_version
        return headers

    def _maybe_extract_session_headers(self, response: httpx.Response) -> None:
        sid = response.headers.get(MCP_SESSION_ID)
        if sid:
            # Update session id if server sends one
            self.session_id = sid
            self._logger.debug("Received session id: %s", sid)

    def _maybe_extract_protocol_version_from_result(self, result: Any) -> None:
        try:
            if isinstance(result, dict) and "protocolVersion" in result:
                pv = result.get("protocolVersion")
                if pv is not None:
                    self.protocol_version = str(pv)
                    self._logger.debug("Negotiated protocol version: %s", pv)
        except Exception:
            pass

    async def _parse_sse_response(self, response: httpx.Response) -> Any:
        """Parse SSE stream and return on first JSON-RPC response/error."""
        # Basic SSE parser: accumulate fields until blank line
        event: Dict[str, Any] = {"event": "message", "data": []}
        async for line in response.aiter_lines():
            if line == "":
                # dispatch event
                data_text = "\n".join(event.get("data", []))
                try:
                    payload = json.loads(data_text) if data_text else None
                except json.JSONDecodeError:
                    payload = None

                if isinstance(payload, dict):
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
            # Unknown field: treat as data continuation
            event.setdefault("data", []).append(line)

        # If we exit loop without a response, return None
        return None

    def _resolve_redirect(self, response: httpx.Response) -> Optional[str]:
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
        return response.headers.get(CONTENT_TYPE, "").lower()

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        request_id = str(asyncio.get_running_loop().time())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        return await self.send_raw(payload)

    async def send_raw(self, payload: Dict[str, Any]) -> Any:
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
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False, trust_env=False
        ) as client:
            if not is_host_allowed(self.url):
                raise Exception(
                    "Network to non-local host is disallowed by safety policy"
                )
            response = await self._post_with_retries(
                client, self.url, payload, sanitize_headers(headers)
            )
            # Handle redirect by retrying once with provided Location or trailing slash
            redirect_url = self._resolve_redirect(response)
            if redirect_url:
                self._logger.debug("Following redirect to %s", redirect_url)
                response = await self._post_with_retries(
                    client, redirect_url, payload, headers
                )
            # Update session headers if available
            self._maybe_extract_session_headers(response)

            # Handle status codes similar to SDK
            if response.status_code == HTTP_ACCEPTED:
                return {}
            if response.status_code == HTTP_NOT_FOUND:
                # Session terminated or not found
                raise Exception("Session terminated or endpoint not found")

            response.raise_for_status()
            ct = self._extract_content_type(response)

            if ct.startswith(JSON_CT):
                # Try to get the JSON response
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    # Fallback: parse first JSON object from raw stream
                    data = {}
                    if hasattr(response, "aread"):
                        try:
                            content = await response.aread()
                            content_str = content.decode("utf-8").strip()
                            decoder = json.JSONDecoder()
                            pos = 0
                            # Limit attempts to prevent infinite loops
                            max_attempts = 1000
                            attempts = 0
                            while pos < len(content_str) and attempts < max_attempts:
                                attempts += 1
                                try:
                                    parsed, new_pos = decoder.raw_decode(
                                        content_str, pos
                                    )
                                    data = parsed
                                    break
                                except json.JSONDecodeError:
                                    pos += 1
                                    # Skip whitespace
                                    while (
                                        pos < len(content_str)
                                        and content_str[pos].isspace()
                                    ):
                                        pos += 1
                        except Exception:
                            pass

                if isinstance(data, dict):
                    if "error" in data:
                        raise Exception(f"Server error: {data['error']}")
                    if "result" in data:
                        # Extract protocol version if present (initialize)
                        self._maybe_extract_protocol_version_from_result(data["result"])
                        # Mark initialized if this was an explicit initialize call
                        if method == "initialize":
                            self._initialized = True
                        result = data["result"]
                        return (
                            result if isinstance(result, dict) else {"result": result}
                        )
                # Normalize non-dict payloads
                return data if isinstance(data, dict) else {"result": data}

            if ct.startswith(SSE_CT):
                parsed = await self._parse_sse_response(response)
                if method == "initialize":
                    self._initialized = True
                if parsed is None:
                    return {}
                return parsed if isinstance(parsed, dict) else {"result": parsed}

            raise Exception(f"Unexpected content type: {ct}")

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        headers = self._prepare_headers()
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False, trust_env=False
        ) as client:
            if not is_host_allowed(self.url):
                raise Exception(
                    "Network to non-local host is disallowed by safety policy"
                )
            safe_headers = sanitize_headers(headers)
            response = await self._post_with_retries(
                client, self.url, payload, safe_headers
            )
            redirect_url = self._resolve_redirect(response)
            if redirect_url:
                response = await self._post_with_retries(
                    client, redirect_url, payload, safe_headers
                )
            response.raise_for_status()

    async def _do_initialize(self) -> None:
        """Perform a minimal MCP initialize + initialized notification."""
        init_payload = {
            "jsonrpc": "2.0",
            "id": str(asyncio.get_running_loop().time()),
            "method": "initialize",
            "params": {
                "protocolVersion": self.protocol_version or DEFAULT_PROTOCOL_VERSION,
                "capabilities": {
                    "elicitation": {},
                    "experimental": {},
                    "roots": {"listChanged": True},
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

    async def _post_with_retries(
        self,
        client: httpx.AsyncClient,
        url: str,
        json: Dict[str, Any],
        headers: Dict[str, str],
        retries: int = 2,  # Default max retries
    ) -> httpx.Response:
        """POST with simple exponential backoff for transient network errors."""
        delay = RETRY_DELAY
        attempt = 0
        while True:
            try:
                return await client.post(url, json=json, headers=headers)
            except (httpx.ConnectError, httpx.ReadTimeout) as e:
                # Only retry for safe, idempotent, or initialization-like methods
                method = None
                try:
                    method = json.get("method")
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
                    raise
                self._logger.debug(
                    "POST retry %d for %s due to %s",
                    attempt + 1,
                    url,
                    type(e).__name__,
                )
                await asyncio.sleep(delay)
                delay *= 2
                attempt += 1

    async def _stream_request(self, payload: Dict[str, Any]):
        """Stream a request and yield parsed JSON or SSE data lines.

        This mirrors the logic used in HTTPTransport._stream_request but adapted
        for the streamable transport and its header/session handling.
        """
        headers = self._prepare_headers()
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False, trust_env=False
        ) as client:
            if not is_host_allowed(self.url):
                raise Exception(
                    "Network to non-local host is disallowed by safety policy"
                )
            safe_headers = sanitize_headers(headers)
            response = await client.post(
                self.url, json=payload, headers=safe_headers, stream=True
            )

            redirect_url = self._resolve_redirect(response)
            if redirect_url:
                await response.aclose()
                response = await client.post(
                    redirect_url, json=payload, headers=safe_headers, stream=True
                )

            try:
                response.raise_for_status()
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
                                continue
            finally:
                await response.aclose()
