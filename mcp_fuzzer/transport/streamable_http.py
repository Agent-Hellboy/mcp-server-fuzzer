import asyncio
import json
import logging
from typing import Any, Dict, Optional

import httpx
from urllib.parse import urljoin, urlparse
from ..config import (
    DEFAULT_PROTOCOL_VERSION,
    CONTENT_TYPE_HEADER,
    JSON_CONTENT_TYPE,
    SSE_CONTENT_TYPE,
    MCP_SESSION_ID_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    DEFAULT_HTTP_ACCEPT,
)

from .base import TransportProtocol


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
        timeout: float = 30.0,
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
        if response.status_code in (307, 308):
            location = response.headers.get("location")
            if not location and not self.url.endswith("/"):
                location = self.url + "/"
            if not location:
                return None
            resolved = urljoin(self.url, location)
            base = urlparse(self.url)
            new = urlparse(resolved)
            if (new.scheme, new.netloc) != (base.scheme, base.netloc):
                self._logger.warning(
                    "Refusing cross-origin redirect from %s to %s",
                    self.url,
                    resolved,
                )
                return None
            return resolved
        return None

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
            timeout=self.timeout, follow_redirects=False
        ) as client:
            response = await self._post_with_retries(client, self.url, payload, headers)
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
            if response.status_code == 202:
                return None
            if response.status_code == 404:
                # Session terminated or not found
                raise Exception("Session terminated or endpoint not found")

            response.raise_for_status()
            ct = self._extract_content_type(response)

            if ct.startswith(JSON_CT):
                data = response.json()
                if isinstance(data, dict):
                    if "error" in data:
                        raise Exception(f"Server error: {data['error']}")
                    if "result" in data:
                        # Extract protocol version if present (initialize)
                        self._maybe_extract_protocol_version_from_result(data["result"])
                        # Mark initialized if this was an explicit initialize call
                        if method == "initialize":
                            self._initialized = True
                        return data["result"]
                return data

            if ct.startswith(SSE_CT):
                parsed = await self._parse_sse_response(response)
                if method == "initialize":
                    self._initialized = True
                return parsed

            raise Exception(f"Unexpected content type: {ct}")

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        headers = self._prepare_headers()
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False
        ) as client:
            response = await self._post_with_retries(client, self.url, payload, headers)
            redirect_url = self._resolve_redirect(response)
            if redirect_url:
                response = await self._post_with_retries(
                    client, redirect_url, payload, headers
                )
            # Update session headers if available
            self._maybe_extract_session_headers(response)
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
        retries: int = 2,
    ) -> httpx.Response:
        """POST with simple exponential backoff for transient network errors."""
        delay = 0.1
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
                    "POST retry %d for %s due to %s", attempt + 1, url, type(e).__name__
                )
                await asyncio.sleep(delay)
                delay *= 2
                attempt += 1
