import json
import logging
from typing import Any, Dict, Optional

import httpx

from .base import TransportProtocol
from ..safety_system.policy import is_host_allowed, sanitize_headers


class SSETransport(TransportProtocol):
    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
        self.headers = {
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        }

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        # SSE transport does not support non-streaming requests via send_request.
        # Use stream-based APIs instead (e.g., _stream_request).
        raise NotImplementedError("SSETransport does not support send_request")

    async def send_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if not is_host_allowed(self.url):
                raise Exception(
                    "Network to non-local host is disallowed by safety policy"
                )
            safe_headers = sanitize_headers(self.headers)
            response = await client.post(self.url, json=payload, headers=safe_headers)
            response.raise_for_status()
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[len("data:") :].strip())
                        if "error" in data:
                            raise Exception(f"Server error: {data['error']}")
                        return data.get("result", data)
                    except json.JSONDecodeError:
                        logging.error("Failed to parse SSE data line as JSON")
                        continue
            try:
                data = response.json()
                if "error" in data:
                    raise Exception(f"Server error: {data['error']}")
                return data.get("result", data)
            except json.JSONDecodeError:
                pass
            raise Exception("No valid SSE response received")

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if not is_host_allowed(self.url):
                raise Exception(
                    "Network to non-local host is disallowed by safety policy"
                )
            safe_headers = sanitize_headers(self.headers)
            response = await client.post(self.url, json=payload, headers=safe_headers)
            response.raise_for_status()

    async def _stream_request(self, payload: Dict[str, Any]):
        """Stream a request via SSE and yield parsed events.

        Args:
            payload: Request payload with method/params

        Yields:
            Parsed JSON objects from SSE events
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if not is_host_allowed(self.url):
                raise Exception(
                    "Network to non-local host is disallowed by safety policy"
                )
            safe_headers = sanitize_headers(self.headers)
            async with client.stream(
                "POST",
                self.url,
                json=payload,
                headers=safe_headers,
            ) as response:
                response.raise_for_status()

                chunks = response.aiter_text()

                # Support both async and sync iterables (tests may provide a list)
                if hasattr(chunks, "__aiter__"):
                    async for chunk in chunks:  # type: ignore[func-returns-value]
                        if not chunk:
                            continue
                        try:
                            parsed = SSETransport._parse_sse_event(chunk)
                        except json.JSONDecodeError:
                            logging.error("Failed to parse SSE event payload as JSON")
                            continue
                        if parsed is not None:
                            yield parsed
                else:
                    for chunk in chunks:  # type: ignore[assignment]
                        if not chunk:
                            continue
                        try:
                            parsed = SSETransport._parse_sse_event(chunk)
                        except json.JSONDecodeError:
                            logging.error("Failed to parse SSE event payload as JSON")
                            continue
                        if parsed is not None:
                            yield parsed

    @staticmethod
    def _parse_sse_event(event_text: str) -> Optional[Dict[str, Any]]:
        """Parse a single SSE event text into a JSON object.

        The input may contain multiple lines such as "event:", "data:", or
        control fields like "retry:". Only the JSON payload from one or more
        "data:" lines is considered. Multiple data lines are concatenated.

        Returns None when there is no data payload. Raises JSONDecodeError when
        a data payload is present but cannot be parsed as JSON.
        """
        if not event_text:
            return None

        data_parts: list[str] = []
        for raw_line in event_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("data:"):
                data_parts.append(line[len("data:") :].strip())
            # Ignore other fields such as "event:" and "retry:"

        if not data_parts:
            return None

        data_str = "".join(data_parts)
        # May raise JSONDecodeError if invalid, as intended by tests
        return json.loads(data_str)
