import json
import logging
import uuid
from typing import Any, Dict, Optional

import httpx

from .base import TransportProtocol


class HTTPTransport(TransportProtocol):
    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        auth_headers: Optional[Dict[str, str]] = None,
    ):
        self.url = url
        self.timeout = timeout
        self.headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if auth_headers:
            self.headers.update(auth_headers)

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
            try:
                data = response.json()
            except json.JSONDecodeError:
                logging.info("Response is not JSON, trying to parse as SSE")
                for line in response.text.splitlines():
                    if line.startswith("data:"):
                        try:
                            data = json.loads(line[len("data:") :].strip())
                            break
                        except json.JSONDecodeError:
                            logging.error("Failed to parse SSE data line as JSON")
                            raise
                else:
                    logging.error("No valid data: line found in SSE response")
                    raise Exception("Invalid SSE response format")
            if isinstance(data, dict) and "error" in data:
                logging.error("Server returned error: %s", data["error"])
                raise Exception(f"Server error: {data['error']}")
            if isinstance(data, dict):
                return data.get("result", data)
            return data

    async def send_raw(self, payload: Dict[str, Any]) -> Any:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
            try:
                data = response.json()
            except json.JSONDecodeError:
                for line in response.text.splitlines():
                    if line.startswith("data:"):
                        data = json.loads(line[len("data:") :].strip())
                        break
                else:
                    raise
            if isinstance(data, dict) and "error" in data:
                raise Exception(f"Server error: {data['error']}")
            if isinstance(data, dict):
                return data.get("result", data)
            return data

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
