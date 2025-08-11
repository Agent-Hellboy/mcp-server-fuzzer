import json
import uuid
import logging
from typing import Any, Dict, Optional

import httpx

from .base import TransportProtocol


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
    ) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[len("data:") :].strip())
                        if "error" in data:
                            logging.error("Server returned error: %s", data["error"])
                            raise Exception(f"Server error: {data['error']}")
                        return data.get("result", data)
                    except json.JSONDecodeError:
                        logging.error("Failed to parse SSE data line as JSON")
                        continue
            raise Exception("No valid SSE response received")

    async def send_raw(self, payload: Dict[str, Any]) -> Any:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
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
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
